"""Tenant-bound document transactions: hosted PostgreSQL or local SQLite.

Every API change and worker sync acquires the same workspace transaction lock.
"""
import contextvars
import hashlib
import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from app.core.postgres import connect_postgres, StateStoreUnavailable
from app.core.deployment import requires_hosted_database

principal_context = contextvars.ContextVar("principal", default=None)
transaction_context = contextvars.ContextVar("transaction", default=None)
_sqlite_schema_lock = threading.Lock()
_initialized_sqlite = set()


def database_path():
    return Path(os.getenv("CRISP_DATABASE_PATH", str(Path(__file__).resolve().parents[2] / "data" / "crisp.sqlite3")))


def connect():
    url = os.getenv("CRISP_DATABASE_URL", "").strip()
    if url:
        if not url.startswith(("postgresql://", "postgres://")):
            raise ValueError("CRISP_DATABASE_URL must be a PostgreSQL connection URL")
        return connect_postgres(url)
    if requires_hosted_database():
        raise RuntimeError("Hosted deployments require CRISP_DATABASE_URL; local SQLite is not durable")
    path = database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=60, isolation_level=None, check_same_thread=False)
    db.execute("PRAGMA busy_timeout=60000")
    db.execute("PRAGMA foreign_keys=ON")
    # Setting journal mode while another connection initializes can fail even
    # with busy_timeout. Serialize first initialization within each process.
    key = str(path.resolve())
    with _sqlite_schema_lock:
        if key not in _initialized_sqlite:
            try:
                db.execute("PRAGMA journal_mode=WAL")
                _initialize_sqlite(db)
                _initialized_sqlite.add(key)
            except Exception:
                db.close()
                raise
    return db


def _initialize_sqlite(db):
    db.executescript('''
        CREATE TABLE IF NOT EXISTS guest_sessions (tenant TEXT PRIMARY KEY, expires BIGINT NOT NULL);
        CREATE TABLE IF NOT EXISTS security_rate_limits (
            bucket TEXT PRIMARY KEY, hits INTEGER NOT NULL, expires BIGINT NOT NULL);
        CREATE TABLE IF NOT EXISTS tenant_documents (
            tenant TEXT NOT NULL, name TEXT NOT NULL, body TEXT NOT NULL,
            version INTEGER NOT NULL DEFAULT 1, PRIMARY KEY(tenant,name));
        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, tenant TEXT NOT NULL,
            subject TEXT NOT NULL, action TEXT NOT NULL, status INTEGER,
            timestamp TEXT NOT NULL, before_hash TEXT, after_hash TEXT);
        CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_events
            BEGIN SELECT RAISE(ABORT, 'Audit events are append only'); END;
        CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_events
            BEGIN SELECT RAISE(ABORT, 'Audit events are append only'); END;
    ''')


def begin_transaction(db, tenant):
    if hasattr(db, "begin"):
        db.begin(tenant)
    else:
        db.execute("BEGIN IMMEDIATE")


@contextmanager
def tenant_transaction(principal):
    db = connect()
    ptoken = principal_context.set(principal)
    ttoken = transaction_context.set(db)
    try:
        begin_transaction(db, principal["tenant"])
        yield db
        db.commit()
    except BaseException:
        db.rollback()
        raise
    finally:
        transaction_context.reset(ttoken)
        principal_context.reset(ptoken)
        db.close()


def active():
    return transaction_context.get() is not None


def read_document(name, default=None):
    db = transaction_context.get()
    if db is None:
        raise RuntimeError("Tenant document access requires a transaction")
    row = db.execute("SELECT body FROM tenant_documents WHERE tenant=? AND name=?",
                     (principal_context.get()["tenant"], name)).fetchone()
    return json.loads(row[0]) if row else default


def write_document(name, value):
    db = transaction_context.get()
    if db is None:
        raise RuntimeError("Tenant document access requires a transaction")
    db.execute('''INSERT INTO tenant_documents(tenant,name,body) VALUES(?,?,?)
        ON CONFLICT(tenant,name) DO UPDATE SET body=excluded.body, version=tenant_documents.version+1''',
        (principal_context.get()["tenant"], name, json.dumps(value, allow_nan=False)))


def audit(action, status, before=None, after=None):
    identity = principal_context.get()
    def fingerprint(value):
        return hashlib.sha256(json.dumps(value,sort_keys=True,default=str).encode()).hexdigest() if value is not None else None
    transaction_context.get().execute('''INSERT INTO audit_events
        (tenant,subject,action,status,timestamp,before_hash,after_hash) VALUES(?,?,?,?,?,?,?)''',
        (identity["tenant"],identity["subject"],action,status,datetime.now(timezone.utc).isoformat(),fingerprint(before),fingerprint(after)))


def tenant_ids():
    db = connect()
    try:
        return [r[0] for r in db.execute("SELECT DISTINCT tenant FROM tenant_documents WHERE tenant NOT LIKE 'guest:%'")]
    finally:
        db.close()
