"""Tenant-bound SQLite transactions for a single-host, multi-process deployment.

All API state changes and background syncs use the same write transaction. SQLite
serializes writers across processes; use a server database for multi-host scaling.
"""
import contextvars
import hashlib
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

principal_context = contextvars.ContextVar("principal", default=None)
transaction_context = contextvars.ContextVar("transaction", default=None)


def database_path():
    return Path(os.getenv("CRISP_DATABASE_PATH", str(Path(__file__).resolve().parents[2] / "data" / "crisp.sqlite3")))


def connect():
    path = database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=60, isolation_level=None, check_same_thread=False)
    db.execute("PRAGMA busy_timeout=60000")
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA foreign_keys=ON")
    db.executescript('''
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
    return db


@contextmanager
def tenant_transaction(principal):
    db = connect()
    ptoken = principal_context.set(principal)
    ttoken = transaction_context.set(db)
    try:
        db.execute("BEGIN IMMEDIATE")
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
        ON CONFLICT(tenant,name) DO UPDATE SET body=excluded.body, version=version+1''',
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
        return [r[0] for r in db.execute("SELECT DISTINCT tenant FROM tenant_documents")]
    finally:
        db.close()
