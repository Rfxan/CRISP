"""PostgreSQL implementation of the document-store connection contract."""
import hashlib
import threading


class StateStoreUnavailable(RuntimeError):
    """A safe error that never includes database credentials."""


_initialized = set()
_schema_lock = threading.Lock()
_schema_statements = (
    '''CREATE TABLE IF NOT EXISTS guest_sessions (tenant TEXT PRIMARY KEY, expires BIGINT NOT NULL)''',
    '''CREATE TABLE IF NOT EXISTS security_rate_limits (
        bucket TEXT PRIMARY KEY, hits INTEGER NOT NULL, expires BIGINT NOT NULL)''',
    '''CREATE TABLE IF NOT EXISTS tenant_documents (
        tenant TEXT NOT NULL, name TEXT NOT NULL, body TEXT NOT NULL,
        version INTEGER NOT NULL DEFAULT 1, PRIMARY KEY(tenant,name))''',
    '''CREATE TABLE IF NOT EXISTS audit_events (
        id BIGSERIAL PRIMARY KEY, tenant TEXT NOT NULL, subject TEXT NOT NULL,
        action TEXT NOT NULL, status INTEGER, timestamp TEXT NOT NULL,
        before_hash TEXT, after_hash TEXT)''',
    '''CREATE OR REPLACE FUNCTION crisp_reject_audit_mutation() RETURNS trigger
        LANGUAGE plpgsql AS $$ BEGIN
            RAISE EXCEPTION 'Audit events are append only';
        END $$''',
    '''CREATE OR REPLACE TRIGGER audit_no_mutation
        BEFORE UPDATE OR DELETE ON audit_events FOR EACH ROW
        EXECUTE FUNCTION crisp_reject_audit_mutation()''',
)


def lock_key(namespace):
    return int.from_bytes(hashlib.sha256(namespace.encode()).digest()[:8], 'big', signed=True)


class PostgresConnection:
    def __init__(self, connection):
        self.connection = connection

    def execute(self, query, parameters=()):
        # The document-store queries use SQLite's positional placeholder syntax.
        # Query text is static; all values remain driver-bound parameters.
        return self.connection.execute(query.replace('?', '%s'), parameters or None)

    def begin(self, tenant):
        import psycopg
        try:
            self.connection.execute('BEGIN')
            self.connection.execute('SET LOCAL lock_timeout = \'60s\'')
            self.connection.execute('SELECT pg_advisory_xact_lock(%s)',
                                    (lock_key('crisp:tenant:' + tenant),))
        except (psycopg.OperationalError, psycopg.errors.LockNotAvailable):
            self.connection.rollback()
            raise StateStoreUnavailable('State store busy or unavailable; retry the request') from None

    def commit(self):
        self.connection.commit()

    def rollback(self):
        self.connection.rollback()

    def close(self):
        self.connection.close()


def connect_postgres(url):
    import psycopg
    try:
        # No prepared statements: compatible with transaction-pooling endpoints.
        connection = psycopg.connect(url, autocommit=True, prepare_threshold=None,
                                     connect_timeout=10)
    except psycopg.OperationalError:
        raise StateStoreUnavailable('Unable to connect to the configured state store') from None
    try:
        fingerprint = hashlib.sha256(url.encode()).hexdigest()
        with _schema_lock:
            if fingerprint not in _initialized:
                # Cross-process bootstrap locking, including first concurrent calls.
                with connection.transaction():
                    connection.execute('SET LOCAL lock_timeout = \'60s\'')
                    connection.execute('SELECT pg_advisory_xact_lock(%s)',
                                       (lock_key('crisp:schema:v1'),))
                    for statement in _schema_statements:
                        connection.execute(statement)
                _initialized.add(fingerprint)
        return PostgresConnection(connection)
    except Exception:
        connection.close()
        raise
