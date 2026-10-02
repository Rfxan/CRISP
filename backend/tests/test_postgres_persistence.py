"""Run DB checks only against a disposable CRISP_TEST_POSTGRES_URL database."""
import os
import multiprocessing
import time
import uuid
from concurrent.futures import ProcessPoolExecutor
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet
from app.core.deployment import production, validate_deployment
from app.core.tenancy import tenant_transaction, read_document, write_document, audit


@pytest.mark.parametrize('environment', ['production', 'preview', 'render'])
def test_host_requires_hosted_database_and_persistent_key(monkeypatch, environment):
    for name in ('VERCEL', 'VERCEL_ENV', 'RENDER'):
        monkeypatch.delenv(name, raising=False)
    if environment == 'render':
        monkeypatch.setenv('RENDER', 'true')
    else:
        monkeypatch.setenv('VERCEL', '1')
        monkeypatch.setenv('VERCEL_ENV', environment)
    monkeypatch.setenv('CRISP_ENV', 'development')
    monkeypatch.delenv('CRISP_DATABASE_URL', raising=False)
    monkeypatch.delenv('CRISP_ENCRYPTION_KEY', raising=False)
    assert production()
    with pytest.raises(RuntimeError, match='hosted PostgreSQL'):
        validate_deployment()
    monkeypatch.setenv('CRISP_DATABASE_URL', 'postgresql://example/database')
    with pytest.raises(RuntimeError, match='persistent'):
        validate_deployment()
    monkeypatch.setenv('CRISP_ENCRYPTION_KEY', Fernet.generate_key().decode())
    validate_deployment()


@pytest.fixture
def postgres(monkeypatch):
    url = os.getenv('CRISP_TEST_POSTGRES_URL')
    if not url:
        pytest.skip('Requires a disposable CRISP_TEST_POSTGRES_URL database')
    monkeypatch.setenv('CRISP_DATABASE_URL', url)
    monkeypatch.setenv('CRISP_ENV', 'production')
    monkeypatch.setenv('CRISP_ENCRYPTION_KEY', Fernet.generate_key().decode())
    monkeypatch.setenv('CRISP_TESTING', '0')
    return {'tenant': 'pg-test-' + uuid.uuid4().hex, 'subject': 'postgres-test'}


def test_postgres_roundtrip_isolation_versions_and_rollback(postgres):
    value = {'currency': '\u20b9', 'unknown': None, 'text': "value? ' OR 1=1 --"}
    with tenant_transaction(postgres) as db:
        write_document('settings', value)
        write_document('settings', value)
        assert read_document('settings') == value
        assert db.execute('SELECT version FROM tenant_documents WHERE tenant=? AND name=?',
                          (postgres['tenant'], 'settings')).fetchone()[0] == 2
    with tenant_transaction({**postgres, 'tenant': postgres['tenant'] + '-other'}):
        assert read_document('settings') is None
    with pytest.raises(RuntimeError, match='abort'):
        with tenant_transaction(postgres):
            write_document('settings', {'overwritten': True})
            audit('rolled-back-change', 200)
            raise RuntimeError('abort')
    with tenant_transaction(postgres) as db:
        assert read_document('settings') == value
        assert db.execute('SELECT COUNT(*) FROM audit_events WHERE tenant=?',
                          (postgres['tenant'],)).fetchone()[0] == 0


def test_postgres_audit_is_append_only(postgres):
    import psycopg
    with tenant_transaction(postgres):
        audit('test', 200)
    for query in ('UPDATE audit_events SET status=500 WHERE tenant=?',
                  'DELETE FROM audit_events WHERE tenant=?'):
        with pytest.raises(psycopg.errors.RaiseException, match='append only'):
            with tenant_transaction(postgres) as db:
                db.execute(query, (postgres['tenant'],))


def _increment(tenant):
    with tenant_transaction({'tenant': tenant, 'subject': 'concurrent-test'}):
        count = read_document('counter', 0)
        time.sleep(.03)
        write_document('counter', count + 1)
    return True


def _sync(tenant):
    from app.worker import sync_once
    with patch('app.api.routes.sync_wazuh_telemetry'), patch('app.api.routes.sync_iam_telemetry'):
        return sync_once(tenant, interval=60)


def test_postgres_concurrent_processes_and_worker_deduplication(postgres):
    with tenant_transaction(postgres):
        write_document('counter', 0)
        write_document('sync_schedule', {'last_intel': time.time()})
    with ProcessPoolExecutor(max_workers=2, mp_context=multiprocessing.get_context('spawn')) as pool:
        assert all(pool.map(_increment, [postgres['tenant']] * 8))
        outcomes = list(pool.map(_sync, [postgres['tenant']] * 2))
    with tenant_transaction(postgres):
        assert read_document('counter') == 8
    assert sorted(outcomes) == [False, True]


def test_postgres_api_persists_across_clients(postgres, monkeypatch):
    # Administration is local-only; production HTTP is a public read-only demo.
    monkeypatch.setenv('CRISP_ENV', 'development')
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as client:
        assert client.get('/api/health').status_code == 200
        result = client.post('/api/controls/bulk-update', json={'controls': [
            {'control_id': 'CTRL-MFA-01', 'coverage_pct': 73}]})
        assert result.status_code == 200, result.text
    with TestClient(app) as client:
        snapshot = client.get('/api/data/snapshot').json()
        control = next(c for c in snapshot['control_state'] if c['control_id'] == 'CTRL-MFA-01')
        assert control['coverage_pct'] == 73
        events = client.get('/api/governance/audit').json()['events']
        assert any(e['action'] == 'POST /api/controls/bulk-update' for e in events)
