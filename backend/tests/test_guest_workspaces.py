import time
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from app.core.guest_workspace import browser_workspace, COOKIE_NAME, cleanup_workspaces, enforce_limits
from app.core.tenancy import connect, tenant_transaction, read_document, write_document, tenant_ids


@pytest.fixture
def guest(monkeypatch, tmp_path):
    monkeypatch.setenv('CRISP_ENV', 'production')
    monkeypatch.setenv('CRISP_ACCESS_MODE', 'public_sandbox')
    monkeypatch.setenv('CRISP_TESTING', '0')
    monkeypatch.setenv('CRISP_ENCRYPTION_KEY', Fernet.generate_key().decode())
    monkeypatch.setenv('CRISP_DATABASE_PATH', str(tmp_path/'guests.sqlite3'))
    monkeypatch.setenv('CRISP_PUBLIC_ORIGINS', 'https://testserver')
    monkeypatch.setenv('CRISP_RATE_COMPUTE_PEER', '100')
    monkeypatch.setenv('CRISP_RATE_COMPUTE_GLOBAL', '200')
    for name in ('CRISP_DATABASE_URL', 'RENDER', 'VERCEL'):
        monkeypatch.delenv(name, raising=False)


def test_public_editing_and_browser_isolation(guest):
    from app.main import app
    with TestClient(app, base_url='https://testserver') as first, TestClient(app, base_url='https://testserver') as second:
        capabilities = first.get('/api/security/capabilities')
        assert capabilities.json()['can_edit'] is True
        assert capabilities.json()['can_use_ai'] is True
        cookie = capabilities.headers['set-cookie']
        assert 'HttpOnly' in cookie and 'Secure' in cookie and 'SameSite=Strict' in cookie
        second.get('/api/security/capabilities')
        assert first.cookies.get(COOKIE_NAME) != second.cookies.get(COOKIE_NAME)
        assert first.get('/api/data/snapshot').json()['assets'] == []
        response = first.post('/api/controls/update', json={'control_id':'CTRL-MFA-01','coverage_pct':65})
        assert response.status_code == 200, response.text
        a = first.get('/api/data/snapshot').json()['control_state']
        b = second.get('/api/data/snapshot', headers={'X-Organization':'local'}).json()['control_state']
        assert next(x for x in a if x['control_id']=='CTRL-MFA-01')['coverage_pct'] == 65
        assert not any(x['control_id']=='CTRL-MFA-01' and x['coverage_pct']==65 for x in b)
        assert first.post('/api/data/reset', headers={'Origin':'https://untrusted.invalid'}).status_code == 403
        assert first.post('/api/data/reset', headers={'Origin':'https://testserver'}).status_code == 200
        assert first.get('/docs').status_code == 403
        assert first.get('/api/ai/config').status_code == 200
        assert first.get('/api/connections').status_code == 200
        assert all(not tenant.startswith('guest:') for tenant in tenant_ids())


def test_forged_expired_and_owner_cookies_cannot_select_workspace(guest, monkeypatch):
    from app.core.security import _get_fernet
    identity, token = browser_workspace('')
    assert browser_workspace(f'{COOKIE_NAME}={token}')[0] == identity
    assert browser_workspace(f'{COOKIE_NAME}=forged')[0]['tenant'] != identity['tenant']
    owner = _get_fernet().encrypt(b'local').decode()
    assert browser_workspace(f'{COOKIE_NAME}={owner}')[0]['tenant'].startswith('guest:')
    expired = _get_fernet().encrypt_at_time(identity['tenant'].encode(), int(time.time())-90000).decode()
    assert browser_workspace(f'{COOKIE_NAME}={expired}')[0]['tenant'] != identity['tenant']


def test_guest_cleanup_and_limits_preserve_owner(guest):
    with tenant_transaction({'tenant':'local','subject':'owner'}):
        write_document('snapshot', {'owner':True})
    with tenant_transaction({'tenant':'guest:expired','subject':'test'}):
        write_document('snapshot', {'sample':True})
        with pytest.raises(Exception, match='100 assets'):
            enforce_limits({'assets':[{}]*101})
    db = connect()
    db.execute('INSERT INTO guest_sessions(tenant,expires) VALUES(?,?)', ('guest:expired', 1))
    cleanup_workspaces(db, 2)
    db.commit()
    db.close()
    with tenant_transaction({'tenant':'local','subject':'owner'}):
        assert read_document('snapshot') == {'owner':True}
    with tenant_transaction({'tenant':'guest:expired','subject':'test'}):
        assert read_document('snapshot') is None


def test_guest_connectors_never_use_server_secrets(guest, monkeypatch):
    from app.core.config import settings
    from app.connectors.wazuh import WazuhConnector
    from app.connectors.iam import KeycloakConnector
    monkeypatch.setattr(settings, 'WAZUH_PASSWORD', 'server-only')
    monkeypatch.setattr(settings, 'KEYCLOAK_ADMIN_TOKEN', 'server-only')
    monkeypatch.setenv('GEMINI_API_KEY', 'server-only')
    from app.ai.llm_config_store import llm_config_store
    with tenant_transaction({'tenant':'guest:test','subject':'browser'}):
        assert WazuhConnector().password == ''
        assert KeycloakConnector().admin_token == ''
        assert llm_config_store.get_config()['api_key'] == ''
