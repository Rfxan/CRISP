import asyncio
import csv
import io
import json
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.web_security import WebSecurityMiddleware, RateLimiter, public_route
from app.core.outbound import validate_outbound_url, integration_request
from app.core.tenancy import connect, tenant_transaction, read_document, write_document


@pytest.fixture
def secured(monkeypatch, tmp_path):
    monkeypatch.setenv('CRISP_ACCESS_MODE', 'public_demo')
    monkeypatch.setenv('CRISP_ENV', 'production')
    monkeypatch.setenv('CRISP_TESTING', '0')
    monkeypatch.setenv('CRISP_ENCRYPTION_KEY', Fernet.generate_key().decode())
    monkeypatch.setenv('CRISP_DATABASE_PATH', str(tmp_path/'security.sqlite3'))
    monkeypatch.delenv('CRISP_DATABASE_URL', raising=False)
    monkeypatch.delenv('RENDER', raising=False)
    monkeypatch.delenv('VERCEL', raising=False)


def test_public_demo_blocks_all_administration_before_tenant_access(secured):
    from app.main import app
    with TestClient(app) as client, patch('app.core.middleware.connect') as workspace_connect:
        for method, path in [('POST','/api/data/seed'),('POST','/api/data/reset'),
                             ('POST','/api/connections/siem/test'),('POST','/api/ai/config'),
                             ('DELETE','/api/assets'),('PUT','/api/model/assumptions'),
                             ('GET','/snapshot'),('GET','/api/data/snapshot'),
                             ('GET','/api/governance/audit'),('GET','/api/connections'),
                             ('POST','/api/ask')]:
            response = client.request(method,path)
            assert response.status_code == 403, path
            assert response.headers['X-Content-Type-Options'] == 'nosniff'
        workspace_connect.assert_not_called()
        assert client.get('/api/health').status_code == 200


def test_new_and_encoded_routes_are_denied_by_default():
    assert not public_route('POST','/api/simulate/')
    assert not public_route('GET','/api/new-admin-endpoint')
    assert not public_route('GET','/api/compliance/sebi/../connections')
    assert public_route('GET','/api/compliance/sebi/evidence-report/csv')


def test_public_analytics_cannot_persist_changes(secured):
    from app.main import app
    identity = {'tenant':'local','subject':'publisher'}
    with tenant_transaction(identity):
        write_document('snapshot', {'current_snapshot': {'assets': [], 'findings': []}})
    def transient_calculation(*args, **kwargs):
        write_document('should_not_persist', {'private':'transient'})
        return {'status':'NO_DATA','org':{'eal':None},'drivers':[]}
    from app.api.routes import SnapshotStore
    with patch.object(SnapshotStore, 'get_summary', side_effect=transient_calculation), TestClient(app) as client:
        assert client.get('/api/risk/explanation').status_code == 200
    with tenant_transaction(identity):
        assert read_document('should_not_persist') is None


def test_shared_rate_limits_are_atomic_across_instances_and_reset(secured, monkeypatch):
    monkeypatch.setenv('CRISP_RATE_PEER','5')
    def consume(_):
        return RateLimiter().check('test-peer', now=120)[0]
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(consume, range(20)))
    assert sum(results) == 5
    assert RateLimiter().check('test-peer', now=180)[0]
    assert RateLimiter().check('other-peer', now=180)[0]


def test_global_quota_cannot_be_bypassed_with_new_peers(secured, monkeypatch):
    monkeypatch.setenv('CRISP_RATE_GLOBAL','3')
    limiter = RateLimiter()
    assert all(limiter.check(str(i), now=120)[0] for i in range(3))
    assert not limiter.check('fourth', now=120)[0]


def test_rate_limit_returns_retry_header_and_ignores_forwarding_headers(secured, monkeypatch):
    monkeypatch.setenv('CRISP_RATE_PEER','1')
    from app.main import app
    with TestClient(app) as client:
        assert client.get('/api/security/capabilities',headers={'X-Forwarded-For':'one'}).status_code == 200
        response = client.get('/api/security/capabilities',headers={'X-Forwarded-For':'two'})
        assert response.status_code == 429
        assert 1 <= int(response.headers['Retry-After']) <= 60
        assert response.headers['Cache-Control'] == 'no-store'


def test_protection_store_failure_fails_closed(secured):
    from app.main import app
    with TestClient(app) as client, patch.object(RateLimiter,'check',side_effect=RuntimeError('secret')):
        response = client.get('/api/risk/summary')
        assert response.status_code == 503
        assert 'secret' not in response.text
        assert client.get('/api/health').status_code == 200


def test_streamed_body_limit_is_enforced_without_content_length(monkeypatch):
    monkeypatch.setenv('CRISP_ENV','development')
    monkeypatch.setenv('CRISP_TESTING','1')
    app = FastAPI()
    app.add_middleware(WebSecurityMiddleware)
    @app.post('/upload')
    def upload():
        pytest.fail('Oversized body reached the route')
    async def exercise():
        messages = iter([{'type':'http.request','body':b'x'*(300*1024),'more_body':True},
                         {'type':'http.request','body':b'x'*(300*1024),'more_body':False}])
        responses = []
        async def receive(): return next(messages)
        async def send(message): responses.append(message)
        await app({'type':'http','asgi':{'version':'3.0'},'method':'POST','path':'/upload',
                   'raw_path':b'/upload','query_string':b'','headers':[],
                   'scheme':'http','server':('test',80),'client':('test',1)},receive,send)
        assert responses[0]['status']==413
    asyncio.run(exercise())


def test_invalid_inputs_do_not_echo_secrets(secured):
    from app.main import app
    with TestClient(app) as client:
        response = client.post('/api/optimize',json={'budget':'secret-value'})
        assert response.status_code == 422
        assert 'secret-value' not in response.text
        assert client.post('/api/simulate',json={'actions':[{}]*101}).status_code == 422
        assert client.post('/api/simulate',json={'actions':[],'seed':2**80}).status_code == 422


def test_public_integration_validation_and_tls(secured, monkeypatch):
    with pytest.raises(ValueError,match='HTTPS'):
        validate_outbound_url('http://unconfigured.invalid/api')
    with pytest.raises(ValueError):
        validate_outbound_url('https://test-user@example.invalid')
    monkeypatch.delenv('CRISP_OUTBOUND_ORIGINS', raising=False)
    from requests import Response
    response = Response()
    response.status_code = 200
    response._content = b'{}'
    response._content_consumed = True
    with patch('socket.getaddrinfo',return_value=[(2,1,6,'',('8.8.8.8',55000))]), patch('requests.Session.request', return_value=response) as send:
        assert validate_outbound_url('https://integration.example:55000/api')
        integration_request('post','https://integration.example:55000/api',auth=('user','secret'))
        assert send.call_args.kwargs['verify'] is True
        assert send.call_args.kwargs['allow_redirects'] is False
    with patch('socket.getaddrinfo',return_value=[(2,1,6,'',('127.0.0.1',55000))]):
        with pytest.raises(ValueError,match='forbidden'):
            validate_outbound_url('https://integration.example:55000/api')


def test_xml_parser_rejects_declared_entities():
    from defusedxml import ElementTree
    from defusedxml.common import EntitiesForbidden
    with pytest.raises(EntitiesForbidden):
        ElementTree.fromstring(b'<!DOCTYPE root [<!ENTITY test "sample">]><root>&test;</root>')


def test_local_documentation_can_load_its_scripts(monkeypatch):
    monkeypatch.setenv('CRISP_ENV', 'development')
    monkeypatch.setenv('CRISP_TESTING', '1')
    app = FastAPI()
    app.add_middleware(WebSecurityMiddleware)
    with TestClient(app) as client:
        response = client.get('/docs')
        assert response.status_code == 200
        assert 'content-security-policy' not in response.headers
        assert response.headers['x-content-type-options'] == 'nosniff'


def test_csv_export_neutralizes_formula_text():
    from app.compliance.evidence_report import EvidenceReportGenerator
    report = EvidenceReportGenerator.build_structured_report('sebi',{})
    report['requirements'][0]['evidence_source'] = '=SUM(1,2)'
    report['requirements'][0]['reviewer'] = ' \t@example'
    rows = list(csv.reader(io.StringIO(EvidenceReportGenerator.generate_csv_report(report))))
    assert any("'=SUM(1,2)" in row for row in rows)
    assert any("' \t@example" in row for row in rows)
