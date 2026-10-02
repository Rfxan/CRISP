import json
import multiprocessing
import time
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timezone, timedelta
from unittest.mock import patch
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from app.core.tenancy import tenant_transaction, read_document, write_document
from app.core.deployment import validate_deployment
from app.compliance.evidence import assess_control, evidence_fingerprint, reporting_readiness
from app.ai.decision_support import DecisionSupportAI


@pytest.fixture
def persisted(monkeypatch, tmp_path):
    monkeypatch.setenv('CRISP_DATABASE_PATH', str(tmp_path/'state.sqlite3'))
    monkeypatch.setenv('CRISP_ENV','production')
    monkeypatch.setenv('CRISP_ENCRYPTION_KEY',Fernet.generate_key().decode())
    monkeypatch.setenv('CRISP_TESTING','0')
    # A leftover token setting must not reactivate the removed feature.
    monkeypatch.setenv('CRISP_AUTH_TOKENS','obsolete-setting')


def test_direct_workspace_access_and_restart_persistence(persisted):
    from app.main import app
    with TestClient(app) as client:
        assert client.get('/api/risk/summary').status_code == 200
        assert client.get('/api/auth/session').status_code == 404
        assert client.post('/api/data/seed').status_code == 200
        baseline = client.get('/api/risk/summary').json()
        assert baseline['org']['eal'] is not None
        plan = client.post('/api/optimize',json={'budget':10000000}).json()['plan']
        replay = client.post('/api/simulate',json={'actions':plan['actions'],'seed':plan['evaluation']['seed']}).json()
        assert replay['post_intervention']['eal'] == plan['remaining_eal']
        assert replay['snapshot_hash'] == plan['evaluation']['snapshot_hash']
        ignored = client.get('/api/risk/summary',headers={'Authorization':'Bearer unused','X-Organization':'another'}).json()
        assert ignored['org']['eal'] == baseline['org']['eal']
        audit = client.get('/api/governance/audit').json()['events']
        assert any(e['action']=='POST /api/data/seed' and e['subject']=='local-workspace' for e in audit)
    with TestClient(app) as restarted:
        assert restarted.get('/api/risk/summary').json()['org']['eal'] == baseline['org']['eal']


def test_production_requires_persistent_encryption_key(monkeypatch):
    monkeypatch.setenv('CRISP_ENV','production')
    monkeypatch.delenv('CRISP_ENCRYPTION_KEY',raising=False)
    with pytest.raises(RuntimeError,match='persistent'): validate_deployment()
    monkeypatch.setenv('CRISP_ENCRYPTION_KEY',Fernet.generate_key().decode())
    validate_deployment()


def _increment(_):
    with tenant_transaction({'tenant':'alpha','subject':'test-process','role':'admin'}):
        value=read_document('counter',0)
        time.sleep(.025)
        write_document('counter',value+1)
    return True


def _worker_sync(_):
    from app.worker import sync_once
    with patch('app.api.routes.sync_wazuh_telemetry'), patch('app.api.routes.sync_iam_telemetry'):
        return sync_once('alpha', interval=60)


def test_concurrent_processes_cannot_overwrite_or_duplicate_sync(persisted):
    identity={'tenant':'alpha','subject':'test','role':'admin'}
    with tenant_transaction(identity):
        write_document('counter',0)
        write_document('sync_schedule',{'last_intel':time.time()})
    with ProcessPoolExecutor(max_workers=2,mp_context=multiprocessing.get_context('spawn')) as pool:
        assert all(pool.map(_increment,range(8)))
        results=list(pool.map(_worker_sync,range(2)))
    with tenant_transaction(identity): assert read_document('counter') == 8
    assert sorted(results) == [False,True]


def test_tenant_configuration_isolation_without_legacy_file(persisted,tmp_path):
    from app.ai.llm_config_store import LLMConfigStore
    with tenant_transaction({'tenant':'alpha','subject':'a','role':'admin'}):
        config=LLMConfigStore(tmp_path/'absent.json')
        config._write_file({'provider':'custom','model':'alpha-only'})
        assert config._read_file()['model']=='alpha-only'
        assert config._read_file()['model']=='alpha-only'
    with tenant_transaction({'tenant':'beta','subject':'b','role':'admin'}):
        assert config._read_file()=={}


def test_compliance_requires_fresh_reviewed_actual_evidence():
    now=datetime.now(timezone.utc)
    state={'coverage_pct':75,'evidence_ref':'Scanner run 123','last_checked':now.isoformat()}
    review={'decision':'compliant','applicability':'applicable','reviewer':'auditor','reviewed_at':now.isoformat(),
            'evidence_fingerprint':evidence_fingerprint(state)}
    assert assess_control(state)['status']=='Not assessed'
    assert assess_control(state,review)['status']=='Compliant'
    assert assess_control({**state,'coverage_pct':70},review)['status']=='Not assessed'
    for changed in ({'is_simulated':True},{'is_user_assumed':True},{'last_checked':(now-timedelta(days=91)).isoformat()}):
        assert not assess_control({**state,**changed},review)['evidence_complete']
    assert reporting_readiness([])['readiness_score_pct'] is None
    exercise={'id':'exercise-1','incident_at':(now-timedelta(hours=4)).isoformat(),
              'detected_at':(now-timedelta(hours=3)).isoformat(),'escalated_at':(now-timedelta(hours=2)).isoformat(),
              'reported_at':(now-timedelta(hours=1)).isoformat(),'evidence_ref':'exercise record'}
    result=reporting_readiness([exercise])
    assert result['exercises'][0]['reporting_minutes']==180
    assert result['readiness_score_pct']==100


@pytest.mark.parametrize('answer', ['{"claims":[{"metric_id":"org.eal","value":999}]}',
    '{"claims":[{"metric_id":"invented","value":100}]}','{"claims":[{"metric_id":"org.eal","value":true}]}'])
def test_ai_rejects_unverified_numbers(answer):
    facts=DecisionSupportAI().facts({'org':{'eal':100}})
    with pytest.raises(ValueError): DecisionSupportAI.validate_claims(answer,facts)


def test_ai_falls_back_and_preserves_unknown():
    ai=DecisionSupportAI()
    assert 'unknown' in ai.ask('Risk?',{'org':{'eal':None}})['answer']
    with patch('app.ai.decision_support.llm_config_store.get_config',return_value={'provider':'custom','api_key':'test'}), \
         patch('app.ai.decision_support.llm_service.generate_response',return_value={'answer':'Guaranteed savings 99999999'}):
        result=ai.ask('Risk?',{'org':{'eal':100,'var95':200},'run_id':'test'})
    assert result['is_llm'] is False
    assert '99999999' not in result['answer']
    assert result['fallback_reason']


def test_real_unconnected_dataset_does_not_seed_demo_telemetry():
    from app.api.routes import SnapshotStore
    local=SnapshotStore()
    local.current_snapshot['assets']=[{'id':'real-host','name':'Real host','criticality_1_5':3}]
    local.current_snapshot['assessment_state']={'status':'completed'}
    local.get_summary()
    with patch('app.api.routes.connections_store.get_connection',return_value=None):
        result=local.get_telemetry_anomalies()
    assert result['is_demo'] is False
    assert result['signals']==[]
    assert local.telemetry_history==[]
