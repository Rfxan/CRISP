import copy
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.api.routes import store


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv('CRISP_TESTING','1')
    monkeypatch.setenv('CRISP_ENV','development')
    original=copy.deepcopy(store.current_snapshot)
    store._init_empty()
    yield TestClient(app)
    store.current_snapshot=original
    store.cached_summary=None


def test_bulk_saves_all_values_and_recomputes_once(client):
    updates=[{'control_id':'CTRL-MFA-01','coverage_pct':85}, {'control_id':'CTRL-EDR-01','coverage_pct':60}]
    with patch.object(store,'get_summary',wraps=store.get_summary) as compute:
        response=client.post('/api/controls/bulk-update',json={'controls':updates})
        assert response.status_code==200
        assert response.json()['updated_count']==2
        assert compute.call_count==1
    states={c['control_id']:c for c in store.current_snapshot['control_state']}
    for change in updates:
        assert states[change['control_id']]['coverage_pct']==change['coverage_pct']
        assert states[change['control_id']]['is_user_assumed'] is True


@pytest.mark.parametrize('second', [
    {'control_id':'UNKNOWN','coverage_pct':60},
    {'control_id':'CTRL-EDR-01','coverage_pct':101},
    {'control_id':'CTRL-MFA-01','coverage_pct':70},
])
def test_invalid_batch_does_not_partially_update(client,second):
    before=copy.deepcopy(store.current_snapshot)
    response=client.post('/api/controls/bulk-update',json={'controls':[
        {'control_id':'CTRL-MFA-01','coverage_pct':85},second]})
    assert response.status_code==422
    assert store.current_snapshot==before


def test_single_save_still_supported(client):
    response=client.post('/api/controls/update',json={'control_id':'CTRL-MFA-01','coverage_pct':0})
    assert response.status_code==200
    assert response.json()['new_coverage']==0
