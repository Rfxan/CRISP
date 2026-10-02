from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.connections_store import ConnectionsStore


@pytest.mark.parametrize('success', [True, False])
def test_refresh_checks_saved_endpoint_and_updates_result(tmp_path, monkeypatch, success):
    monkeypatch.setenv('CRISP_ENV','development')
    monkeypatch.setenv('CRISP_TESTING','1')
    saved = ConnectionsStore(tmp_path/'connections.json')
    saved._write_file({'siem':{'base_url':'https://example.invalid:55000','username':'test',
        'encrypted_password':'unchanged','connected':True,'last_tested':'2020-01-01T00:00:00Z'}})
    with patch('app.api.routes.connections_store',saved), \
         patch.object(saved,'test_connection',return_value={'success':success,'detail':'Checked now'}) as check, \
         patch('app.api.routes.sync_wazuh_telemetry') as sync, patch('app.api.routes.sync_iam_telemetry') as iam:
        response=TestClient(app).post('/api/connections/refresh')
    assert response.status_code==200
    result=response.json()['connections']['siem']
    assert result['connected'] is success
    assert result['last_tested']!='2020-01-01T00:00:00Z'
    assert result['last_test_detail']=='Checked now'
    assert 'encrypted_password' not in result
    assert saved._read_file()['siem']['encrypted_password']=='unchanged'
    check.assert_called_once_with('siem')
    sync.assert_called_once_with(simulate=False)
    iam.assert_not_called()


def test_unconfigured_refresh_makes_no_connector_calls(tmp_path,monkeypatch):
    monkeypatch.setenv('CRISP_ENV','development')
    monkeypatch.setenv('CRISP_TESTING','1')
    saved=ConnectionsStore(tmp_path/'connections.json')
    with patch('app.api.routes.connections_store',saved), patch.object(saved,'test_connection') as check:
        result=TestClient(app).post('/api/connections/refresh')
    assert result.status_code==200
    assert result.json()['results']=={}
    check.assert_not_called()
