"""Indexer aggregation, durable history, failure and credential boundary checks."""
import copy
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.api.routes import SnapshotStore, store, sync_wazuh_indexer
from app.connectors.wazuh_indexer import WazuhIndexerConnector
from app.core.connections_store import ConnectionsStore
from app.core.state_proxy import export_state, import_state

END = datetime(2026, 10, 3, 12, tzinfo=timezone.utc)


def bucket(agent, hours, volume, auth=0, high=0):
    return {"key": {"agent": agent, "window": int((END - timedelta(hours=hours)).timestamp()*1000)},
            "doc_count": volume, "auth_failures": {"doc_count": auth}, "high_severity": {"doc_count": high}}


def response(buckets, after=None, total=150):
    result = {"hits": {"total": {"value": total, "relation": "eq"}}, "_shards": {"failed": 0},
              "aggregations": {"auth_failures": {"doc_count": 4}, "high_severity": {"doc_count": 3},
                               "windows": {"buckets": buckets}}}
    if after:
        result["aggregations"]["windows"]["after_key"] = after
    return result


def measured(buckets):
    connector = WazuhIndexerConnector("https://indexer.example", "reader", "test-secret")
    with patch.object(connector, "_search", return_value=response(buckets)):
        return connector.fetch_alert_windows(now=END)


def test_pagination_preserves_per_agent_counts_and_completed_hours():
    connector = WazuhIndexerConnector("https://indexer.example", "reader", "test-secret")
    cursor = {"agent": "001", "window": int(END.timestamp()*1000)}
    with patch.object(connector, "_search", side_effect=[response([bucket("001", 2, 100, 3, 1)], cursor),
                                                        response([bucket("002", 1, 50, 1, 2)])]) as search:
        data = connector.fetch_alert_windows(now=END + timedelta(minutes=45))
    assert [r["event_volume"] for r in data["windows"]] == [100, 50]
    assert [r["auth_failures"] for r in data["windows"]] == [3, 1]
    assert data["recent_alerts_24h"] == 150
    assert data["range_end"] == END.isoformat()
    second = search.call_args.args[0]
    assert second["aggs"]["windows"]["composite"]["after"] == cursor
    assert second["query"]["range"]["timestamp"]["lt"] == END.isoformat()


@pytest.mark.parametrize("status", [401, 403, 404, 500, 302])
def test_safe_http_errors_do_not_expose_password_or_response(status):
    from requests import Response
    raw = Response()
    raw.status_code = status
    raw._content = b'private response data'
    with patch("app.connectors.wazuh_indexer.integration_request", return_value=raw) as request:
        with pytest.raises(ConnectionError) as error:
            WazuhIndexerConnector("https://indexer.example", "reader", "test-secret").test_connection()
    assert "test-secret" not in str(error.value)
    assert "private response" not in str(error.value)
    assert request.call_args.kwargs["params"]["allow_no_indices"] == "false"


@pytest.mark.parametrize("bad", [{"timed_out": True}, {"_shards": {"failed": 1}}, {}])
def test_incomplete_search_is_not_zero_activity(bad):
    from requests import Response
    import json
    raw = Response()
    raw.status_code = 200
    raw._content = json.dumps(bad).encode()
    with patch("app.connectors.wazuh_indexer.integration_request", return_value=raw):
        with pytest.raises(ConnectionError):
            WazuhIndexerConnector("https://indexer.example", "reader", "secret").test_connection()


@pytest.fixture
def isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("CRISP_ENV", "development")
    monkeypatch.setenv("CRISP_TESTING", "1")
    saved = ConnectionsStore(tmp_path / "connections.json")
    local = SnapshotStore()
    from app.core.state_proxy import bound_store
    token = bound_store.set(local)
    with patch("app.api.routes.connections_store", saved):
        yield saved, local
    bound_store.reset(token)


def save_indexer(saved):
    saved.save_connection("indexer", "https://indexer.example", "reader", "test-secret",
                          test_result={"success": True, "detail": "Verified"})


def test_repeat_refresh_deduplicates_and_state_survives_reload(isolated):
    saved, local = isolated
    save_indexer(saved)
    data = measured([bucket("001", n, 10+n) for n in range(1, 7)] + [bucket("002", 1, 300)])
    with patch("app.api.routes.WazuhIndexerConnector") as connector:
        connector.return_value.fetch_alert_windows.side_effect = lambda: copy.deepcopy(data)
        sync_wazuh_indexer()
        sync_wazuh_indexer()
    assert len(local.telemetry_history) == 7
    assert local.get_telemetry_anomalies()["total_windows"] == 6
    assert local.get_telemetry_anomalies()["status"] == "scored"
    assert local.telemetry_history[-1]["event_volume"] == 300
    restored = SnapshotStore()
    import_state(restored, export_state(local))
    assert restored.get_telemetry_anomalies()["source"] == "Wazuh Indexer API"
    assert restored.get_telemetry_anomalies()["total_windows"] == 6


def test_many_agents_in_one_hour_do_not_satisfy_baseline(isolated):
    saved, local = isolated
    save_indexer(saved)
    data = measured([bucket(str(n), 1, 10) for n in range(10)])
    with patch("app.api.routes.WazuhIndexerConnector") as connector:
        connector.return_value.fetch_alert_windows.return_value = data
        sync_wazuh_indexer()
    result = local.get_telemetry_anomalies()
    assert result["total_windows"] == 1
    assert result["observation_count"] == 10
    assert result["status"] == "insufficient_baseline_data"


def test_failed_search_disables_stale_scoring_and_recovers(isolated):
    from fastapi import HTTPException
    saved, local = isolated
    save_indexer(saved)
    data = measured([bucket("001", n, 10+n) for n in range(1, 7)])
    with patch("app.api.routes.WazuhIndexerConnector") as connector:
        connector.return_value.fetch_alert_windows.side_effect = [copy.deepcopy(data), ConnectionError("Search timed out"), copy.deepcopy(data)]
        sync_wazuh_indexer()
        with pytest.raises(HTTPException):
            sync_wazuh_indexer()
        assert local.get_telemetry_anomalies()["signals"] == []
        assert "timed out" in local.get_telemetry_anomalies()["message"]
        assert saved.get_public_connection("indexer")["connected"] is False
        sync_wazuh_indexer()
        assert local.get_telemetry_anomalies()["status"] == "scored"


def test_credentials_encrypted_and_not_reused_for_new_host(isolated):
    saved, _ = isolated
    save_indexer(saved)
    assert "test-secret" not in saved.file_path.read_text()
    assert "password" not in str(saved.get_all_public())
    with pytest.raises(ValueError, match="credentials again"):
        saved.save_connection("indexer", "https://different.example", "reader", "")
    result = saved.test_connection("indexer", "https://different.example", "reader", None)
    assert result["success"] is False


def test_ui_api_save_refresh_disconnect_lifecycle(isolated):
    saved, local = isolated
    data = measured([bucket("001", n, 10+n) for n in range(1, 7)])
    payload = {"base_url": "https://indexer.example", "username": "reader", "password": "test-secret"}
    with patch("app.core.connections_store.WazuhIndexerConnector") as test_connector, \
         patch("app.api.routes.WazuhIndexerConnector") as sync_connector:
        test_connector.return_value.test_connection.return_value = {"success": True, "detail": "Search verified"}
        sync_connector.return_value.fetch_alert_windows.side_effect = lambda: copy.deepcopy(data)
        client = TestClient(app)
        tested = client.post("/api/connections/indexer/test", json=payload)
        assert tested.json()["success"] is True
        saved_response = client.post("/api/connections/indexer/save", json=payload)
        assert saved_response.status_code == 200
        assert "test-secret" not in saved_response.text
        assert "Loaded" in saved_response.json()["connection"]["last_test_detail"]
        refreshed = client.post("/api/connections/refresh")
        assert refreshed.json()["results"]["indexer"]["success"] is True
        assert len(local.telemetry_history) == 6
        assert client.delete("/api/connections/indexer").json()["status"] == "REMOVED"
        assert local.telemetry_history == []
        assert "indexer_telemetry" not in local.current_snapshot
        from app.core.sync_state import sync_state_manager
        assert sync_state_manager.get_freshness_summary()["wazuh_indexer"]["status"] == "not_configured"


def test_worker_executes_indexer_job_without_simulate_parameter(monkeypatch, tmp_path):
    import time
    from app.worker import sync_once
    from app.core.tenancy import tenant_transaction, write_document, read_document
    monkeypatch.setenv("CRISP_ENV", "development")
    monkeypatch.setenv("CRISP_DATABASE_PATH", str(tmp_path / "worker.sqlite3"))
    identity = {"tenant": "indexer-worker", "subject": "test"}
    with tenant_transaction(identity):
        write_document("sync_schedule", {"last_intel": time.time()})
    with patch("app.api.routes.sync_wazuh_telemetry"), patch("app.api.routes.sync_iam_telemetry"), \
         patch("app.api.routes.sync_wazuh_indexer") as sync:
        assert sync_once(identity["tenant"])
        sync.assert_called_once_with()
    with tenant_transaction(identity):
        assert read_document("sync_schedule")["failed_jobs"] == []


def test_no_alerts_is_measured_zero_without_fabricated_windows(isolated):
    saved, local = isolated
    save_indexer(saved)
    connector = WazuhIndexerConnector("https://indexer.example", "reader", "test-secret")
    data = response([], total=0)
    data["aggregations"]["auth_failures"]["doc_count"] = 0
    data["aggregations"]["high_severity"]["doc_count"] = 0
    with patch.object(connector, "_search", return_value=data):
        empty = connector.fetch_alert_windows(now=END)
    with patch("app.api.routes.WazuhIndexerConnector") as live:
        live.return_value.fetch_alert_windows.return_value = empty
        sync_wazuh_indexer()
    assert local.current_snapshot["indexer_telemetry"]["recent_alerts_24h"] == 0
    assert local.telemetry_history == []
    assert local.get_telemetry_anomalies()["status"] == "insufficient_baseline_data"
