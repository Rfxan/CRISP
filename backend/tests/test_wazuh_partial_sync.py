from unittest.mock import patch

from fastapi.testclient import TestClient

from app.main import app
from app.api.routes import store
from app.connectors.wazuh import WazuhConnector
from app.core.connections_store import connections_store


def test_manager_alerts_are_unknown_without_unsupported_requests():
    connector = WazuhConnector(base_url="https://wazuh.example")
    with patch("app.connectors.wazuh.integration_request") as request:
        alerts = connector.fetch_alert_summary()
    request.assert_not_called()
    assert alerts["recent_alerts_24h"] is None
    assert alerts["high_severity_alerts_24h"] is None
    assert alerts["auth_failures_24h"] is None
    assert alerts["alert_status"] == "unavailable"


def test_refresh_preserves_agent_connection_when_alerts_unavailable():
    store.load_seed()
    store.telemetry_history = []
    agents = {"total_agents": 1, "active_agents": 1, "agent_coverage_pct": 100.0,
              "agents": [{"id": "001", "name": "endpoint", "status": "active"}]}
    alerts = WazuhConnector(base_url="https://wazuh.example").fetch_alert_summary()
    conn = {"base_url": "https://wazuh.example", "username": "wazuh-wui", "connected": True}
    with patch.object(connections_store, "get_public_connection", side_effect=lambda category: conn if category == "siem" else None), \
         patch.object(connections_store, "get_connection", return_value=conn), \
         patch.object(connections_store, "test_connection", return_value={"success": True, "detail": "Found 1 agent"}), \
         patch.object(connections_store, "record_connection_result") as recorded, \
         patch("app.api.routes.WazuhConnector") as connector:
        connector.return_value.fetch_agent_status.return_value = agents
        connector.return_value.fetch_alert_summary.return_value = alerts
        response = TestClient(app).post("/api/connections/refresh")
    assert response.status_code == 200
    result = response.json()["results"]["siem"]
    assert result["success"] is True
    assert "indexer" in result["warning"]
    assert recorded.call_args.args[1] is True
    assert store.current_snapshot["wazuh_telemetry"]["active_agents"] == 1
    assert store.current_snapshot["wazuh_telemetry"]["recent_alerts_24h"] is None
    assert store.telemetry_history == []
    assert store.has_real_siem_sync is False
    assert next(c for c in store.current_snapshot["control_state"] if c["control_id"] == "CTRL-EDR-01")["coverage_pct"] == 100
