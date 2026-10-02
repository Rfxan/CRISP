import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.api.routes import store
from app.core.connections_store import connections_store

client = TestClient(app)


def test_real_wazuh_sync_updates_both_edr_and_siem_controls_and_sebi_readiness():
    """
    Acceptance test:
    With 1-agent lab connected, run a real sync:
    - CTRL-EDR-01 updated to 100%
    - CTRL-SIEM-01 updated to 100%
    - Evidence format specifies active/total endpoints reporting
    - With IR 0%, SEBI 6-hour readiness calculates to 70.0% and status is honestly 'AT RISK'
    """
    store.load_seed()
    store.telemetry_history = []
    store.has_real_siem_sync = False
    store.telemetry_source = "none"

    # Set CTRL-IR-01 to 0.0% coverage so IR has no telemetry
    for c in store.current_snapshot.get("control_state", []):
        if c.get("control_id") == "CTRL-IR-01":
            c["coverage_pct"] = 0.0

    mock_conn = {
        "category": "siem",
        "base_url": "https://wazuh-lab.internal:55000",
        "username": "wazuh-lab-admin",
        "connected": True
    }

    mock_agent_data = {
        "total_agents": 1,
        "active_agents": 1,
        "agent_coverage_pct": 100.0,
        "agent_names": ["lab-agent-01"],
        "agents": [{"id": "001", "name": "lab-agent-01", "status": "active"}]
    }
    mock_alert_data = {
        "recent_alerts_24h": 45,
        "high_severity_alerts_24h": 1,
        "auth_failures_24h": 2
    }

    with patch.object(connections_store, "get_connection", return_value=mock_conn):
        with patch("app.api.routes.WazuhConnector") as MockConnector:
            inst = MockConnector.return_value
            inst.fetch_agent_status.return_value = mock_agent_data
            inst.fetch_alert_summary.return_value = mock_alert_data

            res = client.post("/api/ingest/wazuh-sync")
            assert res.status_code == 200
            data = res.json()

            # Check response contains both edr_control and siem_control
            assert "edr_control" in data
            assert "siem_control" in data
            assert data["edr_control"]["coverage_pct"] == 100.0
            assert "Wazuh Live API (1/1 endpoints)" in data["edr_control"]["evidence_ref"]
            assert data["edr_control"]["is_simulated"] is False

            assert data["siem_control"]["coverage_pct"] == 100.0
            assert "Wazuh Live API (1/1 endpoints reporting)" in data["siem_control"]["evidence_ref"]
            assert data["siem_control"]["is_simulated"] is False

            # Verify in snapshot control_state
            ctrl_edr = next((c for c in store.current_snapshot["control_state"] if c["control_id"] == "CTRL-EDR-01"), None)
            ctrl_siem = next((c for c in store.current_snapshot["control_state"] if c["control_id"] == "CTRL-SIEM-01"), None)

            assert ctrl_edr is not None
            assert ctrl_edr["coverage_pct"] == 100.0
            assert "Wazuh Live API (1/1 endpoints)" in ctrl_edr["evidence_ref"]
            assert ctrl_edr["is_simulated"] is False
            assert ctrl_edr["is_user_assumed"] is False

            assert ctrl_siem is not None
            assert ctrl_siem["coverage_pct"] == 100.0
            assert "Wazuh Live API (1/1 endpoints reporting)" in ctrl_siem["evidence_ref"]
            assert ctrl_siem["is_simulated"] is False
            assert ctrl_siem["is_user_assumed"] is False

            # Verify SEBI 6-hour readiness evaluation
            eval_res = client.get("/api/compliance/sebi")
            assert eval_res.status_code == 200
            eval_data = eval_res.json()
            sebi = eval_data["sebi_6hour_readiness"]

            # Tool coverage cannot establish demonstrated incident-reporting readiness.
            assert sebi["readiness_score_pct"] is None
            assert sebi["status"] == "NOT VERIFIED"
            assert sebi["exercises"] == []


def test_simulate_sync_sets_mock_label_on_both_controls():
    """POST /api/ingest/wazuh-sync?simulate=true sets mock evidence label on both EDR and SIEM."""
    store.load_seed()

    res = client.post("/api/ingest/wazuh-sync?simulate=true")
    assert res.status_code == 200
    data = res.json()

    assert data["edr_control"]["is_simulated"] is True
    assert "Wazuh Telemetry Mock (6/6 endpoints)" in data["edr_control"]["evidence_ref"]

    assert data["siem_control"]["is_simulated"] is True
    assert "Wazuh Telemetry Mock (6/6 endpoints reporting)" in data["siem_control"]["evidence_ref"]

    ctrl_edr = next((c for c in store.current_snapshot["control_state"] if c["control_id"] == "CTRL-EDR-01"), None)
    ctrl_siem = next((c for c in store.current_snapshot["control_state"] if c["control_id"] == "CTRL-SIEM-01"), None)

    assert ctrl_edr["is_simulated"] is True
    assert "Wazuh Telemetry Mock (6/6 endpoints)" in ctrl_edr["evidence_ref"]

    assert ctrl_siem["is_simulated"] is True
    assert "Wazuh Telemetry Mock (6/6 endpoints reporting)" in ctrl_siem["evidence_ref"]


def test_disconnect_wazuh_drops_both_controls_to_not_connected_without_deleting():
    """
    Disconnect Wazuh:
    Both CTRL-EDR-01 and CTRL-SIEM-01 drop to Not Connected / coverage_pct=None
    without being deleted from control_state.
    """
    store.load_seed()

    # Save a connection first
    save_res = client.post("/api/connections/siem/save", json={
        "base_url": "https://wazuh-temp.internal:55000",
        "username": "admin",
        "password": "secretpassword"
    })
    assert save_res.status_code == 200

    # Simulate sync so controls have coverage
    client.post("/api/ingest/wazuh-sync?simulate=true")
    ctrl_siem = next((c for c in store.current_snapshot["control_state"] if c["control_id"] == "CTRL-SIEM-01"), None)
    assert ctrl_siem["coverage_pct"] is not None

    # Now disconnect Wazuh
    del_res = client.delete("/api/connections/siem")
    assert del_res.status_code == 200
    assert del_res.json()["status"] == "REMOVED"

    # Both controls must remain in control_state, never deleted
    ctrl_edr = next((c for c in store.current_snapshot["control_state"] if c["control_id"] == "CTRL-EDR-01"), None)
    ctrl_siem = next((c for c in store.current_snapshot["control_state"] if c["control_id"] == "CTRL-SIEM-01"), None)

    assert ctrl_edr is not None
    assert ctrl_edr["coverage_pct"] is None
    assert ctrl_edr["evidence_ref"] == "Not Connected"
    assert ctrl_edr["is_simulated"] is False

    assert ctrl_siem is not None
    assert ctrl_siem["coverage_pct"] == None
    assert ctrl_siem["evidence_ref"] == "Not Connected"
    assert ctrl_siem["is_simulated"] is False


def test_wazuh_sync_failure_resets_both_controls_to_not_connected():
    """When live Wazuh API sync raises an error, both controls are reset to Not Connected."""
    store.load_seed()

    mock_conn = {
        "category": "siem",
        "base_url": "https://wazuh-failing.internal:55000",
        "username": "admin",
        "connected": True
    }

    with patch.object(connections_store, "get_connection", return_value=mock_conn):
        with patch("app.api.routes.WazuhConnector") as MockConnector:
            inst = MockConnector.return_value
            inst.fetch_agent_status.side_effect = RuntimeError("Connection timeout to Wazuh Manager")

            res = client.post("/api/ingest/wazuh-sync")
            assert res.status_code == 502
            assert res.json()["detail"] == "External service unavailable"
            assert "Connection timeout" not in res.text

            ctrl_edr = next((c for c in store.current_snapshot["control_state"] if c["control_id"] == "CTRL-EDR-01"), None)
            ctrl_siem = next((c for c in store.current_snapshot["control_state"] if c["control_id"] == "CTRL-SIEM-01"), None)

            assert ctrl_edr is not None
            assert ctrl_edr["coverage_pct"] is None
            assert ctrl_edr["evidence_ref"] == "Not Connected"

            assert ctrl_siem is not None
            assert ctrl_siem["coverage_pct"] is None
            assert ctrl_siem["evidence_ref"] == "Not Connected"
