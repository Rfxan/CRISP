import sys
import json
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.api.routes import store
from app.core.connections_store import connections_store
from app.ai.anomaly import ANOMALY_LABEL

client = TestClient(app)


def test_zero_connections_demo_data_labeled():
    """When zero connections exist, demo seeding is explicit with demo fixture source and DEMO label."""
    # Load seed snapshot and reset telemetry history and connection
    store.load_seed()
    store.telemetry_history = []
    store.has_real_siem_sync = False
    store.telemetry_source = "none"

    with patch.object(connections_store, "get_connection", return_value=None):
        res = client.get("/api/threats/anomalies")
        assert res.status_code == 200
        data = res.json()
        assert data["source"] == "demo fixture"
        assert data["is_demo"] is True
        for sig in data.get("signals", []):
            assert sig["is_demo"] is True
            assert sig["source"] == "demo fixture"


def test_live_wazuh_sync_baseline_accumulation_and_no_demo_fiction():
    """
    Live Wazuh API sync:
    1. Never calls _init_demo_telemetry_history().
    2. Appends real telemetry windows from live agent.
    3. Returns 'Building baseline: N/5 windows · Source: Wazuh Live API' until 5 windows exist.
    4. Once 5 windows exist, only the real agent appears (no fictional wazuh-* demo agents).
    """
    store.telemetry_history = []
    store.has_real_siem_sync = False
    store.telemetry_source = "none"

    mock_conn = {
        "category": "siem",
        "base_url": "https://wazuh-live.internal:55000",
        "username": "wazuh-admin",
        "connected": True
    }

    mock_agent_data = {
        "total_agents": 1,
        "active_agents": 1,
        "agent_coverage_pct": 100.0,
        "agent_names": ["lab-agent-prod-01"],
        "agents": [
            {"id": "001", "name": "lab-agent-prod-01", "status": "active"}
        ]
    }
    mock_alert_data = {
        "recent_alerts_24h": 120,
        "high_severity_alerts_24h": 2,
        "auth_failures_24h": 5
    }

    with patch.object(connections_store, "get_connection", return_value=mock_conn):
        # Even before sync, having a configured SIEM connection prevents demo seeding
        pre_res = client.get("/api/threats/anomalies")
        assert pre_res.status_code == 200
        pre_data = pre_res.json()
        assert pre_data["status"] == "insufficient_baseline_data"
        assert pre_data["source"] == "Wazuh Live API"
        assert pre_data["is_demo"] is False
        assert "Building baseline: 0/5 windows · Source: Wazuh Live API" in pre_data["message"]
        # Ensure no fictional agents were seeded
        assert len(store.telemetry_history) == 0

        # Run 1 real sync
        with patch("app.api.routes.WazuhConnector") as MockConnector:
            connector_instance = MockConnector.return_value
            connector_instance.fetch_agent_status.return_value = mock_agent_data
            connector_instance.fetch_alert_summary.return_value = mock_alert_data

            sync_res = client.post("/api/ingest/wazuh-sync")
            assert sync_res.status_code == 200
            assert store.has_real_siem_sync is True
            assert len(store.telemetry_history) == 1
            assert store.telemetry_history[0]["agent_id"] == "001"
            assert store.telemetry_history[0]["agent_name"] == "lab-agent-prod-01"
            assert store.telemetry_history[0]["source"] == "Wazuh Live API"

            # Check anomaly endpoint after 1 window
            res1 = client.get("/api/threats/anomalies")
            data1 = res1.json()
            assert data1["status"] == "insufficient_baseline_data"
            assert data1["message"] == "Building baseline: 1/5 windows · Source: Wazuh Live API"
            assert data1["total_windows"] == 1
            assert data1["source"] == "Wazuh Live API"
            assert data1["is_demo"] is False

            # Check drivers endpoint after 1 window
            drivers_res = client.get("/api/risk/drivers")
            drivers_data = drivers_res.json()
            assert drivers_data["anomaly_detection"]["status"] == "insufficient_baseline_data"
            assert drivers_data["anomaly_detection"]["message"] == "Building baseline: 1/5 windows · Source: Wazuh Live API"
            assert drivers_data["anomaly_detection"]["source"] == "Wazuh Live API"
            assert drivers_data["anomaly_detection"]["is_demo"] is False

            # Run 4 more syncs to reach 5 observation windows
            for i in range(2, 6):
                client.post("/api/ingest/wazuh-sync")
                assert len(store.telemetry_history) == i

            # Now 5 windows exist: baseline should be scored
            res5 = client.get("/api/threats/anomalies")
            data5 = res5.json()
            assert data5["status"] == "scored"
            assert data5["total_windows"] == 5
            assert data5["source"] == "Wazuh Live API"
            assert data5["is_demo"] is False

            # Any flagged or nominal signals must ONLY feature the real agent
            for item in data5.get("results", []):
                assert item["agent_id"] == "001"
                assert item["agent_name"] == "lab-agent-prod-01"
                assert "wazuh-ast-" not in item["agent_name"]
                assert item["source"] == "Wazuh Live API"
                assert item["is_demo"] is False


def test_simulate_flag_preserves_mock_label():
    """POST /api/ingest/wazuh-sync?simulate=true retains explicit mock label."""
    store.telemetry_history = []
    store.has_real_siem_sync = False
    store.telemetry_source = "none"

    with patch.object(connections_store, "get_connection", return_value=None):
        res = client.post("/api/ingest/wazuh-sync?simulate=true")
        assert res.status_code == 200
        assert store.current_snapshot["wazuh_telemetry"]["source"] == "Wazuh Telemetry Mock"

        anom_res = client.get("/api/threats/anomalies")
        anom_data = anom_res.json()
        assert anom_data["source"] == "Wazuh Telemetry Mock"
        assert anom_data["is_demo"] is True
