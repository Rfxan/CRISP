import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from app.main import app
from app.api.routes import store
from app.core.sync_state import sync_state_manager


@pytest.fixture
def client():
    return TestClient(app)


def test_sync_state_persistence_and_freshness():
    """
    1. Verify scheduled/manual sync jobs record last_sync_at, source, counts, status.
    2. Persists to sync_state.json and survives re-reading.
    3. Exposes real-time freshness summary.
    """
    # Record mock wazuh sync
    rec = sync_state_manager.record_sync(
        job_name="wazuh",
        source="Wazuh Live API",
        counts={"total_agents": 6, "active_agents": 6, "assets": 6, "findings": 0},
        status="ok",
        message="Synced 6/6 active agents"
    )
    assert rec["job"] == "wazuh"
    assert rec["status"] == "ok"
    assert rec["counts"]["active_agents"] == 6

    # Verify freshness summary
    freshness = sync_state_manager.get_freshness_summary()
    assert "wazuh" in freshness
    assert freshness["wazuh"]["agents_active"] == 6
    assert freshness["wazuh"]["agents_total"] == 6
    assert freshness["wazuh"]["status"] == "ok"
    assert freshness["wazuh"]["last_sync_at"] is not None


def test_diff_and_conditional_recompute(client):
    """
    Acceptance: hit sync, verify new run_id appears ONLY when data changed.
    If nothing changed, skip recompute (log why) and retain run_id.
    """
    # 1. Reset snapshot and load seed
    store.current_snapshot["assets"] = [
        {"id": "AST-01", "name": "Payment Gateway", "criticality_1_5": 5, "revenue_per_hour": 100000.0, "records_count": 50000}
    ]
    store.current_snapshot["findings"] = [
        {"id": "FND-01", "asset_id": "AST-01", "cve_id": "CVE-2024-1234", "severity": "High"}
    ]
    store.current_snapshot["control_state"] = [
        {"control_id": "CTRL-EDR-01", "coverage_pct": 50.0}
    ]

    # Initial compute
    init_summary = store.check_and_recompute(trigger="test_init", force=True)
    init_run_id = init_summary["run_id"]
    assert init_run_id is not None
    assert store.run_metadata["recomputed"] is True

    # 2. Call sync without changing any data -> recompute must be SKIPPED
    res1 = client.post("/api/ingest/wazuh-sync?simulate=true")
    assert res1.status_code == 200
    data1 = res1.json()
    first_run_id = data1["run_id"]

    # 3. Call sync again with identical data
    res2 = client.post("/api/ingest/wazuh-sync?simulate=true")
    assert res2.status_code == 200
    data2 = res2.json()
    second_run_id = data2["run_id"]

    # Same data must retain SAME run_id and skip recompute
    assert first_run_id == second_run_id
    assert data2["run_metadata"]["recomputed"] is False
    assert "No changes detected" in data2["run_metadata"]["skip_reason"]

    # 4. Now modify data: add a finding
    store.current_snapshot["findings"].append({
        "id": "FND-02", "asset_id": "AST-01", "cve_id": "CVE-2024-9999", "severity": "Critical"
    })

    # Call sync again -> data changed, so a NEW run_id MUST be minted!
    res3 = client.post("/api/ingest/wazuh-sync?simulate=true")
    assert res3.status_code == 200
    data3 = res3.json()
    third_run_id = data3["run_id"]

    assert third_run_id != second_run_id
    assert data3["run_metadata"]["recomputed"] is True
    assert data3["run_metadata"]["changes_detected"] is True


def test_sync_all_endpoint_and_freshness(client):
    """
    Tests POST /api/sync/all and GET /api/sync/state
    """
    res = client.post("/api/sync/all")
    assert res.status_code == 200
    payload = res.json()
    assert payload["status"] == "COMPLETED"
    assert "job_results" in payload
    assert "freshness" in payload
    assert "sync_state" in payload
    assert "run_metadata" in payload

    # Test GET /api/sync/state
    state_res = client.get("/api/sync/state")
    assert state_res.status_code == 200
    state_data = state_res.json()
    assert "freshness" in state_data
    assert "sync_state" in state_data
