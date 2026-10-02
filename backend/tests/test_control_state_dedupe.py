import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient
from app.main import app
from app.api.routes import store, dedupe_control_states, _is_better_control_state

client = TestClient(app)


def test_fresh_backend_snapshot_16_unique_controls():
    """Verify fresh backend GET /snapshot returns exactly 16 control states with 16 unique IDs."""
    store._init_empty()
    res = client.get("/snapshot")
    assert res.status_code == 200, f"Expected 200 from GET /snapshot, got {res.status_code}"
    data = res.json()
    controls = data.get("control_state", [])
    assert len(controls) == 16, f"Expected 16 controls, got {len(controls)}"
    control_ids = [c["control_id"] for c in controls]
    assert len(set(control_ids)) == 16, f"Expected 16 unique control IDs, got {len(set(control_ids))}: {control_ids}"


def test_dedupe_prefers_last_checked_and_coverage():
    """Verify dedupe collapses duplicates keeping most recent last_checked or non-None coverage_pct."""
    # 1. Prefer non-None coverage_pct over None
    c_none = {
        "control_id": "CTRL-EDR-01",
        "coverage_pct": None,
        "evidence_ref": "Not Connected",
        "last_checked": None,
        "is_simulated": False
    }
    c_cov = {
        "control_id": "CTRL-EDR-01",
        "coverage_pct": 85.0,
        "evidence_ref": "Wazuh Live API (6/6 endpoints)",
        "last_checked": "2026-09-28T10:00:00Z",
        "is_simulated": False
    }
    deduped, removed = dedupe_control_states([c_none, c_cov])
    assert removed == 1
    assert len(deduped) == 1
    assert deduped[0]["coverage_pct"] == 85.0
    assert deduped[0]["last_checked"] == "2026-09-28T10:00:00Z"

    # 2. Reverse order: still prefers non-None coverage_pct
    deduped, removed = dedupe_control_states([c_cov, c_none])
    assert removed == 1
    assert len(deduped) == 1
    assert deduped[0]["coverage_pct"] == 85.0

    # 3. Prefer more recent last_checked
    c_older = {
        "control_id": "CTRL-MFA-01",
        "coverage_pct": 50.0,
        "evidence_ref": "Keycloak",
        "last_checked": "2026-09-20T10:00:00Z"
    }
    c_newer = {
        "control_id": "CTRL-MFA-01",
        "coverage_pct": 75.0,
        "evidence_ref": "Keycloak",
        "last_checked": "2026-09-29T10:00:00Z"
    }
    deduped, removed = dedupe_control_states([c_older, c_newer])
    assert removed == 1
    assert deduped[0]["coverage_pct"] == 75.0

    # 4. Collapse 16 catalog NO DATA appended on top of 12 seed states -> exactly 16 unique controls
    catalog_states = [
        {"control_id": ctrl["id"], "coverage_pct": None, "last_checked": None, "evidence_ref": "Not Connected"}
        for ctrl in store.controls_catalog
    ]
    seed_states = [
        {"control_id": f"CTRL-{name}", "coverage_pct": 60.0, "last_checked": "2026-09-24T12:00:00Z", "evidence_ref": "Measured"}
        for name in ["MFA-01", "EDR-01", "PATCH-01", "ENC-01", "WAF-01", "SEG-01", "BKP-01", "SIEM-01", "PAM-01", "DLP-01", "API-01", "IR-01"]
    ]
    combined = seed_states + catalog_states
    assert len(combined) == 28
    deduped, removed = dedupe_control_states(combined)
    assert len(deduped) == 16
    assert removed == 12
    # Verify the 12 seed controls kept their 60.0% coverage
    for cs in deduped:
        if cs["control_id"] in [s["control_id"] for s in seed_states]:
            assert cs["coverage_pct"] == 60.0


def test_demo_data_renders_drilldown_and_optimizer():
    """Verify that with demo data ingested, summary has real EAL and is not NO_DATA."""
    store.load_seed()
    res = client.get("/api/risk/summary")
    assert res.status_code == 200
    summary = res.json()
    assert summary.get("status") not in ("NO_DATA", "NO_FINDINGS")
    assert summary.get("org", {}).get("eal", 0) > 0

    res_drivers = client.get("/api/risk/drivers")
    assert res_drivers.status_code == 200
    drivers = res_drivers.json()
    assert drivers.get("status") not in ("NO_DATA", "NO_FINDINGS")

    res_opt = client.post("/api/optimize", json={"budget": 10000000})
    assert res_opt.status_code == 200
    opt_data = res_opt.json()
    assert "plan" in opt_data
    assert "benchmark" in opt_data
    assert len(opt_data["plan"].get("selected_controls", [])) > 0
