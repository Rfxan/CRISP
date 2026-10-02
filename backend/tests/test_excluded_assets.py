import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import json
from app.engine.fair_engine import FAIREngine
from app.core.config import DATA_DIR, settings

def test_unassigned_asset_reproduction():
    with open(DATA_DIR / "scenarios.json", "r", encoding="utf-8") as f:
        scenarios = json.load(f)

    # Discovered host with NO business context (exactly as created by scan ingestion)
    asset = {
        "id": "192.168.118.212",
        "name": "192.168.118.212",
        "type": "Discovered Host",
        "owner": None,
        "business_service_id": None,
        "environment": None,
        "internet_facing": None,
        "data_classification": None,
        "records_count": None,
        "revenue_per_hour": None,
        "criticality_1_5": None,
        "is_real_lab_asset": True,
        "has_business_context": False
    }

    findings = [
        {"id": "F1", "asset_id": "192.168.118.212", "cve_id": "CVE-2024-1111", "severity": "Critical", "cvss": 9.8},
        {"id": "F2", "asset_id": "192.168.118.212", "cve_id": "CVE-2024-2222", "severity": "High", "cvss": 7.5},
        {"id": "F3", "asset_id": "192.168.118.212", "cve_id": "CVE-2024-3333", "severity": "Medium", "cvss": 5.0},
        {"id": "F4", "asset_id": "192.168.118.212", "cve_id": "CVE-2024-4444", "severity": "Low", "cvss": 3.0}
    ]

    snapshot = {
        "assets": [asset],
        "services": [],
        "findings": findings,
        "cve_intel": {},
        "control_state": [],
        "scenarios": scenarios,
        "organization": {"name": "Test Org", "risk_appetite_var95": 100000000.0}
    }

    engine = FAIREngine(trials=5000, seed=settings.DEFAULT_SEED)
    res = engine.run(snapshot)
    print("CURRENT EAL:", res["org"]["eal"])
    print("Breakdown:", res["loss_breakdown"])
    print("Excluded count:", res.get("excluded_assets_count"))
    print("Excluded assets:", res.get("excluded_assets"))

    # Assertions for Approach A:
    # 1. Unassigned asset contributes strictly ₹0 to EAL and loss breakdown
    assert res["org"]["eal"] is None

    # 2. Excluded assets list and count surfaced in simulation output
    assert res.get("excluded_assets_count") == 1
    assert res["excluded_assets"][0]["asset_id"] == "192.168.118.212"
    assert res["excluded_assets"][0]["reason"] == "Missing declared business context"

    # 3. Asset summary reflects exclusion
    assert len(res["assets"]) == 1
    assert res["assets"][0]["asset_id"] == "192.168.118.212"
    assert res["assets"][0]["criticality"] is None
    assert res["assets"][0]["eal"] is None
    assert res["assets"][0]["excluded_from_eal"] is True
    assert res["assets"][0]["has_business_context"] is False

    # 4. If business context IS declared (e.g. criticality = 2), it computes normally
    snapshot_assigned = json.loads(json.dumps(snapshot))
    snapshot_assigned["assets"][0]["criticality_1_5"] = 2
    snapshot_assigned["assets"][0]["has_business_context"] = True
    res_assigned = engine.run(snapshot_assigned)
    assert res_assigned["org"]["eal"] > 0.0
    assert res_assigned.get("excluded_assets_count") == 0
    print("ASSIGNED EAL:", res_assigned["org"]["eal"])

if __name__ == "__main__":
    test_unassigned_asset_reproduction()
