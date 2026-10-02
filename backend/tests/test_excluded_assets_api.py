import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import json
from fastapi.testclient import TestClient
from app.main import app
from app.api.routes import store
from app.core.config import DATA_DIR, settings

client = TestClient(app)

def test_api_excluded_assets_behavior():
    with open(DATA_DIR / "scenarios.json", "r", encoding="utf-8") as f:
        scenarios = json.load(f)

    # Asset with NO business context (e.g. newly discovered host)
    unassigned_asset = {
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
        {"id": "FND-001", "asset_id": "192.168.118.212", "cve_id": "CVE-2024-1111", "severity": "Critical", "cvss": 9.8},
        {"id": "FND-002", "asset_id": "192.168.118.212", "cve_id": "CVE-2024-2222", "severity": "High", "cvss": 7.5},
        {"id": "FND-003", "asset_id": "192.168.118.212", "cve_id": "CVE-2024-3333", "severity": "Medium", "cvss": 5.0},
        {"id": "FND-004", "asset_id": "192.168.118.212", "cve_id": "CVE-2024-4444", "severity": "Low", "cvss": 3.0}
    ]

    store.current_snapshot = {
        "assets": [unassigned_asset],
        "services": [],
        "findings": findings,
        "cve_intel": {},
        "control_state": [],
        "scenarios": scenarios,
        "organization": {"name": "Apex FinCorp Lab", "risk_appetite_var95": 120000000.0}
    }
    store.cached_summary = None

    # 1. Verify GET /api/risk/summary
    res = client.get("/api/risk/summary?refresh=true")
    assert res.status_code == 200
    data = res.json()
    assert data["org"]["eal"] is None
    assert data["excluded_assets_count"] == 1
    assert data["excluded_assets"][0]["asset_id"] == "192.168.118.212"

    # 2. Verify GET /api/risk/entities?level=asset
    res_ent = client.get("/api/risk/entities?level=asset")
    assert res_ent.status_code == 200
    ent_data = res_ent.json()
    assert ent_data["excluded_assets_count"] == 1
    assert len(ent_data["entities"]) == 1
    assert ent_data["entities"][0]["asset_id"] == "192.168.118.212"
    assert ent_data["entities"][0]["criticality"] is None
    assert ent_data["entities"][0]["eal"] is None
    assert ent_data["entities"][0]["excluded_from_eal"] is True

    print("[PASS] API /api/risk/summary & /api/risk/entities verified: EAL=0.0, excluded_assets_count=1")

if __name__ == "__main__":
    test_api_excluded_assets_behavior()
