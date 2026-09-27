import sys
import io
if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_api_contract_endpoints():
    from app.api.routes import store
    from app.core.config import DATA_DIR
    import json

    # 0. Verify fresh empty state
    res_empty = client.get("/api/risk/summary")
    assert res_empty.status_code == 200
    assert res_empty.json()["status"] == "NO_DATA"

    # Load developer test fixture snapshot for API contract verification
    with open(DATA_DIR / "seed_snapshot.json", "r", encoding="utf-8") as f:
        store.current_snapshot = json.load(f)
    store.get_summary(force_refresh=True)

    # 1. Summary
    res = client.get("/api/risk/summary")
    assert res.status_code == 200, f"Summary failed: {res.text}"
    summary = res.json()
    assert "run_id" in summary
    assert "org" in summary
    assert summary["org"]["eal"] > 0
    print("✓ GET /api/risk/summary verified")

    # 2. Entities
    res = client.get("/api/risk/entities?level=asset")
    assert res.status_code == 200
    assert len(res.json()["entities"]) > 0
    print("✓ GET /api/risk/entities verified")

    # 3. Drivers
    res = client.get("/api/risk/drivers")
    assert res.status_code == 200
    assert len(res.json()["top_drivers"]) > 0
    print("✓ GET /api/risk/drivers verified")

    # 4. Curve
    res = client.get("/api/risk/curve")
    assert res.status_code == 200
    assert len(res.json()["curve"]) > 0
    print("✓ GET /api/risk/curve verified")

    # 5. Simulate
    sim_payload = {
        "actions": [
            {"type": "increase_control_coverage", "target_id": "CTRL-MFA-01", "coverage_pct": 100.0}
        ]
    }
    res = client.post("/api/simulate", json=sim_payload)
    assert res.status_code == 200
    sim_data = res.json()
    assert "delta" in sim_data
    assert sim_data["delta"]["eal_reduction"] > 0
    assert "cost_of_delay" in sim_data
    print("✓ POST /api/simulate verified")

    # 6. Optimize
    opt_payload = {"budget": 10000000.0}
    res = client.post("/api/optimize", json=opt_payload)
    assert res.status_code == 200
    opt_data = res.json()
    assert "benchmark" in opt_data
    assert "headline" in opt_data["benchmark"]
    print("✓ POST /api/optimize verified")

    # 7. Pareto
    res = client.get("/api/pareto")
    assert res.status_code == 200
    assert len(res.json()["curve"]) > 0
    print("✓ GET /api/pareto verified")

    # 8. Compliance
    res = client.get("/api/compliance/sebi")
    assert res.status_code == 200
    comp_data = res.json()
    assert "sebi_6hour_readiness" in comp_data
    assert "overall_coverage_pct" in comp_data
    print("✓ GET /api/compliance/sebi verified")

    # 9. Report
    res = client.get("/api/report/sebi")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "CRISP Continuous Compliance" in res.text
    print("✓ GET /api/report/sebi verified")

    # 10. Ask AI
    ask_payload = {"question": "What is our highest financial cyber risk today?"}
    res = client.post("/api/ask", json=ask_payload)
    assert res.status_code == 200
    ask_data = res.json()
    assert "answer" in ask_data
    assert "run_id" in ask_data
    print("✓ POST /api/ask verified")

    # 11. Health / Data Quality
    res = client.get("/api/health/data-quality")
    assert res.status_code == 200
    assert res.json()["data_quality_score"] > 0.5
    print("✓ GET /api/health/data-quality verified")

    # 12. Demo Live Event Injection
    inject_payload = {
        "cve_id": "CVE-2026-9999",
        "asset_id": "AST-CORE-DB-01",
        "severity": "Critical",
        "epss": 0.98
    }
    res = client.post("/api/demo/inject-event", json=inject_payload)
    assert res.status_code == 200
    inject_data = res.json()
    assert inject_data["event"] == "KEV_INJECTION_SUCCESS"
    assert inject_data["new_eal"] > inject_data["previous_eal"]
    print(f"✓ POST /api/demo/inject-event verified (EAL jumped by ₹{inject_data['jump_amount']:,.2f})")

if __name__ == "__main__":
    test_api_contract_endpoints()
    print("\nALL 12 PRD API CONTRACT ENDPOINTS TESTED AND VERIFIED SUCCESSFULLY!")
