import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.api.routes import store

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_snapshot():
    # Set up clean test state with 2 assets and findings
    store.current_snapshot["assets"] = [
        {
            "id": "AST-TEST-01",
            "name": "Test Server 1",
            "type": "Server",
            "owner": "SecOps",
            "business_service_id": "SVC-TEST-01",
            "environment": "Production",
            "internet_facing": True,
            "data_classification": "Confidential",
            "records_count": 50000,
            "revenue_per_hour": 100000.0,
            "criticality_1_5": 5,
            "is_real_lab_asset": True,
            "has_business_context": True
        },
        {
            "id": "AST-TEST-02",
            "name": "Test Server 2",
            "type": "Database",
            "owner": "DBA",
            "business_service_id": "SVC-TEST-02",
            "environment": "Internal",
            "internet_facing": False,
            "data_classification": "Internal",
            "records_count": 10000,
            "revenue_per_hour": 25000.0,
            "criticality_1_5": 3,
            "is_real_lab_asset": True,
            "has_business_context": True
        }
    ]
    store.current_snapshot["findings"] = [
        {
            "id": "FND-001",
            "asset_id": "AST-TEST-01",
            "cve_id": "CVE-2023-38606",
            "severity": "Critical",
            "is_patched": False
        },
        {
            "id": "FND-002",
            "asset_id": "AST-TEST-02",
            "cve_id": "CVE-2023-32434",
            "severity": "High",
            "is_patched": False
        }
    ]
    store.current_snapshot["services"] = [
        {"service_id": "SVC-TEST-01", "name": "Service 1", "criticality": 5},
        {"service_id": "SVC-TEST-02", "name": "Service 2", "criticality": 3}
    ]
    store.get_summary(force_refresh=True)
    yield
    # Cleanup
    store._init_empty()


def test_delete_single_asset_success():
    res = client.delete("/api/assets/AST-TEST-01")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ASSET_DELETED"
    assert data["asset_id"] == "AST-TEST-01"
    assert data["total_active_assets"] == 1

    # Verify asset is removed from snapshot
    remaining_ids = [a["id"] for a in store.current_snapshot["assets"]]
    assert "AST-TEST-01" not in remaining_ids
    assert "AST-TEST-02" in remaining_ids

    # Verify associated finding was also purged
    remaining_findings = store.current_snapshot["findings"]
    assert len(remaining_findings) == 1
    assert remaining_findings[0]["asset_id"] == "AST-TEST-02"

    # Verify orphaned service was cleaned up
    remaining_services = [s["service_id"] for s in store.current_snapshot["services"]]
    assert "SVC-TEST-01" not in remaining_services
    assert "SVC-TEST-02" in remaining_services


def test_delete_single_asset_not_found():
    res = client.delete("/api/assets/NON-EXISTENT-ID")
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()


def test_clear_asset_inventory_delete_method():
    res = client.delete("/api/assets")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "INVENTORY_CLEARED"
    assert data["total_active_assets"] == 0
    assert data["assets_removed"] == 2

    assert len(store.current_snapshot["assets"]) == 0
    assert len(store.current_snapshot["findings"]) == 0
    assert len(store.current_snapshot["services"]) == 0

    # Summary should now return NO_DATA
    summary = store.get_summary()
    assert summary["status"] == "NO_DATA"


def test_clear_asset_inventory_post_alias():
    res = client.post("/api/assets/clear")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "INVENTORY_CLEARED"
    assert data["total_active_assets"] == 0


def test_update_single_asset_success():
    payload = {
        "name": "Updated Server 1 Name",
        "criticality": 4,
        "revenue_per_hour": 150000.0,
        "records_count": 80000,
        "internet_facing": False,
        "business_service_id": "SVC-TEST-UPDATED"
    }
    res = client.put("/api/assets/AST-TEST-01", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ASSET_UPDATED"
    assert data["asset"]["name"] == "Updated Server 1 Name"
    assert data["asset"]["criticality_1_5"] == 4
    assert data["asset"]["revenue_per_hour"] == 150000.0
    assert data["asset"]["records_count"] == 80000
    assert data["asset"]["internet_facing"] is False
    assert data["asset"]["business_service_id"] == "SVC-TEST-UPDATED"
    assert data["asset"]["has_business_context"] is True

    # Verify registered service
    service_ids = [s["service_id"] for s in store.current_snapshot["services"]]
    assert "SVC-TEST-UPDATED" in service_ids


def test_update_single_asset_validation():
    # Invalid criticality (> 5)
    res = client.put("/api/assets/AST-TEST-01", json={"criticality": 6})
    assert res.status_code == 400
    assert "criticality" in res.json()["detail"].lower()

    # Negative revenue
    res = client.put("/api/assets/AST-TEST-01", json={"revenue_per_hour": -50.0})
    assert res.status_code == 400
    assert "revenue" in res.json()["detail"].lower()

    # Negative records
    res = client.put("/api/assets/AST-TEST-01", json={"records_count": -10})
    assert res.status_code == 400
    assert "records" in res.json()["detail"].lower()


def test_update_single_asset_not_found():
    res = client.put("/api/assets/NON-EXISTENT", json={"name": "New Name"})
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()

