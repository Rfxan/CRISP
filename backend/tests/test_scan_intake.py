import threading
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.main import app
from app.api.routes import store


SCAN = b'IP,CVEs,CVSS,Severity,NVT Name,Port\n192.0.2.1,CVE-2021-44228,10,Critical,Imported finding,443\n'


def test_csv_import_saves_evidence_without_external_feed_requests(monkeypatch):
    monkeypatch.setenv("CRISP_ENV", "development")
    monkeypatch.setenv("CRISP_TESTING", "1")
    store._init_empty()
    with patch("requests.get", side_effect=AssertionError("Import must not wait for external feeds")) as outbound:
        response = TestClient(app).post("/api/ingest/scan", files={"file": ("report.csv", SCAN, "text/csv")})
    assert response.status_code == 200
    assert response.json()["parsed"] == 1
    assert response.json()["new_eal"] is None
    outbound.assert_not_called()
    assert len(store.current_snapshot["assets"]) == 1
    finding = store.current_snapshot["findings"][0]
    assert finding["in_kev"] is None
    assert finding["threat_intel_provenance"]["epss"]["status"] == "pending"
    assert finding["cvss"] == 10


def test_scan_processing_does_not_block_health_endpoint(monkeypatch):
    monkeypatch.setenv("CRISP_ENV", "development")
    monkeypatch.setenv("CRISP_TESTING", "1")
    store._init_empty()
    entered = threading.Event()
    release = threading.Event()
    results = []

    def pause_processing(*args, **kwargs):
        entered.set()
        assert release.wait(timeout=5)

    with TestClient(app) as client, patch.object(store._target(), "enrich_findings_intel", side_effect=pause_processing):
        upload = threading.Thread(target=lambda: results.append(client.post("/api/ingest/scan", files={"file": ("report.csv", SCAN)})))
        upload.start()
        try:
            assert entered.wait(timeout=3)
            assert client.get("/api/health").status_code == 200
        finally:
            release.set()
            upload.join(timeout=5)
    assert results[0].status_code == 200
