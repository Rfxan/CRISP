import pytest
import io
from pathlib import Path
from fastapi.testclient import TestClient
from app.main import app
from app.api.routes import store
from app.connectors.defender import DefenderEDRConnector, DEFENDER_SEVERITY_MAP
from app.connectors.format_detector import detect_scan_format
from app.engine.fair_engine import SEVERITY_EXPLOITABILITY_PRIORS

SAMPLE_CSV = Path(__file__).resolve().parent.parent / "app" / "data" / "SYNTHETIC_defender_advanced_hunting.csv"
SAMPLE_JSON = Path(__file__).resolve().parent.parent / "app" / "data" / "SYNTHETIC_defender_advanced_hunting.json"


@pytest.fixture
def client():
    return TestClient(app)


def test_format_detector_for_defender():
    """Verify auto-detection identifies Defender CSV and JSON from file structure."""
    csv_bytes = SAMPLE_CSV.read_bytes()
    json_bytes = SAMPLE_JSON.read_bytes()

    assert detect_scan_format(csv_bytes, "SYNTHETIC_defender_advanced_hunting.csv") == "defender_edr"
    assert detect_scan_format(json_bytes, "SYNTHETIC_defender_advanced_hunting.json") == "defender_edr"
    # Even if named generic.csv or generic.json
    assert detect_scan_format(csv_bytes, "report.csv") == "defender_edr"
    assert detect_scan_format(json_bytes, "export.json") == "defender_edr"


def test_defender_csv_parsing():
    """Verify deterministic field mapping from Defender CSV."""
    connector = DefenderEDRConnector()
    csv_bytes = SAMPLE_CSV.read_bytes()
    result = connector.parse(csv_bytes, filename="SYNTHETIC_defender_advanced_hunting.csv")

    findings = result["findings"]
    assert len(findings) == 5
    assert result["skipped"] == 0

    # First finding check: High severity, PowerShell, MITRE T1059.001
    f1 = findings[0]
    assert f1["asset_id"] == "AST-PAY-GW-01"
    assert f1["severity"] == "High"
    assert f1["cve_id"] is None, "EDR detections must NOT have CVE IDs"
    assert "dae-9412" in f1["issue_type"]
    assert "T1059.001" in f1["mitre_techniques"]
    assert f1["source"] == "Microsoft Defender for Endpoint"

    # Second finding check: Critical severity, Credential Dumping, multiple MITRE techniques
    f2 = findings[1]
    assert f2["severity"] == "Critical"
    assert "T1003" in f2["mitre_techniques"]
    assert "T1003.001" in f2["mitre_techniques"]

    # Fifth finding check: Informational -> Info
    f5 = findings[4]
    assert f5["severity"] == "Info"


def test_defender_json_parsing():
    """Verify deterministic field mapping from Defender JSON."""
    connector = DefenderEDRConnector()
    json_bytes = SAMPLE_JSON.read_bytes()
    result = connector.parse(json_bytes, filename="SYNTHETIC_defender_advanced_hunting.json")

    findings = result["findings"]
    assert len(findings) == 5
    assert all(f["source"] == "Microsoft Defender for Endpoint" for f in findings)
    assert all(f["cve_id"] is None for f in findings)


def test_loud_failure_on_unmapped_severity():
    """
    CRITICAL: If Defender severity can't be mapped, fail LOUDLY with the unmapped value in the error.
    """
    connector = DefenderEDRConnector()
    bad_csv = (
        "Timestamp,DeviceId,DeviceName,AlertId,Title,Severity,Category\n"
        "2026-09-29T10:00:00Z,dev-1,AST-01,dae-01,Test Alert,Catastrophic,Execution\n"
    ).encode("utf-8")

    with pytest.raises(ValueError) as excinfo:
        connector.parse(bad_csv, "bad.csv")

    assert "Catastrophic" in str(excinfo.value), "Error must surface the exact unmapped severity value"
    assert "Unmapped Microsoft Defender severity" in str(excinfo.value)


def test_api_upload_existing_ingestion_endpoint(client):
    """
    Acceptance: upload the sample via the existing ingestion endpoint (/api/ingest/scan);
    detections appear in findings, flow into EAL, and are labeled by source.
    """
    # 1. Provide an asset with declared business context so EAL can compute
    store.current_snapshot["assets"] = [
        {
            "id": "AST-PAY-GW-01",
            "name": "Payment Gateway",
            "criticality_1_5": 5,
            "revenue_per_hour": 500000.0,
            "records_count": 100000,
            "business_service_id": "SRV-PAY"
        },
        {
            "id": "AST-CORE-DB-01",
            "name": "Core Banking DB",
            "criticality_1_5": 5,
            "revenue_per_hour": 800000.0,
            "records_count": 300000,
            "business_service_id": "SRV-CORE"
        }
    ]
    store.current_snapshot["findings"] = []

    # 2. Upload sample CSV to /api/ingest/scan (the existing unified ingestion endpoint)
    csv_bytes = SAMPLE_CSV.read_bytes()
    resp = client.post(
        "/api/ingest/scan",
        files={"file": ("SYNTHETIC_defender_advanced_hunting.csv", io.BytesIO(csv_bytes), "text/csv")}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "INGESTED"
    assert data["format"] == "defender_edr"
    assert data["parsed"] == 5
    assert data["new_eal"] is not None
    assert data["new_eal"] > 0

    # 3. Verify detections appear in findings and are labeled by source
    findings = store.current_snapshot["findings"]
    edr_findings = [f for f in findings if f.get("source") == "Microsoft Defender for Endpoint"]
    assert len(edr_findings) == 5

    # 4. Verify loud failure through the API returns HTTP 400 with unmapped severity
    bad_csv = (
        "Timestamp,DeviceId,DeviceName,AlertId,Title,Severity,Category\n"
        "2026-09-29T10:00:00Z,dev-1,AST-01,dae-01,Test Alert,UltraSevere,Execution\n"
    ).encode("utf-8")
    err_resp = client.post(
        "/api/ingest/scan",
        files={"file": ("bad_edr.csv", io.BytesIO(bad_csv), "text/csv")}
    )
    assert err_resp.status_code == 400
    assert "UltraSevere" in err_resp.json()["detail"]


def test_fair_engine_edr_exploitability_scale():
    """
    Verify EDR detections flow into FAIR engine with agreed exploitability assumptions:
    Critical 0.6 / High 0.4 / Medium 0.2 / Low 0.05.
    """
    assert SEVERITY_EXPLOITABILITY_PRIORS["Critical"] == 0.60
    assert SEVERITY_EXPLOITABILITY_PRIORS["High"] == 0.40
    assert SEVERITY_EXPLOITABILITY_PRIORS["Medium"] == 0.20
    assert SEVERITY_EXPLOITABILITY_PRIORS["Low"] == 0.05
    assert SEVERITY_EXPLOITABILITY_PRIORS["Info"] == 0.01
