import os
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.compliance.framework_engine import FrameworkEngine, normalize_framework_id, FRAMEWORK_ALIASES
from app.compliance.framework_registry import FRAMEWORK_REQUIREMENTS
from app.compliance.catalog import FRAMEWORKS

client = TestClient(app)

def test_compliance_coverage_doc_exists_and_accurate():
    """Verify docs/COMPLIANCE_COVERAGE.md exists and contains coverage tables for all frameworks."""
    doc_path = os.path.join(os.path.dirname(__file__), "..", "..", "docs", "COMPLIANCE_COVERAGE.md")
    assert os.path.exists(doc_path), f"Coverage documentation not found at {doc_path}"
    
    with open(doc_path, "r", encoding="utf-8") as f:
        content = f.read()
    
    assert len(content) > 1000
    for fw in ["SEBI CSCRF", "RBI Cyber Security Framework", "NIST CSF 2.0", "ISO/IEC 27001:2022", "CIS Controls v8"]:
        assert fw in content, f"Framework '{fw}' missing from COMPLIANCE_COVERAGE.md"
    
    # Check that computed percentages are present
    fe = FrameworkEngine()
    for fw_key in ["sebi", "rbi", "nist", "iso", "cis"]:
        res = fe.evaluate_framework(fw_key, [])
        pct_str = f"{res['mapping_coverage_pct']}%"
        assert pct_str in content, f"Calculated coverage {pct_str} for {fw_key} not in coverage doc"


def test_framework_alias_normalization_and_loud_failure():
    """Verify alias lookup resolves canonical keys, and unknown framework IDs fail loudly with ValueError."""
    # Test valid aliases
    assert normalize_framework_id("sebi_cscrf") == "sebi"
    assert normalize_framework_id("SEBICscRF") == "sebi"
    assert normalize_framework_id("rbi_csf") == "rbi"
    assert normalize_framework_id("iso27001") == "iso"
    assert normalize_framework_id("nist_csf") == "nist"
    assert normalize_framework_id("cis_v8") == "cis"
    
    # Test loud failure on unknown ID
    unknown_ids = ["hipaa", "pci_dss_v4", "sox_404", "nonexistent_framework"]
    for uid in unknown_ids:
        with pytest.raises(ValueError) as exc_info:
            normalize_framework_id(uid)
        err_msg = str(exc_info.value)
        assert f"Unknown framework '{uid}'" in err_msg
        assert "Valid IDs:" in err_msg


def test_dynamic_percentages_computation_no_false_100():
    """
    Ensure percentages are computed dynamically from requirements registry,
    and no framework falsely claims 100% when out-of-scope clauses exist.
    """
    fe = FrameworkEngine()
    framework_keys = ["sebi", "rbi", "nist", "iso", "cis", "dpdp"]
    
    for fw_key in framework_keys:
        res = fe.evaluate_framework(fw_key, [])
        reqs = FRAMEWORK_REQUIREMENTS.get(fw_key, [])
        assert len(reqs) > 0, f"No requirements registered for {fw_key}"
        
        mapped_count = len([r for r in reqs if r.get("mapped_control_id")])
        unmapped_count = len([r for r in reqs if not r.get("mapped_control_id")])
        expected_pct = round((mapped_count / len(reqs)) * 100.0, 1)
        
        # Verify dynamic calculation matches
        assert res["total_framework_requirements"] == len(reqs)
        assert res["mapped_requirements_count"] == mapped_count
        assert res["unmapped_requirements_count"] == unmapped_count
        assert res["mapping_coverage_pct"] == expected_pct
        
        # Assert NO framework claims 100% unless genuinely 100%
        if unmapped_count > 0:
            assert res["mapping_coverage_pct"] < 100.0, f"{fw_key} claims 100% despite {unmapped_count} unmapped requirements!"
            
        # Verify all unmapped requirements have explicit rationale
        for unmapped in res["unmapped_requirements"]:
            assert unmapped.get("unmapped_reason"), f"Unmapped req {unmapped['id']} missing unmapped_reason"
            assert len(unmapped["unmapped_reason"]) > 10


def test_compliance_summary_api_endpoint():
    """Test GET /api/compliance/summary returns accurate computed coverage across all frameworks."""
    res = client.get("/api/compliance/summary")
    assert res.status_code == 200
    data = res.json()
    
    assert "sebi" in data
    assert "rbi" in data
    assert "nist" in data
    assert "iso" in data
    assert "cis" in data
    
    sebi = data["sebi"]
    assert sebi["mapping_coverage_pct"] == 84.0
    assert sebi["unmapped_requirements_count"] == 4
    assert sebi["total_framework_requirements"] == 25
    assert sebi["mapped_requirements_count"] == 21
    
    rbi = data["rbi"]
    assert rbi["mapping_coverage_pct"] == 80.0
    assert rbi["unmapped_requirements_count"] == 4
    assert rbi["total_framework_requirements"] == 20
    assert rbi["mapped_requirements_count"] == 16


def test_closed_gaps_rbi_and_sebi():
    """Verify RBI and SEBI gaps have been closed with correct control IDs and authoritative clauses."""
    fe = FrameworkEngine()
    
    sebi_res = fe.evaluate_framework("sebi", [])
    sebi_control_ids = {c["control_id"] for c in sebi_res["controls"]}
    
    # Assert newly added gap-closing controls are mapped
    assert "CTRL-HARD-01" in sebi_control_ids
    assert "CTRL-TPRM-01" in sebi_control_ids
    assert "CTRL-VAPT-01" in sebi_control_ids
    assert "CTRL-ANOM-01" in sebi_control_ids
    
    # Verify authoritative framework clauses are populated
    for c in sebi_res["controls"]:
        clause = c.get("framework_clause")
        assert clause is not None and len(clause) > 0
        assert any(k in clause for k in ["Cl.", "Section", "Part", "Annex"]), f"Invalid clause citation: {clause}"


def test_sebi_cscrf_evidence_report_never_invents_data():
    from app.compliance.evidence_report import EvidenceReportGenerator
    report = EvidenceReportGenerator.build_structured_report('sebi', {})
    assert report['summary_metrics']['total_requirements'] == 25
    assert report['organization']['total_assets'] == 0
    assert report['audit_run']['run_id'] is None
    assert report['summary_metrics']['evidence_completeness_pct'] == 0
    for row in report['requirements']:
        assert row['control_coverage_pct'] is None
        assert row['supporting_finding_ids'] == []
        assert row['coverage_status'].startswith('NO EVIDENCE')


def test_evidence_report_csv_and_html_exports():
    """Verify CSV export (RFC 4180) and printable HTML export (with print stylesheet)."""
    # 1. CSV via query param
    res_csv = client.get("/api/compliance/sebi/evidence-report?format=csv")
    assert res_csv.status_code == 200
    assert "text/csv" in res_csv.headers["content-type"]
    assert "attachment" in res_csv.headers.get("content-disposition", "")
    csv_text = res_csv.text
    assert "# CRISP Continuous Compliance Audit Evidence Report" in csv_text
    assert "SEBI CSCRF" in csv_text
    assert "NO EVIDENCE — unmapped" in csv_text
    assert "None%" not in csv_text
    assert "Applicability" in csv_text
    
    # 2. CSV via dedicated path
    res_csv_path = client.get("/api/compliance/sebi/evidence-report/csv")
    assert res_csv_path.status_code == 200
    assert "text/csv" in res_csv_path.headers["content-type"]
    
    # 3. HTML via query param
    res_html = client.get("/api/compliance/sebi/evidence-report?format=html")
    assert res_html.status_code == 200
    assert "text/html" in res_html.headers["content-type"]
    html_text = res_html.text
    assert "<!DOCTYPE html>" in html_text
    assert "Audit Evidence Traceability Report" in html_text
    assert "@media print" in html_text
    assert "window.print()" in html_text
    assert "badge-unmapped" in html_text
    assert "NO EVIDENCE — unmapped" in html_text
    
    # 4. Backward-compatible /api/report/{framework}
    res_rep = client.get("/api/report/sebi")
    assert res_rep.status_code == 200
    assert "text/html" in res_rep.headers["content-type"]
    assert "Audit Evidence Traceability Report" in res_rep.text

