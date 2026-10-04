import json

import pytest

from app.connectors.generic import GenericVendorConnector
from app.connectors.sniffer import detect_structure, suggest_field_mapping
from test_audit_regressions import isolated_app


def parse_suggested(content, extension):
    inspection = detect_structure(content, extension)
    assert "error" not in inspection, inspection
    config = {"vendor_name": "Validation vendor", "vendor_slug": "validation_vendor",
              "format": inspection["format"], "record_path": inspection["detected_record_path"],
              "field_mapping": inspection["suggested_mapping"]}
    return inspection, GenericVendorConnector(config).parse(content), config


def openvas_refs_xml(namespace=""):
    return f'''<report{namespace}><results><result><host>192.0.2.1</host>
      <severity>9.8</severity><threat>High</threat><port>443/tcp</port>
      <nvt><name>TLS finding</name><cvss_base>9.8</cvss_base><refs>
        <ref type="url" id="https://example.org/advisory"/>
        <ref type="cve" id="CVE-2021-44228"/>
        <ref type="cve" id="CVE-2021-45046"/>
        <ref type="cve" id="CVE-2021-44228"/>
      </refs></nvt></result></results></report>'''.encode()


@pytest.mark.parametrize("namespace", ["", ' xmlns="urn:vendor:scanner"'])
def test_xml_refs_do_not_replace_finding_records(namespace):
    inspection, parsed, _ = parse_suggested(openvas_refs_xml(namespace), "xml")
    assert inspection["detected_record_path"] == "report.results.result"
    assert inspection["record_count_sample"] == 1
    assert inspection["suggested_mapping"] == {
        "asset_id": "host", "severity": "threat", "cve_id": "nvt.refs.ref.@id",
        "cvss": "nvt.cvss_base", "port": "port", "issue_type": "nvt.name"}
    assert parsed["skipped"] == 0
    assert {f["cve_id"] for f in parsed["findings"]} == {"CVE-2021-44228", "CVE-2021-45046"}
    assert all(f["asset_id"] == "192.0.2.1" and f["severity"] == "High"
               and f["port"] == 443 and f["cvss"] == 9.8 for f in parsed["findings"])
    assert len({f["id"] for f in parsed["findings"]}) == 2


def test_aliases_use_whole_names_and_sample_values():
    fields = ["Description", "Plugin ID", "Host IP", "CVSS v3 Base Score", "Risk Factor", "CVE", "Port"]
    mapping = suggest_field_mapping(fields)
    assert mapping["asset_id"] == "Host IP"
    assert mapping["cvss"] == "CVSS v3 Base Score"
    assert mapping["severity"] == "Risk Factor"
    assert suggest_field_mapping(["description", "subscription", "@id", "risk_score"])["asset_id"] == ""
    assert suggest_field_mapping(["vulnerabilityId"], [{"vulnerabilityId": "QID-123"}])["cve_id"] == ""
    assert suggest_field_mapping(["cvss"], [{"cvss": ""}, {"cvss": 9.8}])["cvss"] == "cvss"


def test_csv_bom_trimmed_headers_and_multiple_cves():
    content = ('\ufeff Description , Host IP , Risk Factor , CVE , CVSS v3 Base Score , Port\n'
               'Finding,192.0.2.2,High,"CVE-2021-44228; CVE-2021-45046",9.8,443\n').encode()
    inspection, parsed, _ = parse_suggested(content, "csv")
    assert inspection["record_count_sample"] == 1
    assert inspection["suggested_mapping"]["asset_id"] == "Host IP"
    assert parsed["skipped"] == 0
    assert len(parsed["findings"]) == 2
    assert {f["cve_id"] for f in parsed["findings"]} == {"CVE-2021-44228", "CVE-2021-45046"}


def test_nested_json_findings_beat_longer_metadata_array():
    content = json.dumps({"metadata": [{"id": i} for i in range(10)], "data": {"findings": [{
        "hostIp": "192.0.2.3", "severity": "High", "cvss3Score": 9.8,
        "vulnerability": {"cves": [{"id": "CVE-2021-44228"}, {"id": "CVE-2021-45046"}]},
    }]}}).encode()
    inspection = detect_structure(content, "json")
    assert inspection["detected_record_path"] == "data.findings"
    assert inspection["suggested_mapping"]["asset_id"] == "hostIp"
    assert inspection["suggested_mapping"]["cve_id"] == "vulnerability.cves.id"
    config = {"format": "json", "record_path": "data.findings", "field_mapping": {
        "asset_id": "hostIp", "severity": "severity", "cve_id": "vulnerability.cves.id"}}
    parsed = GenericVendorConnector(config).parse(content)
    assert {f["cve_id"] for f in parsed["findings"]} == {"CVE-2021-44228", "CVE-2021-45046"}


def test_configuration_scanner_and_zero_severity_are_valid():
    content = json.dumps([{"resourceArn": "arn:example:resource", "severity": 0,
                           "checkId": "storage_configuration"}]).encode()
    inspection, parsed, _ = parse_suggested(content, "json")
    assert not inspection["suggested_mapping"]["cve_id"]
    assert inspection["suggested_mapping"]["issue_type"] == "checkId"
    assert parsed["skipped"] == 0
    assert parsed["findings"][0]["severity"] == "Info"
    assert parsed["findings"][0]["cve_id"] is None


def test_inspect_preview_save_and_ingest_use_same_mapping(isolated_app):
    client = isolated_app
    content = openvas_refs_xml()
    files = {"file": ("sample.xml", content, "application/xml")}
    inspection = client.post("/api/vendors/inspect", files=files)
    assert inspection.status_code == 200, inspection.text
    metadata = inspection.json()
    preview = client.post("/api/vendors/preview", files=files, data={
        "format": metadata["format"], "record_path": metadata["detected_record_path"],
        "field_mapping": json.dumps(metadata["suggested_mapping"])})
    assert preview.status_code == 200, preview.text
    assert preview.json()["total_extracted"] == 2
    assert preview.json()["total_skipped"] == 0
    saved = client.post("/api/vendors/save", json={
        "vendor_name": "Validation vendor", "format": metadata["format"],
        "record_path": metadata["detected_record_path"],
        "field_mapping": metadata["suggested_mapping"], "sample_file_used": "sample.xml"})
    assert saved.status_code == 200, saved.text
    slug = saved.json()["config"]["vendor_slug"]
    inventory = b"Asset ID,Name,Service,Criticality (1-5),Records,RevenuePerHour\n192.0.2.1,Validation asset,VALIDATION,3,0,0\n"
    response = client.post("/api/ingest/assets", files={"file": ("inventory.csv", inventory, "text/csv")})
    assert response.status_code == 200, response.text
    uploaded = client.post(f"/api/ingest/vendor/{slug}", files=files)
    assert uploaded.status_code == 200, uploaded.text
    snapshot = client.get("/api/data/snapshot").json()
    assert {f["cve_id"] for f in snapshot["findings"]} == {"CVE-2021-44228", "CVE-2021-45046"}


def test_empty_or_unmappable_files_do_not_invent_fields():
    assert "error" in detect_structure(b"", "xml")
    result = detect_structure(b"description,subscription\nTest,Account\n", "csv")
    assert result["suggested_mapping"]["asset_id"] == ""
    assert result["suggested_mapping"]["severity"] == ""
