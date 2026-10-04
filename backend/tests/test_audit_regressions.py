import copy
import threading
import time
from unittest.mock import patch
import numpy as np
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from app.engine.loss_metrics import expected_shortfall, exceedance_curve
from app.core.inventory import normalize_inventory
from app.api.routes import SnapshotStore


def test_zero_inflated_tail_and_strict_exceedance():
    losses = [0.] * 960 + [1000.] * 40
    assert np.percentile(losses, 95) == 0
    assert expected_shortfall(losses) == pytest.approx(800)
    assert exceedance_curve(losses) == [[0., .04], [1000., 0.]]


def test_fractional_tail_and_constant_losses():
    assert expected_shortfall([0, 10, 100], .5) == pytest.approx(70)
    assert expected_shortfall([7]*17) == pytest.approx(7)
    assert exceedance_curve([0]*10) == [[0., 0.]]
    curve = exceedance_curve(np.arange(1000)/3)
    assert len(curve) <= 100
    assert len({x for x, _ in curve}) == len(curve)
    assert all(p == pytest.approx(np.mean(np.arange(1000)/3 > x)) for x, p in curve)


def test_service_migration_preserves_financial_context():
    snapshot = {"services": [{"id": "S", "name": "Payments", "revenue_per_hour": 4000},
                              {"service_id": "S", "name": "S", "revenue_per_hour": 0}],
                "assets": [{"id": "A", "is_real_lab_asset": True}]}
    normalize_inventory(snapshot)
    assert snapshot["services"] == [{"id": "S", "service_id": "S", "name": "Payments", "revenue_per_hour": 4000}]
    assert snapshot["assets"][0]["origin"] == "unknown"
    assert snapshot["assets"][0]["is_real_lab_asset"] is False


@pytest.fixture
def isolated_app(monkeypatch, tmp_path):
    for name in ("RENDER", "VERCEL", "CRISP_DATABASE_URL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CRISP_ENV", "production")
    monkeypatch.setenv("CRISP_ACCESS_MODE", "public_sandbox")
    monkeypatch.setenv("CRISP_TESTING", "0")
    monkeypatch.setenv("CRISP_DATABASE_PATH", str(tmp_path / "audit.sqlite3"))
    monkeypatch.setenv("CRISP_ENCRYPTION_KEY", Fernet.generate_key().decode())
    for quota in ("CRISP_RATE_PEER", "CRISP_RATE_GLOBAL", "CRISP_RATE_COMPUTE_PEER", "CRISP_RATE_COMPUTE_GLOBAL"):
        monkeypatch.setenv(quota, "10000")
    from app.main import app
    # No lifespan here: production checks require a real hosted DB at startup.
    return TestClient(app, base_url="https://testserver")


def test_seed_inventory_csv_and_asset_crud_preserve_services(isolated_app):
    c = isolated_app
    assert c.post("/api/data/seed").status_code == 200
    before = c.get("/api/data/snapshot").json()
    before_eal = c.get("/api/risk/summary").json()["org"]["eal"]
    sid = before["services"][0]["id"]
    asset = {"id": "TEMP", "name": "Temporary", "business_service_id": sid,
             "criticality_1_5": 3, "records_count": 0, "revenue_per_hour": 0}
    assert c.post("/api/assets/add", json=asset).status_code == 200
    assert c.put("/api/assets/TEMP", json={"business_service_id": sid}).status_code == 200
    assert c.delete("/api/assets/TEMP").status_code == 200
    after = c.get("/api/data/snapshot").json()
    assert before["services"] == after["services"]
    assert c.get("/api/risk/summary").json()["org"]["eal"] == before_eal
    csv = f'Asset ID,Name,Service,Criticality (1-5),Records,RevenuePerHour\nTEMP,Imported,{sid},3,0,0\n'.encode()
    response = c.post("/api/ingest/assets", files={"file": ("inventory.csv", csv)})
    assert response.status_code == 200, response.text
    assert c.get("/api/data/snapshot").json()["services"] == before["services"]


def test_risk_summary_exposes_linked_service_results(isolated_app):
    c = isolated_app
    assert c.get("/api/risk/summary").json().get("services", []) == []
    asset = {"id": "LOGSRV", "name": "Log server", "business_service_id": "SVC-NETBANK",
             "criticality_1_5": 4, "records_count": 600, "revenue_per_hour": 100000}
    added = c.post("/api/assets/add", json=asset)
    assert added.status_code == 200, added.text
    scan = b'IP,CVEs,CVSS,Severity,NVT Name,Port\nLOGSRV,,4.0,Medium,TLS configuration,9200\n'
    imported = c.post("/api/ingest/scan", files={"file": ("report.csv", scan, "text/csv")})
    assert imported.status_code == 200, imported.text
    response = c.get("/api/risk/summary")
    assert response.status_code == 200, response.text
    summary = response.json()
    entities = c.get("/api/risk/entities?level=service").json()["entities"]
    assert summary["services"] == entities
    assert len(summary["services"]) == 1
    service = summary["services"][0]
    assert service["service_id"] == "SVC-NETBANK"
    assert service["rto_hours"] == 4.0
    assert service["eal"] == summary["org"]["eal"]
    assert service["var95"] == summary["org"]["var95"]
    assert service["eal"] > 0
    assert service["revenue_per_hour"] == 0  # Separately declared service revenue.
    assert service["linked_asset_revenue_per_hour"] == 100000
    assert service["revenue_exposure_per_hour"] == 100000
    snapshot = c.get("/api/data/snapshot").json()
    assert snapshot["services"][0].get("revenue_per_hour", 0) == 0
    edited = c.put("/api/assets/LOGSRV", json={"revenue_per_hour": 200000})
    assert edited.status_code == 200, edited.text
    updated = c.get("/api/risk/summary").json()["services"][0]
    assert updated["linked_asset_revenue_per_hour"] == 200000
    assert updated["revenue_exposure_per_hour"] == 200000
    assert updated["revenue_per_hour"] == 0
    cleared = c.delete("/api/assets")
    assert cleared.status_code == 200, cleared.text
    assert c.get("/api/risk/summary").json()["services"] == []


def test_persisted_summary_is_refreshed_when_result_schema_changes(monkeypatch):
    from app.api import routes
    from app.core.state_proxy import export_state, import_state
    local = SnapshotStore()
    local.engine.trials = 1000
    local.current_snapshot['assets'] = [{'id': 'LOGSRV', 'name': 'Log server',
        'business_service_id': 'SVC-NETBANK', 'criticality_1_5': 4,
        'records_count': 600, 'revenue_per_hour': 100000}]
    local.current_snapshot['services'] = [{'service_id': 'SVC-NETBANK',
        'name': 'Netbank', 'rto_hours': 4}]
    local.current_snapshot['assessment_state'] = {'status': 'completed'}
    monkeypatch.setattr(routes, 'RESULT_SCHEMA_VERSION', 1, raising=False)
    old = local.get_summary()
    financial_totals = copy.deepcopy(old['org'])
    for service in old['services']:
        service.pop('linked_asset_revenue_per_hour', None)
        service.pop('revenue_exposure_per_hour', None)
    persisted = copy.deepcopy(export_state(local))
    restored = SnapshotStore()
    restored.engine.trials = 1000
    import_state(restored, persisted)
    inputs = copy.deepcopy(restored.current_snapshot)
    monkeypatch.setattr(routes, 'RESULT_SCHEMA_VERSION', 2)
    refreshed = restored.get_summary()
    assert refreshed['services'][0]['revenue_exposure_per_hour'] == 100000
    assert refreshed['org'] == financial_totals
    assert restored.current_snapshot == inputs
    assert restored.last_state_signature != persisted['last_state_signature']
    assert restored.get_summary() is refreshed  # No repeated recomputation.


def test_feed_failure_is_not_fresh_success():
    local = SnapshotStore()
    local.current_snapshot["findings"] = [{"id": "F", "asset_id": "A", "cve_id": "CVE-2021-44228"}]
    degraded = {"epss": None, "in_kev": None, "provenance": {k: {"status": "unavailable"} for k in ("epss", "nvd", "kev")}}
    with patch.object(local.threat_intel, "fetch_cisa_kev", return_value={"status": "unavailable"}), \
         patch.object(local.threat_intel, "enrich_cve", return_value=degraded):
        result = local.sync_live_threat_intel()
    assert result["status"] == "FAILED"
    assert result["sync_record"]["status"] == "error"
    assert result["feeds"]["epss"]["unavailable"] == 1


def test_copilot_reporting_answers_follow_saved_exercises_without_financial_data(isolated_app):
    from datetime import datetime, timedelta, timezone
    c = isolated_app
    question = {'question': 'Are we compliant with SEBI 6-hour reporting?'}
    with patch('app.ai.decision_support.llm_config_store.get_config', return_value={'enabled': False}), \
         patch.object(SnapshotStore, 'get_optimizer', side_effect=AssertionError('Reporting must not invoke investment optimization')):
        response = c.post('/api/ask', json=question)
        assert response.status_code == 200, response.text
        assert 'NOT VERIFIED' in response.json()['answer']
        assert response.json()['tool_used'] == 'reporting_readiness'
        incident = datetime.now(timezone.utc) - timedelta(hours=12)
        exercise = {'id': 'exercise-1', 'incident_at': incident.isoformat(),
                    'detected_at': (incident + timedelta(minutes=10)).isoformat(),
                    'escalated_at': (incident + timedelta(minutes=20)).isoformat(),
                    'reported_at': (incident + timedelta(hours=3)).isoformat(),
                    'evidence_ref': 'Recorded drill evidence'}
        saved = c.post('/api/governance/exercises', json=exercise)
        assert saved.status_code == 200, saved.text
        assert 'READY' in c.post('/api/ask', json=question).json()['answer']
        exercise['reported_at'] = (incident + timedelta(hours=8)).isoformat()
        assert c.post('/api/governance/exercises', json=exercise).status_code == 200
        answer = c.post('/api/ask', json=question).json()['answer']
        assert 'AT RISK' in answer
        assert 'Expected annual loss' not in answer


def test_copilot_var_explanation_uses_current_assessment_without_optimizer(isolated_app):
    from app.ai.decision_support import _format_inr
    c = isolated_app
    question = {'question': 'Explain our Value at Risk (VaR 95) for the Board of Directors'}
    with patch('app.ai.decision_support.llm_config_store.get_config', return_value={'enabled': False}), \
         patch.object(SnapshotStore, 'get_optimizer', side_effect=AssertionError('VaR explanation must not invoke investment optimization')):
        empty = c.post('/api/ask', json=question)
        assert empty.status_code == 200, empty.text
        assert 'unknown' in empty.json()['answer'].lower()
        asset = {'id': 'VAR-HOST', 'name': 'Board assessment host', 'business_service_id': 'SVC-NETBANK',
                 'criticality_1_5': 4, 'records_count': 600, 'revenue_per_hour': 100000}
        assert c.post('/api/assets/add', json=asset).status_code == 200
        scan = b'IP,CVEs,CVSS,Severity,NVT Name,Port\nVAR-HOST,,4.0,Medium,TLS configuration,9200\n'
        assert c.post('/api/ingest/scan', files={'file': ('report.csv', scan, 'text/csv')}).status_code == 200
        summary = c.get('/api/risk/summary').json()
        response = c.post('/api/ask', json=question)
        assert response.status_code == 200, response.text
        result = response.json()
        assert result['tool_used'] == 'var95_explanation'
        assert result['run_id'] == summary['run_id']
        assert _format_inr(summary['org']['var95']) in result['answer']
        assert '95%' in result['answer'] and 'maximum' in result['answer']
        assert next(f for f in result['claims'] if f['metric_id'] == 'org.var95')['value'] == summary['org']['var95']


def test_scan_merge_retains_distinct_non_cve_findings_and_unique_ids():
    from app.connectors.openvas import OpenVASConnector
    local = SnapshotStore()
    local.current_snapshot["findings"] = [
        {"id": "FND-OV-001", "asset_id": "192.0.2.1", "cve_id": "CVE-2021-44228", "port": 443, "source": "OpenVAS Scanner"},
        {"id": "FND-OV-004", "asset_id": "192.0.2.1", "cve_id": None, "port": 443, "name": "Missing header", "source": "OpenVAS Scanner"},
    ]
    xml = b'''<report><result><host>192.0.2.1</host><port>443/tcp</port>
        <nvt><name>Package</name><cve>CVE-2021-44228,CVE-2021-45046</cve></nvt></result>
        <result><host>192.0.2.1</host><port>443/tcp</port><nvt><name>Missing header</name></nvt></result>
        <result><host>192.0.2.1</host><port>443/tcp</port><nvt><name>Weak TLS</name></nvt></result></report>'''
    for _ in range(2):
        rows = OpenVASConnector().parse(xml, "scan.xml", len(local.current_snapshot["findings"]))["findings"]
        local.merge_findings(rows)
        findings = local.current_snapshot["findings"]
        assert len(findings) == 4
        assert len({f["id"] for f in findings}) == 4
        assert {f["name"] for f in findings if not f.get("cve_id")} == {"Missing header", "Weak TLS"}
        assert next(f for f in findings if f.get("cve_id") == "CVE-2021-44228")["id"] == "FND-OV-001"
        assert next(f for f in findings if f.get("name") == "Missing header")["id"] == "FND-OV-004"


def test_saved_failed_connection_is_retried_and_last_success_is_preserved():
    from app.api import routes
    from app.core.state_proxy import bound_store
    from app.core.tenancy import document_buffer
    from fastapi import HTTPException
    local = SnapshotStore()
    local.current_snapshot["wazuh_telemetry"] = {"status": "ok", "active_agents": 1, "last_sync": "2026-10-01T00:00:00Z"}
    token = bound_store.set(local)
    buffer = document_buffer.set({"sync_state": {}})
    conn = {"base_url": "https://example.org", "username": "audit", "password": "audit-only", "connected": False}
    try:
        with patch.object(routes.connections_store, "get_connection", return_value=conn), \
             patch.object(routes.connections_store, "record_connection_result") as recorded, \
             patch.object(routes.WazuhConnector, "fetch_agent_status", side_effect=ConnectionError("Authentication failed")) as fetch:
            with pytest.raises(HTTPException) as error:
                routes.sync_wazuh_telemetry()
            assert error.value.status_code == 502
            fetch.assert_called_once()
            assert recorded.call_args.args[1] is False
            telemetry = local.current_snapshot["wazuh_telemetry"]
            assert telemetry["status"] == "error"
            assert telemetry["last_sync"] == "2026-10-01T00:00:00Z"
            assert telemetry["last_successful"]["active_agents"] == 1
    finally:
        document_buffer.reset(buffer)
        bound_store.reset(token)


@pytest.mark.parametrize("initial_cursor", [{}, None])
def test_intel_batches_continue_instead_of_repeating_first_cves(initial_cursor):
    from app.core.tenancy import document_buffer
    local = SnapshotStore()
    local.current_snapshot["findings"] = [{"id": f"F{i}", "asset_id": "A", "cve_id": f"CVE-2024-{1000+i}"} for i in range(30)]
    intel = {"epss": .1, "in_kev": False, "provenance": {k: {"status": "live"} for k in ("epss", "nvd", "kev")}}
    token = document_buffer.set({"sync_state": {}, "intel_cursor": initial_cursor})
    try:
        with patch.object(local.threat_intel, "fetch_cisa_kev", return_value={"status": "live"}), \
             patch.object(local.threat_intel, "enrich_cve", return_value=intel) as enrich:
            first = local.sync_live_threat_intel()
            second = local.sync_live_threat_intel()
        assert first["cves_queried"] == 25 and first["cves_pending"] == 5
        assert first["status"] == "DEGRADED"
        assert second["cves_queried"] == 5 and second["cves_pending"] == 0
        assert second["status"] == "SYNCED"
        assert len({call.args[0] for call in enrich.call_args_list}) == 30
    finally:
        document_buffer.reset(token)


@pytest.mark.parametrize("kind", ["intel", "all"])
def test_first_background_intel_sync_initializes_cursor(isolated_app, kind):
    from app.connectors.threat_intel import ThreatIntelFeed
    c = isolated_app
    with patch.object(ThreatIntelFeed, "fetch_cisa_kev", return_value={"status": "live", "count": 1}):
        # Use the actual detached worker and enrichment method: a fresh workspace
        # has no stored intel_cursor, unlike an already initialized batch.
        for _ in range(2):
            response = c.post(f"/api/sync/jobs?kind={kind}")
            assert response.status_code == 202, response.text
            job_id = response.json()["id"]
            for _ in range(100):
                result = c.get(f"/api/sync/jobs/{job_id}").json()
                if result["status"] not in ("QUEUED", "RUNNING"):
                    break
                time.sleep(.05)
            assert result["status"] == "COMPLETED", result
            if kind == "all":
                assert result["job_results"]["threat_intel"] == "SYNCED"
            else:
                assert result["result"]["cves_queried"] == 0
            state = c.get("/api/sync/state").json()["sync_state"]
            assert state["threat_intel"]["status"] == "ok"


def test_multi_cve_upload_and_overview_sync_cover_every_reference(isolated_app):
    from app.connectors.threat_intel import ThreatIntelFeed
    c = isolated_app
    cves = {f"CVE-2024-{1000+i}" for i in range(46)}
    xml = ('<report><result><host>192.0.2.1</host><port>443/tcp</port><nvt><name>Package</name><cve>'
           + ','.join(sorted(cves)) + '</cve><cvss_base>7.5</cvss_base></nvt></result></report>').encode()
    with patch("requests.get", side_effect=AssertionError("Upload must not query external feeds")):
        for _ in range(2):
            response = c.post("/api/ingest/scan", files={"file": ("multi-cve.xml", xml)})
            assert response.status_code == 200, response.text
            assert response.json()["total_active_findings"] == 46
    snapshot = c.get("/api/data/snapshot").json()
    assert {f["cve_id"] for f in snapshot["findings"]} == cves
    assert len({f["id"] for f in snapshot["findings"]}) == 46
    intel = {"epss": .1, "in_kev": False, "provenance": {k: {"status": "live"} for k in ("epss", "nvd", "kev")}}
    with patch.object(ThreatIntelFeed, "fetch_cisa_kev", return_value={"status": "live", "count": 1}), \
         patch.object(ThreatIntelFeed, "enrich_cve", return_value=intel) as enrich:
        for queried, pending in ((25, 21), (21, 0)):
            response = c.post("/api/sync/jobs?kind=all")
            assert response.status_code == 202, response.text
            for _ in range(100):
                job = c.get(f'/api/sync/jobs/{response.json()["id"]}').json()
                if job["status"] not in ("QUEUED", "RUNNING"):
                    break
                time.sleep(.05)
            assert job["status"] == ("DEGRADED" if pending else "COMPLETED"), job
            summary = job["result"]["threat_intel"]
            assert summary["total_cves"] == 46
            assert summary["cves_queried"] == queried
            assert summary["cves_pending"] == pending
        assert {call.args[0] for call in enrich.call_args_list} == cves
    assert set(c.get("/api/data/snapshot").json()["cve_intel"]) == cves


@pytest.mark.parametrize("edit_during_sync", [False, True, "cancel"])
def test_background_sync_releases_lock_and_preserves_concurrent_edits(isolated_app, edit_during_sync):
    from app.core.tenancy import write_document
    c = isolated_app
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()

    def slow_sync(local):
        entered.set()
        assert release.wait(10)
        local.current_snapshot["organization"] = {"name": "Retrieved"}
        write_document("sync_state", {"threat_intel": {"status": "ok"}})
        finished.set()
        return {"status": "SYNCED", "cves_queried": 0}

    with patch.object(SnapshotStore, "sync_live_threat_intel", slow_sync):
        response = c.post("/api/sync/jobs?kind=intel")
        assert response.status_code == 202, response.text
        job_id = response.json()["id"]
        assert entered.wait(5)
        # A normal tenant read and optional mutation complete while the upstream
        # is blocked, proving that the sync does not hold the database lock.
        start = time.monotonic()
        assert c.get("/api/data/snapshot").status_code == 200
        assert time.monotonic() - start < 2
        other = TestClient(c.app, base_url="https://testserver")
        assert other.get(f"/api/sync/jobs/{job_id}").status_code == 404
        if edit_during_sync == "cancel":
            assert c.delete(f"/api/sync/jobs/{job_id}").status_code == 200
        elif edit_during_sync:
            assert c.post("/api/assets/add", json={"id": "NEW", "name": "Concurrent edit", "criticality_1_5": 3}).status_code == 200
        release.set()
        assert finished.wait(5)
        for _ in range(50):
            result = c.get(f"/api/sync/jobs/{job_id}").json()
            if result["status"] not in ("QUEUED", "RUNNING"):
                break
            time.sleep(.05)
        assert result["status"] == ("CANCELLED" if edit_during_sync == "cancel" else "SUPERSEDED" if edit_during_sync else "COMPLETED"), result
        snapshot = c.get("/api/data/snapshot").json()
        if edit_during_sync == "cancel":
            assert c.get("/api/risk/summary").json()["org"]["name"] != "Retrieved"
        elif edit_during_sync:
            assert snapshot["assets"][0]["id"] == "NEW"
        else:
            assert c.get("/api/risk/summary").json()["org"]["name"] == "Retrieved"
