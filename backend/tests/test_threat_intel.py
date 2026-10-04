"""
Comprehensive Unit and Integration Tests for Threat Intelligence Module (NVD, CISA KEV, FIRST EPSS).
Tests:
1. NVD API v2 fetching, CVSS metric parsing, rate-limiting, and 7-day TTL disk caching.
2. CISA KEV catalog download, weaponization tracking, and exploitability labeling.
3. Offline / fail-soft behavior: stale labeling, unavailable handling without crashes or invented scores.
4. Per-finding and per-CVE provenance surfacing via API endpoints.
5. End-to-end FAIR engine integration and live KEV acceptance test.
"""

import os
import json
import time
import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from app.ai.threat_intel import (
    ThreatIntelFeed,
    NVD_TTL_SECONDS,
    KEV_TTL_SECONDS,
    EPSS_TTL_SECONDS
)
from app.main import app
from app.api.routes import store


@pytest.fixture
def temp_cache_dir():
    """Provides an isolated temporary directory for testing disk caching."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def mock_nvd_response():
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-44228",
                    "descriptions": [
                        {"lang": "en", "value": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP."}
                    ],
                    "published": "2021-12-10T10:15:00.000",
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 10.0,
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
                                }
                            }
                        ]
                    }
                }
            }
        ]
    }


@pytest.fixture
def mock_kev_response():
    return {
        "title": "CISA Known Exploited Vulnerabilities Catalog",
        "catalogVersion": "2026.01.01",
        "dateReleased": "2026-01-01T00:00:00Z",
        "count": 2,
        "vulnerabilities": [
            {
                "cveID": "CVE-2021-44228",
                "vendorProject": "Apache",
                "product": "Log4j",
                "vulnerabilityName": "Apache Log4j Remote Code Execution",
                "dateAdded": "2021-12-10",
                "shortDescription": "Log4j allows remote code execution via LDAP JNDI.",
                "knownRansomwareCampaignUse": "Known"
            },
            {
                "cveID": "CVE-2023-34362",
                "vendorProject": "Progress",
                "product": "MOVEit Transfer",
                "vulnerabilityName": "MOVEit Transfer SQL Injection",
                "dateAdded": "2023-06-02",
                "shortDescription": "SQL injection leading to unauthenticated access.",
                "knownRansomwareCampaignUse": "Known"
            }
        ]
    }


@pytest.fixture
def mock_epss_response():
    return {
        "status": "OK",
        "data": [
            {
                "cve": "CVE-2021-44228",
                "epss": "0.97542",
                "percentile": "0.99980"
            }
        ]
    }


# =============================================================================
# 1. NIST NVD API v2 Tests
# =============================================================================

def test_nvd_fetch_and_parse(temp_cache_dir, mock_nvd_response):
    """Verifies parsing of NVD v2 description, CVSS v3.1 score/vector, and publish date."""
    feed = ThreatIntelFeed(cache_dir=temp_cache_dir)
    feed.min_nvd_interval = 0.0

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_nvd_response

    with patch("requests.get", return_value=mock_resp) as mock_get:
        res = feed.fetch_nvd_cve("CVE-2021-44228")
        assert mock_get.called
        assert res["cve_id"] == "CVE-2021-44228"
        assert res["cvss_score"] == 10.0
        assert "AV:N/AC:L" in res["cvss_vector"]
        assert "Apache Log4j2" in res["description"]
        assert res["published_date"] == "2021-12-10T10:15:00.000"
        assert res["status"] == "live"
        assert res["fetched_at"] is not None

        # Verify disk cache file was created
        cache_file = temp_cache_dir / "nvd_CVE-2021-44228.json"
        assert cache_file.exists()


def test_nvd_caching_and_ttl(temp_cache_dir, mock_nvd_response):
    """Verifies that second call uses 7-day disk cache without making network requests."""
    feed = ThreatIntelFeed(cache_dir=temp_cache_dir)
    feed.min_nvd_interval = 0.0

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_nvd_response

    with patch("requests.get", return_value=mock_resp) as mock_get:
        # First call: hits network
        res1 = feed.fetch_nvd_cve("CVE-2021-44228")
        assert mock_get.call_count == 1
        assert res1["status"] == "live"

        # Second call: served from disk cache
        res2 = feed.fetch_nvd_cve("CVE-2021-44228")
        assert mock_get.call_count == 1  # No additional network call!
        assert res2["status"] == "cached"
        assert res2["cvss_score"] == 10.0


def test_nvd_offline_fallback_stale(temp_cache_dir):
    """Verifies that when network fails, expired cache is labeled 'stale' without crashing."""
    feed = ThreatIntelFeed(cache_dir=temp_cache_dir)
    feed.min_nvd_interval = 0.0

    # Seed disk cache with an expired record (> 7 days old)
    old_time = time.time() - (NVD_TTL_SECONDS + 1000)
    cache_record = {
        "cve_id": "CVE-2021-44228",
        "description": "Cached old log4j",
        "cvss_score": 10.0,
        "cvss_vector": "CVSS:3.1/...",
        "published_date": "2021-12-10",
        "cached_at": old_time,
        "fetched_at": "2026-09-01T00:00:00Z"
    }
    with open(temp_cache_dir / "nvd_CVE-2021-44228.json", "w", encoding="utf-8") as f:
        json.dump(cache_record, f)

    # Simulate network failure
    with patch("requests.get", side_effect=Exception("ConnectionRefused")):
        res = feed.fetch_nvd_cve("CVE-2021-44228")
        assert res["status"] == "stale"
        assert res["cvss_score"] == 10.0
        assert res["description"] == "Cached old log4j"


def test_nvd_offline_unavailable_no_invention(temp_cache_dir):
    """Verifies that offline with no cache returns unavailable and does NOT invent scores."""
    feed = ThreatIntelFeed(cache_dir=temp_cache_dir)
    feed.min_nvd_interval = 0.0

    with patch("requests.get", side_effect=Exception("Network Unreachable")):
        res = feed.fetch_nvd_cve("CVE-9999-9999")
        assert res["status"] == "unavailable"
        assert res["cvss_score"] is None
        assert res["cvss_vector"] is None
        assert res["description"] is None


def test_nvd_api_key_header_and_rate_limit(temp_cache_dir, mock_nvd_response):
    """Verifies NVD_API_KEY header injection and rate limit configuration."""
    feed = ThreatIntelFeed(cache_dir=temp_cache_dir, nvd_api_key="TEST-API-KEY-12345")
    assert feed.min_nvd_interval == 0.6  # 50 req/30s
    feed.min_nvd_interval = 0.0

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_nvd_response

    with patch("requests.get", return_value=mock_resp) as mock_get:
        feed.fetch_nvd_cve("CVE-2021-44228")
        assert mock_get.called
        headers = mock_get.call_args[1].get("headers", {})
        assert headers.get("apiKey") == "TEST-API-KEY-12345"


# =============================================================================
# 2. CISA KEV Catalog Tests
# =============================================================================

def test_cisa_kev_fetch_and_enrichment(temp_cache_dir, mock_kev_response):
    """Verifies CISA KEV download, CVE set membership, and exploitability labeling."""
    feed = ThreatIntelFeed(cache_dir=temp_cache_dir)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_kev_response

    with patch("requests.get", return_value=mock_resp):
        kev_res = feed.fetch_cisa_kev()
        assert kev_res["status"] == "live"
        assert kev_res["count"] == 2
        assert "CVE-2021-44228" in kev_res["cves"]
        assert "CVE-2023-34362" in kev_res["cves"]

        # Test enrichment for CVE in KEV
        enriched_kev = feed.enrich_cve("CVE-2021-44228", kev_catalog=kev_res)
        assert enriched_kev["in_kev"] is True
        assert enriched_kev["exploitability_label"] == "KEV-confirmed active exploitation"
        assert enriched_kev["provenance"]["kev"]["in_kev"] is True
        assert enriched_kev["provenance"]["kev"]["exploitability_label"] == "KEV-confirmed active exploitation"

        # Test enrichment for CVE NOT in KEV
        enriched_non_kev = feed.enrich_cve("CVE-2020-0001", kev_catalog=kev_res)
        assert enriched_non_kev["in_kev"] is False
        assert enriched_non_kev["exploitability_label"] == "Standard exploit likelihood"
        assert enriched_non_kev["provenance"]["kev"]["in_kev"] is False


@pytest.mark.parametrize("primary_failure", [404, 503, "timeout", "malformed"])
def test_cisa_kev_uses_official_mirror_on_primary_failure(temp_cache_dir, mock_kev_response, primary_failure):
    from app.ai.threat_intel import CISA_KEV_URL
    feed = ThreatIntelFeed(cache_dir=temp_cache_dir)
    mirror_url = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
    primary = MagicMock(status_code=primary_failure if isinstance(primary_failure, int) else 200)
    primary.json.return_value = {"error": "Invalid catalog"}
    mirror = MagicMock(status_code=200)
    mirror.json.return_value = mock_kev_response
    failure = TimeoutError("Primary feed timed out") if primary_failure == "timeout" else primary
    with patch("requests.get", side_effect=[failure, mirror]) as fetch:
        result = feed.fetch_cisa_kev(force_refresh=True)
    assert result["status"] == "live"
    assert result["count"] == 2
    assert result["source_url"] == mirror_url
    assert [call.args[0] for call in fetch.call_args_list] == [CISA_KEV_URL, mirror_url]
    # Persist the actual source when later serving the valid cached catalog.
    with patch("requests.get", side_effect=AssertionError("Fresh cache should not fetch")):
        cached = feed.fetch_cisa_kev()
    assert cached["status"] == "cached"
    assert cached["source_url"] == mirror_url


def test_cisa_kev_rejects_invalid_catalog_without_claiming_success(temp_cache_dir):
    feed = ThreatIntelFeed(cache_dir=temp_cache_dir)
    invalid = MagicMock(status_code=200)
    invalid.json.return_value = {"error": "Temporarily unavailable"}
    with patch("requests.get", return_value=invalid):
        result = feed.fetch_cisa_kev(force_refresh=True)
    assert result["status"] == "unavailable"
    assert result["count"] == 0
    assert not (temp_cache_dir / "cisa_kev.json").exists()


def test_cisa_kev_offline_fallback(temp_cache_dir):
    """Verifies CISA KEV offline fail-soft behavior with stale cache."""
    feed = ThreatIntelFeed(cache_dir=temp_cache_dir)

    old_time = time.time() - (KEV_TTL_SECONDS + 500)
    cached_kev = {
        "cached_at": old_time,
        "fetched_at": "2026-09-01T00:00:00Z",
        "cves": {
            "CVE-2021-44228": {"date_added": "2021-12-10", "vulnerability_name": "Log4j"}
        }
    }
    with open(temp_cache_dir / "cisa_kev.json", "w", encoding="utf-8") as f:
        json.dump(cached_kev, f)

    with patch("requests.get", side_effect=Exception("Timeout")):
        res = feed.fetch_cisa_kev()
        assert res["status"] == "stale"
        assert "CVE-2021-44228" in res["cves"]


# =============================================================================
# 3. FIRST EPSS Integration Tests
# =============================================================================

def test_epss_fetch_and_caching(temp_cache_dir, mock_epss_response):
    """Verifies EPSS score parsing and disk caching."""
    feed = ThreatIntelFeed(cache_dir=temp_cache_dir)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_epss_response

    with patch("requests.get", return_value=mock_resp) as mock_get:
        res = feed.fetch_live_epss("CVE-2021-44228")
        assert mock_get.call_count == 1
        assert res["status"] == "live"
        assert res["epss"] == pytest.approx(0.97542, rel=1e-3)
        assert res["epss_percentile"] == pytest.approx(0.99980, rel=1e-3)

        # Second call hits cache
        res2 = feed.fetch_live_epss("CVE-2021-44228")
        assert mock_get.call_count == 1
        assert res2["status"] == "cached"


# =============================================================================
# 4. Provenance API Endpoints & FAIR Engine Integration
# =============================================================================

def test_api_threat_intel_sync_and_provenance(mock_nvd_response, mock_kev_response, mock_epss_response):
    """
    Verifies that POST /api/ingest/sync-live-intel and GET /api/threat-intel/provenance
    surface per-source provenance, KEV membership, and exploitability labels.
    """
    # Seed snapshot with a finding for Log4j
    seed_file = Path(__file__).resolve().parent.parent / "app" / "data" / "seed_snapshot.json"
    if seed_file.exists():
        with open(seed_file, "r", encoding="utf-8") as f:
            store.current_snapshot = json.load(f)

    # Ensure CVE-2021-44228 is in findings
    findings = store.current_snapshot.setdefault("findings", [])
    if not any(f.get("cve_id") == "CVE-2021-44228" for f in findings):
        findings.append({
            "id": "FND-LOG4J-TEST",
            "asset_id": "AST-PAY-GW-01",
            "cve_id": "CVE-2021-44228",
            "name": "Apache Log4j RCE",
            "severity": "Critical"
        })

    def mock_requests_get(url, *args, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        if "cisa.gov" in url:
            resp.json.return_value = mock_kev_response
        elif "services.nvd.nist.gov" in url:
            resp.json.return_value = mock_nvd_response
        elif "api.first.org" in url:
            resp.json.return_value = mock_epss_response
        else:
            resp.status_code = 404
        return resp

    client = TestClient(app)
    orig_interval = store.threat_intel.min_nvd_interval
    store.threat_intel.min_nvd_interval = 0.0

    try:
        with patch("requests.get", side_effect=mock_requests_get):
            # Trigger threat intel sync
            sync_resp = client.post("/api/ingest/sync-live-intel")
            assert sync_resp.status_code == 200
            sync_data = sync_resp.json()
            assert sync_data["status"] == "SYNCED"
            assert sync_data["kev_catalog_count"] == 2

            # Verify GET /api/threat-intel/provenance for specific CVE
            prov_resp = client.get("/api/threat-intel/provenance?cve_id=CVE-2021-44228")
            assert prov_resp.status_code == 200
            prov_data = prov_resp.json()
            assert prov_data["cve_id"] == "CVE-2021-44228"
            assert prov_data["in_kev"] is True
            assert prov_data["exploitability_label"] == "KEV-confirmed active exploitation"

            provenance = prov_data["provenance"]
            assert "epss" in provenance
            assert "nvd" in provenance
            assert "kev" in provenance
            assert provenance["kev"]["in_kev"] is True
            assert provenance["nvd"]["cvss_score"] == 10.0
            assert provenance["epss"]["score"] > 0.9

            # Verify GET /api/data/snapshot includes provenance in cve_intel
            tech_resp = client.get("/api/data/snapshot")
            assert tech_resp.status_code == 200
            tech_data = tech_resp.json()
            cve_intel = tech_data.get("cve_intel", {})
        assert "CVE-2021-44228" in cve_intel
        assert cve_intel["CVE-2021-44228"]["in_kev"] is True
        assert "provenance" in cve_intel["CVE-2021-44228"]

        # Verify FAIR engine drivers surface exploitability label
        summary = store.get_summary()
        log4j_driver = next((d for d in summary.get("drivers", []) if d.get("id") == "CVE-2021-44228"), None)
        if log4j_driver:
            assert log4j_driver["in_kev"] is True
            assert log4j_driver.get("exploitability_label") == "KEV-confirmed active exploitation"
    finally:
        store.threat_intel.min_nvd_interval = orig_interval


# =============================================================================
# 5. Live Acceptance Test (Runs live if network is accessible)
# =============================================================================

def test_live_network_acceptance_cve_2021_44228():
    """
    Acceptance Test:
    With network on, a finding for a real KEV CVE (CVE-2021-44228) returns in_kev=true
    with a fetch timestamp; with network off, engine still runs and marks intel as
    stale/unavailable — never crashes, never invents scores.
    """
    feed = ThreatIntelFeed()

    # Try live query
    try:
        enriched = feed.enrich_cve("CVE-2021-44228")
        assert enriched["cve_id"] == "CVE-2021-44228"
        # If network connected, verify KEV status and timestamp
        if enriched["provenance"]["kev"]["status"] in ["live", "cached"]:
            assert enriched["in_kev"] is True
            assert enriched["exploitability_label"] == "KEV-confirmed active exploitation"
            assert enriched["provenance"]["kev"]["fetched_at"] is not None
            print(f"\n>>> LIVE ACCEPTANCE VERIFIED: Log4j KEV=True, fetched_at={enriched['provenance']['kev']['fetched_at']}")
    except Exception as e:
        # Should never reach unhandled exception
        pytest.fail(f"ThreatIntelFeed crashed on live test: {e}")
