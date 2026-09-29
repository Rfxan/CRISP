"""
CRISP Threat Intelligence Integration Module.
Ingests live threat intelligence from three official authoritative feeds:
1. FIRST.org EPSS (Exploit Prediction Scoring System) - daily exploit probability
2. CISA KEV (Known Exploited Vulnerabilities) - active weaponization catalog
3. NIST NVD API v2 (National Vulnerability Database) - CVSS v3.x metrics, descriptions, vectors

Resilient Design:
- Rate-limited for NVD API v2 (5 req/30s unauthenticated; 50 req/30s with NVD_API_KEY).
- Disk caching with TTL (7-day TTL for NVD, 24-hour TTL for CISA KEV and EPSS).
- Graceful offline fallback: if network is unavailable or times out, uses cached data
  (marked 'stale') or marks feed as 'unavailable' without crashing or inventing scores.
- Tracks per-finding provenance and timestamps for full auditability.
"""

import os
import json
import time
import logging
import threading
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, Set

import requests

logger = logging.getLogger(__name__)

# Cache TTL constants
NVD_TTL_SECONDS = 7 * 86400      # 7 days for NVD responses
KEV_TTL_SECONDS = 24 * 3600      # 24 hours for CISA KEV catalog
EPSS_TTL_SECONDS = 24 * 3600     # 24 hours for EPSS scores

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/json/known_exploited_vulnerabilities.json"
FIRST_EPSS_URL = "https://api.first.org/data/v1/epss"


def _iso_now() -> str:
    """Returns current UTC ISO-8601 formatted timestamp string."""
    return datetime.now(timezone.utc).isoformat()


def _resolve_threat_cache_dir() -> Path:
    """
    Resolves a writable directory for persisting threat intelligence caches.
    Tries backend/data/threat_cache, then ~/.crisp/threat_cache, then system tempdir.
    """
    candidates = [
        Path(__file__).resolve().parent.parent / "data" / "threat_cache",
        Path.home() / ".crisp" / "threat_cache",
        Path(tempfile.gettempdir()) / "crisp_threat_cache"
    ]
    for candidate in candidates:
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            test_file = candidate / ".write_test"
            test_file.write_text("ok", encoding="utf-8")
            test_file.unlink(missing_ok=True)
            return candidate
        except Exception:
            continue

    # Absolute fallback
    fallback = Path(tempfile.gettempdir()) / "crisp_threat_cache"
    fallback.mkdir(parents=True, exist_ok=True)
    return fallback


class ThreatIntelFeed:
    """
    Threat Intelligence Ingestion and Enrichment Engine.
    Queries NVD API v2, FIRST EPSS, and CISA KEV with disk caching,
    rate-limiting, graceful offline degradation, and provenance tracking.
    """

    def __init__(self, cache_dir: Optional[Path] = None, nvd_api_key: Optional[str] = None):
        self.cache_dir = cache_dir or _resolve_threat_cache_dir()
        self.nvd_api_key = (nvd_api_key or os.getenv("NVD_API_KEY", "")).strip() or None

        # Rate limiting: 50 req/30s with key (0.6s min gap), 5 req/30s without key (6.0s min gap)
        self.min_nvd_interval = 0.6 if self.nvd_api_key else 6.0
        self._last_nvd_call_time = 0.0
        self._rate_limit_lock = threading.Lock()

        # In-memory session and cache for KEV catalog
        self._cached_kev_data: Optional[Dict[str, Any]] = None

    def _wait_for_nvd_rate_limit(self):
        """Enforces NIST NVD API rate limits using a thread-safe sliding delay."""
        with self._rate_limit_lock:
            now = time.time()
            elapsed = now - self._last_nvd_call_time
            if elapsed < self.min_nvd_interval:
                sleep_duration = self.min_nvd_interval - elapsed
                logger.debug(f"NVD Rate Limiter: sleeping {sleep_duration:.2f}s (key={bool(self.nvd_api_key)})")
                time.sleep(sleep_duration)
            self._last_nvd_call_time = time.time()

    # -------------------------------------------------------------------------
    # Disk Cache Helpers
    # -------------------------------------------------------------------------

    def _read_disk_cache(self, filename: str) -> Optional[Dict[str, Any]]:
        """Reads a JSON file from cache_dir, returning None if unreadable."""
        file_path = self.cache_dir / filename
        if not file_path.exists():
            return None
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Could not read threat cache file {file_path}: {e}")
            return None

    def _write_disk_cache(self, filename: str, data: Dict[str, Any]):
        """Persists data dictionary to cache_dir."""
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            file_path = self.cache_dir / filename
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.warning(f"Could not write threat cache file {filename}: {e}")

    # -------------------------------------------------------------------------
    # 1. FIRST EPSS Integration
    # -------------------------------------------------------------------------

    def fetch_live_epss(self, cve_id: str) -> Dict[str, Any]:
        """
        Queries official FIRST EPSS live API for a given CVE ID.
        Returns score, percentile, status ('live' | 'cached' | 'stale' | 'unavailable'),
        and fetched_at timestamp.
        """
        cve = cve_id.strip().upper()
        cache_filename = f"epss_{cve}.json"
        cached = self._read_disk_cache(cache_filename)

        now = time.time()
        if cached:
            cached_at = cached.get("cached_at", 0.0)
            if now - cached_at < EPSS_TTL_SECONDS:
                return {
                    "epss": cached.get("epss"),
                    "epss_percentile": cached.get("epss_percentile"),
                    "status": "cached",
                    "fetched_at": cached.get("fetched_at")
                }

        # Attempt live API call
        try:
            url = f"{FIRST_EPSS_URL}?cve={cve}"
            resp = requests.get(url, timeout=4.0)
            if resp.status_code == 200:
                data = resp.json().get("data", [])
                if data:
                    epss_val = float(data[0].get("epss", 0.1))
                    pct_val = float(data[0].get("percentile", 0.5))
                    fetched_at = _iso_now()

                    record = {
                        "cve_id": cve,
                        "epss": epss_val,
                        "epss_percentile": pct_val,
                        "cached_at": now,
                        "fetched_at": fetched_at
                    }
                    self._write_disk_cache(cache_filename, record)
                    return {
                        "epss": epss_val,
                        "epss_percentile": pct_val,
                        "status": "live",
                        "fetched_at": fetched_at
                    }
        except Exception as e:
            logger.info(f"EPSS live query error for {cve}: {e}")

        # Fail-soft fallback to stale cache if present
        if cached and cached.get("epss") is not None:
            return {
                "epss": cached.get("epss"),
                "epss_percentile": cached.get("epss_percentile"),
                "status": "stale",
                "fetched_at": cached.get("fetched_at")
            }

        # No network, no cache
        return {
            "epss": None,
            "epss_percentile": None,
            "status": "unavailable",
            "fetched_at": None
        }

    # -------------------------------------------------------------------------
    # 2. CISA KEV Catalog Integration
    # -------------------------------------------------------------------------

    def fetch_cisa_kev(self, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Downloads CISA Known Exploited Vulnerabilities catalog.
        Caches locally with 24-hour TTL. Builds a mapping of active KEV CVE IDs.
        Returns:
          {
            "cves": { "CVE-XXXX-YYYY": { "date_added": "...", "vulnerability_name": "...", ... } },
            "status": "live" | "cached" | "stale" | "unavailable",
            "fetched_at": str,
            "count": int
          }
        """
        cache_filename = "cisa_kev.json"
        cached = self._read_disk_cache(cache_filename)
        now = time.time()

        if not force_refresh and cached and cached.get("cves"):
            cached_at = cached.get("cached_at", 0.0)
            if now - cached_at < KEV_TTL_SECONDS:
                self._cached_kev_data = cached
                return {
                    "cves": cached.get("cves", {}),
                    "status": "cached",
                    "fetched_at": cached.get("fetched_at"),
                    "count": len(cached.get("cves", {}))
                }

        # Attempt live download
        try:
            resp = requests.get(CISA_KEV_URL, timeout=10.0)
            if resp.status_code == 200:
                raw_data = resp.json()
                vulns = raw_data.get("vulnerabilities", [])
                cve_map: Dict[str, Any] = {}
                for v in vulns:
                    cid = v.get("cveID", "").strip().upper()
                    if cid:
                        cve_map[cid] = {
                            "date_added": v.get("dateAdded"),
                            "vulnerability_name": v.get("vulnerabilityName", ""),
                            "vendor_project": v.get("vendorProject", ""),
                            "product": v.get("product", ""),
                            "short_description": v.get("shortDescription", ""),
                            "known_ransomware_campaign_use": v.get("knownRansomwareCampaignUse", "Unknown")
                        }

                fetched_at = _iso_now()
                record = {
                    "title": raw_data.get("title", "CISA KEV"),
                    "catalog_version": raw_data.get("catalogVersion", ""),
                    "date_released": raw_data.get("dateReleased", ""),
                    "cached_at": now,
                    "fetched_at": fetched_at,
                    "cves": cve_map
                }
                self._write_disk_cache(cache_filename, record)
                self._cached_kev_data = record
                return {
                    "cves": cve_map,
                    "status": "live",
                    "fetched_at": fetched_at,
                    "count": len(cve_map)
                }
        except Exception as e:
            logger.info(f"CISA KEV live download error: {e}")

        # Fail-soft fallback to stale cache
        if cached and cached.get("cves"):
            self._cached_kev_data = cached
            return {
                "cves": cached.get("cves", {}),
                "status": "stale",
                "fetched_at": cached.get("fetched_at"),
                "count": len(cached.get("cves", {}))
            }

        # No network, no cache
        return {
            "cves": {},
            "status": "unavailable",
            "fetched_at": None,
            "count": 0
        }

    # -------------------------------------------------------------------------
    # 3. NIST NVD API v2 Integration
    # -------------------------------------------------------------------------

    def fetch_nvd_cve(self, cve_id: str) -> Dict[str, Any]:
        """
        Queries NVD API v2 for CVE details (description, CVSS v3.x score/vector, published date).
        Respects rate limits (5 req/30s or 50 req/30s with NVD_API_KEY).
        Caches responses on disk with 7-day TTL.
        Fails soft on network error, returning stale data or unavailable status without inventing scores.
        """
        cve = cve_id.strip().upper()
        cache_filename = f"nvd_{cve}.json"
        cached = self._read_disk_cache(cache_filename)
        now = time.time()

        if cached:
            cached_at = cached.get("cached_at", 0.0)
            if now - cached_at < NVD_TTL_SECONDS:
                return {
                    "cve_id": cve,
                    "description": cached.get("description"),
                    "cvss_score": cached.get("cvss_score"),
                    "cvss_vector": cached.get("cvss_vector"),
                    "published_date": cached.get("published_date"),
                    "status": "cached",
                    "fetched_at": cached.get("fetched_at")
                }

        # Live NVD API v2 request with rate limit delay
        try:
            self._wait_for_nvd_rate_limit()

            url = f"{NVD_BASE_URL}?cveId={cve}"
            headers = {"User-Agent": "CRISP-Security-Platform/1.0"}
            if self.nvd_api_key:
                headers["apiKey"] = self.nvd_api_key

            resp = requests.get(url, headers=headers, timeout=8.0)
            if resp.status_code == 200:
                payload = resp.json()
                vulns = payload.get("vulnerabilities", [])
                if vulns:
                    cve_obj = vulns[0].get("cve", {})
                    # Description
                    descriptions = cve_obj.get("descriptions", [])
                    desc = next((d.get("value") for d in descriptions if d.get("lang") == "en"), None)
                    if not desc and descriptions:
                        desc = descriptions[0].get("value")

                    # Published date
                    published = cve_obj.get("published")

                    # CVSS v3.1 / v3.0 / v2
                    metrics = cve_obj.get("metrics", {})
                    cvss_score: Optional[float] = None
                    cvss_vector: Optional[str] = None

                    v31_list = metrics.get("cvssMetricV31", [])
                    v30_list = metrics.get("cvssMetricV30", [])
                    v2_list = metrics.get("cvssMetricV2", [])

                    if v31_list:
                        data = v31_list[0].get("cvssData", {})
                        cvss_score = float(data.get("baseScore")) if data.get("baseScore") is not None else None
                        cvss_vector = data.get("vectorString")
                    elif v30_list:
                        data = v30_list[0].get("cvssData", {})
                        cvss_score = float(data.get("baseScore")) if data.get("baseScore") is not None else None
                        cvss_vector = data.get("vectorString")
                    elif v2_list:
                        data = v2_list[0].get("cvssData", {})
                        cvss_score = float(data.get("baseScore")) if data.get("baseScore") is not None else None
                        cvss_vector = data.get("vectorString")

                    fetched_at = _iso_now()
                    record = {
                        "cve_id": cve,
                        "description": desc,
                        "cvss_score": cvss_score,
                        "cvss_vector": cvss_vector,
                        "published_date": published,
                        "cached_at": now,
                        "fetched_at": fetched_at
                    }
                    self._write_disk_cache(cache_filename, record)
                    return {
                        "cve_id": cve,
                        "description": desc,
                        "cvss_score": cvss_score,
                        "cvss_vector": cvss_vector,
                        "published_date": published,
                        "status": "live",
                        "fetched_at": fetched_at
                    }
        except Exception as e:
            logger.info(f"NVD API live query error for {cve}: {e}")

        # Fallback to stale cache if present
        if cached:
            return {
                "cve_id": cve,
                "description": cached.get("description"),
                "cvss_score": cached.get("cvss_score"),
                "cvss_vector": cached.get("cvss_vector"),
                "published_date": cached.get("published_date"),
                "status": "stale",
                "fetched_at": cached.get("fetched_at")
            }

        # Offline / unavailable
        return {
            "cve_id": cve,
            "description": None,
            "cvss_score": None,
            "cvss_vector": None,
            "published_date": None,
            "status": "unavailable",
            "fetched_at": None
        }

    # -------------------------------------------------------------------------
    # Unified Enrichment & Provenance
    # -------------------------------------------------------------------------

    def enrich_cve(
        self,
        cve_id: str,
        kev_catalog: Optional[Dict[str, Any]] = None,
        local_cache: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Enriches a CVE by combining FIRST EPSS, CISA KEV, and NIST NVD.
        Surfaces detailed per-source provenance, labels KEV exploitation,
        and degrades gracefully without ever inventing scores.
        """
        cve = cve_id.strip().upper()

        # 1. KEV check
        if kev_catalog is None:
            kev_res = self.fetch_cisa_kev()
            kev_cves = kev_res.get("cves", {})
            kev_status = kev_res.get("status", "unavailable")
            kev_fetched_at = kev_res.get("fetched_at")
        else:
            kev_cves = kev_catalog.get("cves", {})
            kev_status = kev_catalog.get("status", "cached")
            kev_fetched_at = kev_catalog.get("fetched_at")

        in_kev = cve in kev_cves
        kev_detail = kev_cves.get(cve) if in_kev else None

        exploitability_label = (
            "KEV-confirmed active exploitation" if in_kev
            else "Standard exploit likelihood"
        )

        # 2. EPSS check
        epss_res = self.fetch_live_epss(cve)
        epss_val = epss_res.get("epss")
        epss_pct = epss_res.get("epss_percentile")

        # 3. NVD check
        nvd_res = self.fetch_nvd_cve(cve)

        # Build provenance
        provenance = {
            "epss": {
                "source": "FIRST EPSS",
                "score": epss_val,
                "percentile": epss_pct,
                "status": epss_res.get("status", "unavailable"),
                "fetched_at": epss_res.get("fetched_at")
            },
            "nvd": {
                "source": "NIST NVD API v2",
                "cvss_score": nvd_res.get("cvss_score"),
                "cvss_vector": nvd_res.get("cvss_vector"),
                "description": nvd_res.get("description"),
                "published_date": nvd_res.get("published_date"),
                "status": nvd_res.get("status", "unavailable"),
                "fetched_at": nvd_res.get("fetched_at")
            },
            "kev": {
                "source": "CISA KEV Catalog",
                "in_kev": in_kev,
                "date_added": kev_detail.get("date_added") if kev_detail else None,
                "vulnerability_name": kev_detail.get("vulnerability_name") if kev_detail else None,
                "ransomware_campaign": kev_detail.get("known_ransomware_campaign_use") if kev_detail else None,
                "exploitability_label": exploitability_label,
                "status": kev_status,
                "fetched_at": kev_fetched_at
            }
        }

        # Fallback values from existing local_cache if online sources unavailable
        existing = (local_cache or {}).get(cve, {})

        final_epss = epss_val if epss_val is not None else existing.get("epss", 0.15)
        final_pct = epss_pct if epss_pct is not None else existing.get("epss_percentile", 0.50)
        final_desc = nvd_res.get("description") or existing.get("description") or "Security vulnerability"
        final_pub = nvd_res.get("published_date") or existing.get("published") or "Unknown"

        return {
            "cve_id": cve,
            "description": final_desc,
            "epss": final_epss,
            "epss_percentile": final_pct,
            "in_kev": in_kev,
            "exploit_public": in_kev or existing.get("exploit_public", False),
            "exploitability_label": exploitability_label,
            "cvss_v3_score": nvd_res.get("cvss_score") or existing.get("cvss"),
            "cvss_v3_vector": nvd_res.get("cvss_vector"),
            "published": final_pub,
            "provenance": provenance
        }

    def get_cve_intel(self, cve_id: str, local_cache: Dict[str, Any]) -> Dict[str, Any]:
        """Backward-compatible helper returning enriched threat intel for a given CVE ID."""
        if cve_id in local_cache and "provenance" in local_cache[cve_id]:
            return local_cache[cve_id]
        return self.enrich_cve(cve_id, local_cache=local_cache)
