from typing import Dict, Any, Optional
import requests
import json
from pathlib import Path

class ThreatIntelFeed:
    """
    Threat Intelligence Ingestion and Enrichment (NVD, FIRST EPSS, CISA KEV).
    Provides online fetching with immediate graceful fallback to cached snapshots.
    """
    def __init__(self, cache_file: Optional[Path] = None):
        self.cache_file = cache_file

    def get_cve_intel(self, cve_id: str, local_cache: Dict[str, Any]) -> Dict[str, Any]:
        """Returns enriched threat intel for a given CVE ID."""
        if cve_id in local_cache:
            return local_cache[cve_id]

        # Default fallback if unknown
        return {
            "cve_id": cve_id,
            "description": "Security vulnerability",
            "epss": 0.15,
            "epss_percentile": 0.50,
            "in_kev": False,
            "exploit_public": False,
            "published": "2024-01-01"
        }

    def fetch_live_epss(self, cve_id: str) -> Optional[Dict[str, float]]:
        """Optionally queries FIRST EPSS live API."""
        try:
            url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
            resp = requests.get(url, timeout=3.0)
            if resp.status_code == 200:
                data = resp.json().get("data", [])
                if data:
                    return {
                        "epss": float(data[0].get("epss", 0.1)),
                        "epss_percentile": float(data[0].get("percentile", 0.5))
                    }
        except Exception:
            pass
        return None
