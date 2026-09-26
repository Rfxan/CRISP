from typing import Dict, Any, List
from datetime import datetime, timezone
from app.connectors.base import BaseConnector

class OpenVASConnector(BaseConnector):
    """
    OpenVAS / Greenbone GMP Connector.
    Parses OpenVAS XML/JSON reports into CRISP findings canonical model.
    """
    def __init__(self, raw_report_path: str = None):
        self.raw_report_path = raw_report_path

    def fetch(self) -> Dict[str, Any]:
        return {
            "source": "OpenVAS / Greenbone Community Edition",
            "scan_id": "scan-lab-primary-001",
            "target_range": "10.0.10.0/24",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    def normalize(self, raw_data: Any) -> List[Dict[str, Any]]:
        findings = []
        if isinstance(raw_data, list):
            for idx, item in enumerate(raw_data):
                findings.append({
                    "id": item.get("id", f"FND-OV-{idx+1:03d}"),
                    "asset_id": item.get("asset_id"),
                    "cve_id": item.get("cve_id"),
                    "cvss": float(item.get("cvss", 5.0)),
                    "severity": item.get("severity", "Medium"),
                    "port": int(item.get("port", 80)),
                    "first_seen": item.get("first_seen", datetime.now(timezone.utc).isoformat()),
                    "last_seen": item.get("last_seen", datetime.now(timezone.utc).isoformat()),
                    "source": "OpenVAS Scanner"
                })
        return findings
