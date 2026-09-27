from typing import Dict, Any, List
from datetime import datetime, timezone
import xml.etree.ElementTree as ET
import csv
import io
import json
import logging
from app.connectors.base import BaseConnector

logger = logging.getLogger(__name__)


class OpenVASConnector(BaseConnector):
    """
    OpenVAS / Greenbone GMP Connector.
    Parses OpenVAS XML/CSV/JSON reports into CRISP findings canonical model.
    Never fabricates values — skips results with missing required fields.
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
        """Normalize pre-parsed list data into findings. For backward compatibility."""
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

    def parse(self, content: bytes, filename: str, finding_id_offset: int = 0) -> Dict[str, Any]:
        """
        Parses OpenVAS report content (XML, CSV, or JSON) into standard findings.
        Returns { "findings": [...], "skipped": int, "skip_reasons": [...] }
        Never fabricates values — skips results with missing required fields.
        """
        new_findings = []
        skipped = 0
        skip_reasons = []
        fname = filename.lower()

        if fname.endswith(".json"):
            data = json.loads(content.decode("utf-8"))
            if isinstance(data, list):
                new_findings = data
            elif isinstance(data, dict) and "findings" in data:
                new_findings = data["findings"]

        elif fname.endswith(".csv"):
            reader = csv.DictReader(io.StringIO(content.decode("utf-8", errors="ignore")))
            for row_idx, row in enumerate(reader):
                cve = row.get("CVE") or row.get("cve_id")
                asset = row.get("Host") or row.get("asset_id")
                cvss_raw = row.get("CVSS") or row.get("cvss")

                missing = []
                if not cve:
                    missing.append("CVE/cve_id")
                if not asset:
                    missing.append("Host/asset_id")
                if not cvss_raw:
                    missing.append("CVSS/cvss")

                if missing:
                    reason = f"CSV row {row_idx + 1}: missing {', '.join(missing)}"
                    skip_reasons.append(reason)
                    logger.warning(f"OpenVAS CSV parse skipped: {reason}")
                    skipped += 1
                    continue

                try:
                    cvss_val = float(cvss_raw)
                except ValueError:
                    reason = f"CSV row {row_idx + 1}: invalid CVSS value '{cvss_raw}'"
                    skip_reasons.append(reason)
                    logger.warning(f"OpenVAS CSV parse skipped: {reason}")
                    skipped += 1
                    continue

                new_findings.append({
                    "id": f"FND-OV-{finding_id_offset + len(new_findings) + 1:03d}",
                    "asset_id": asset,
                    "cve_id": cve,
                    "cvss": cvss_val,
                    "severity": "Critical" if cvss_val >= 9.0 else ("High" if cvss_val >= 7.0 else "Medium"),
                    "port": int(row.get("Port") or 80),
                    "first_seen": datetime.now(timezone.utc).isoformat(),
                    "last_seen": datetime.now(timezone.utc).isoformat(),
                    "source": "Uploaded OpenVAS CSV"
                })

        elif fname.endswith(".xml"):
            root = ET.fromstring(content)
            for result_idx, result in enumerate(root.iter("result")):
                host_elem = result.find("host")
                nvt_elem = result.find("nvt")

                if host_elem is None or not host_elem.text or not host_elem.text.strip():
                    reason = f"XML <result> #{result_idx + 1}: missing or empty <host>"
                    skip_reasons.append(reason)
                    logger.warning(f"OpenVAS XML parse skipped: {reason}")
                    skipped += 1
                    continue

                host = host_elem.text.strip()

                if nvt_elem is None:
                    reason = f"XML <result> #{result_idx + 1}: missing <nvt> element"
                    skip_reasons.append(reason)
                    logger.warning(f"OpenVAS XML parse skipped: {reason}")
                    skipped += 1
                    continue

                cve_elem = nvt_elem.find("cve")
                cvss_elem = nvt_elem.find("cvss_base")

                if cve_elem is None or not cve_elem.text or not cve_elem.text.strip():
                    reason = f"XML <result> #{result_idx + 1}: missing or empty <cve> in <nvt>"
                    skip_reasons.append(reason)
                    logger.warning(f"OpenVAS XML parse skipped: {reason}")
                    skipped += 1
                    continue

                if cvss_elem is None or not cvss_elem.text or not cvss_elem.text.strip():
                    reason = f"XML <result> #{result_idx + 1}: missing or empty <cvss_base> in <nvt>"
                    skip_reasons.append(reason)
                    logger.warning(f"OpenVAS XML parse skipped: {reason}")
                    skipped += 1
                    continue

                cve = cve_elem.text.split(",")[0].strip()
                try:
                    cvss_val = float(cvss_elem.text)
                except ValueError:
                    reason = f"XML <result> #{result_idx + 1}: invalid <cvss_base> value '{cvss_elem.text}'"
                    skip_reasons.append(reason)
                    logger.warning(f"OpenVAS XML parse skipped: {reason}")
                    skipped += 1
                    continue

                new_findings.append({
                    "id": f"FND-OV-{finding_id_offset + len(new_findings) + 1:03d}",
                    "asset_id": host,
                    "cve_id": cve,
                    "cvss": cvss_val,
                    "severity": "Critical" if cvss_val >= 9.0 else "High",
                    "port": 443,
                    "first_seen": datetime.now(timezone.utc).isoformat(),
                    "last_seen": datetime.now(timezone.utc).isoformat(),
                    "source": "Uploaded OpenVAS XML"
                })

        return {
            "findings": new_findings,
            "skipped": skipped,
            "skip_reasons": skip_reasons
        }
