import re
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from defusedxml import ElementTree as ET
import csv
import io
import json
import logging
from app.connectors.base import BaseConnector

logger = logging.getLogger(__name__)


class OpenVASConnector(BaseConnector):
    """
    OpenVAS / Greenbone GMP Connector.
    Parses OpenVAS XML/CSV/JSON reports into CRISP canonical findings model.
    Extracts real host identifiers from <host> tags and never fabricates business-context fields.
    """
    CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

    @classmethod
    def _extract_cve(cls, raw_val: Optional[str]) -> Optional[str]:
        """
        Extracts the first valid CVE identifier from raw string (e.g. from CVEs/CVE/cve_id).
        Splits on commas, strips whitespace, matches ^CVE-\d{4}-\d{4,}$,
        and treats 'NOCVE', 'NONE', or empty values as None.
        """
        if not raw_val:
            return None
        raw_str = str(raw_val).strip()
        if not raw_str or raw_str.upper() in ["NOCVE", "NONE", "N/A", "NA"]:
            return None

        for token in raw_str.split(","):
            cleaned = token.strip()
            if not cleaned or cleaned.upper() in ["NOCVE", "NONE", "N/A", "NA"]:
                continue
            if cls.CVE_PATTERN.match(cleaned):
                return cleaned.upper()
        return None

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
                    "name": item.get("name", "Vulnerability Finding"),
                    "cvss": float(item.get("cvss", 5.0)),
                    "severity": item.get("severity", "Medium"),
                    "port": int(item.get("port", 0)),
                    "first_seen": item.get("first_seen", datetime.now(timezone.utc).isoformat()),
                    "last_seen": item.get("last_seen", datetime.now(timezone.utc).isoformat()),
                    "source": "OpenVAS Scanner"
                })
        return findings

    def parse(self, content: bytes, filename: str, finding_id_offset: int = 0) -> Dict[str, Any]:
        """
        Parses OpenVAS report content (XML, CSV, or JSON) into standard findings.
        Returns { "findings": [...], "skipped": int, "skip_reasons": [...] }
        Extracts real host values from <host> tags.
        Findings strictly contain technical scan attributes — never business metrics.
        """
        new_findings = []
        skipped = 0
        skip_reasons = []
        fname = filename.lower()

        if fname.endswith(".json"):
            data = json.loads(content.decode("utf-8"))
            if isinstance(data, list):
                raw_list = data
            elif isinstance(data, dict) and "findings" in data:
                raw_list = data["findings"]
            else:
                raw_list = []

            for idx, item in enumerate(raw_list):
                asset = item.get("asset_id") or item.get("host")
                if not asset:
                    skipped += 1
                    skip_reasons.append(f"JSON item #{idx + 1}: missing asset_id/host")
                    continue
                try:
                    cvss_val = float(item.get("cvss", 0.0))
                except (ValueError, TypeError):
                    cvss_val = 0.0

                new_findings.append({
                    "id": item.get("id", f"FND-OV-{finding_id_offset + len(new_findings) + 1:03d}"),
                    "asset_id": str(asset).strip(),
                    "cve_id": item.get("cve_id"),
                    "name": item.get("name", "Vulnerability Finding"),
                    "cvss": round(cvss_val, 1),
                    "severity": item.get("severity", "Medium"),
                    "port": int(item.get("port", 0)),
                    "first_seen": item.get("first_seen", datetime.now(timezone.utc).isoformat()),
                    "last_seen": item.get("last_seen", datetime.now(timezone.utc).isoformat()),
                    "source": "OpenVAS Scanner"
                })

        elif fname.endswith(".csv"):
            reader = csv.DictReader(io.StringIO(content.decode("utf-8", errors="ignore")))
            for row_idx, row in enumerate(reader):
                asset = row.get("Host") or row.get("Hostname") or row.get("asset_id") or row.get("IP")
                if not asset or not asset.strip():
                    reason = f"CSV row {row_idx + 1}: missing Host / asset_id"
                    skip_reasons.append(reason)
                    skipped += 1
                    continue

                raw_cve = (
                    row.get("CVEs")
                    or row.get("CVE")
                    or row.get("cve_id")
                    or row.get("cves")
                    or row.get("cve")
                )
                cve = self._extract_cve(raw_cve)

                cvss_raw = row.get("CVSS") or row.get("cvss")
                cvss_val = 0.0
                if cvss_raw:
                    try:
                        cvss_val = float(cvss_raw)
                    except ValueError:
                        cvss_val = 0.0

                port_raw = row.get("Port") or row.get("port") or "0"
                port_m = re.match(r"^(\d+)", str(port_raw).strip())
                port_val = int(port_m.group(1)) if port_m else 0

                sev = row.get("Severity") or row.get("severity")
                if not sev:
                    if cvss_val >= 9.0:
                        sev = "Critical"
                    elif cvss_val >= 7.0:
                        sev = "High"
                    elif cvss_val >= 4.0:
                        sev = "Medium"
                    else:
                        sev = "Low"

                finding_name = (
                    row.get("NVT Name")
                    or row.get("Name")
                    or row.get("name")
                    or row.get("nvt_name")
                    or "Vulnerability Finding"
                )
                if isinstance(finding_name, str):
                    finding_name = finding_name.strip() or "Vulnerability Finding"

                new_findings.append({
                    "id": f"FND-OV-{finding_id_offset + len(new_findings) + 1:03d}",
                    "asset_id": asset.strip(),
                    "cve_id": cve,
                    "name": finding_name,
                    "cvss": round(cvss_val, 1),
                    "severity": sev.capitalize(),
                    "port": port_val,
                    "first_seen": datetime.now(timezone.utc).isoformat(),
                    "last_seen": datetime.now(timezone.utc).isoformat(),
                    "source": "Uploaded OpenVAS CSV"
                })

        elif fname.endswith(".xml"):
            root = ET.fromstring(content)
            for result_idx, result in enumerate(root.iter("result")):
                # 1. Real Host extraction
                host_elem = result.find("host")
                host = None
                if host_elem is not None:
                    direct_text = (host_elem.text or "").strip()
                    if direct_text:
                        host = direct_text
                    else:
                        hostname_elem = host_elem.find("hostname")
                        if hostname_elem is not None and hostname_elem.text and hostname_elem.text.strip():
                            host = hostname_elem.text.strip()
                        else:
                            all_text = "".join(host_elem.itertext()).strip()
                            if all_text:
                                host = all_text

                if not host:
                    reason = f"XML <result> #{result_idx + 1}: missing or empty <host>"
                    skip_reasons.append(reason)
                    logger.warning(f"OpenVAS XML parse skipped: {reason}")
                    skipped += 1
                    continue

                # 2. Port extraction
                port_elem = result.find("port")
                port_val = 0
                if port_elem is not None and port_elem.text and port_elem.text.strip():
                    p_str = port_elem.text.strip()
                    m = re.match(r"^(\d+)", p_str)
                    if m:
                        port_val = int(m.group(1))

                # 3. NVT details (Name, CVE, CVSS)
                nvt_elem = result.find("nvt")
                finding_name = "Vulnerability Finding"
                cve_id = None
                cvss_val = None

                if nvt_elem is not None:
                    name_elem = nvt_elem.find("name")
                    if name_elem is not None and name_elem.text and name_elem.text.strip():
                        finding_name = name_elem.text.strip()

                    # Direct <cve> tag
                    cve_elem = nvt_elem.find("cve")
                    if cve_elem is not None and cve_elem.text and cve_elem.text.strip() and cve_elem.text.strip().upper() != "NOCVE":
                        cve_id = cve_elem.text.split(",")[0].strip()

                    # Check <refs><ref type="cve" id="..."/>
                    if not cve_id:
                        for ref in nvt_elem.findall("refs/ref"):
                            if ref.get("type", "").lower() == "cve" and ref.get("id"):
                                cve_id = ref.get("id").strip()
                                break

                    # Check <xref> tags for CVE patterns
                    if not cve_id:
                        for xref in nvt_elem.findall("xref"):
                            if xref.text and "cve" in xref.text.lower():
                                m = re.search(r"CVE-\d{4}-\d+", xref.text, re.IGNORECASE)
                                if m:
                                    cve_id = m.group(0).upper()
                                    break

                    # CVSS Base score from NVT
                    cvss_elem = nvt_elem.find("cvss_base")
                    if cvss_elem is not None and cvss_elem.text and cvss_elem.text.strip():
                        try:
                            cvss_val = float(cvss_elem.text.strip())
                        except ValueError:
                            pass
                else:
                    name_elem = result.find("name")
                    if name_elem is not None and name_elem.text and name_elem.text.strip():
                        finding_name = name_elem.text.strip()

                # Fallback to result-level <severity>
                if cvss_val is None:
                    sev_elem = result.find("severity")
                    if sev_elem is not None and sev_elem.text and sev_elem.text.strip():
                        try:
                            cvss_val = float(sev_elem.text.strip())
                        except ValueError:
                            pass

                # Fallback to result-level <threat>
                threat_elem = result.find("threat")
                threat_str = (threat_elem.text.strip() if threat_elem is not None and threat_elem.text else "").capitalize()

                if cvss_val is None:
                    threat_cvss = {"Critical": 9.5, "High": 7.5, "Medium": 5.0, "Low": 2.5, "Log": 0.0}
                    cvss_val = threat_cvss.get(threat_str, 0.0)

                # Determine categorical severity
                if cvss_val >= 9.0:
                    severity = "Critical"
                elif cvss_val >= 7.0:
                    severity = "High"
                elif cvss_val >= 4.0:
                    severity = "Medium"
                elif cvss_val > 0.0:
                    severity = "Low"
                else:
                    severity = threat_str or "Info"

                # Findings strictly contain technical attributes — never synthetic business values
                new_findings.append({
                    "id": f"FND-OV-{finding_id_offset + len(new_findings) + 1:03d}",
                    "asset_id": host,
                    "cve_id": cve_id,
                    "name": finding_name,
                    "cvss": round(cvss_val, 1),
                    "severity": severity,
                    "port": port_val,
                    "first_seen": datetime.now(timezone.utc).isoformat(),
                    "last_seen": datetime.now(timezone.utc).isoformat(),
                    "source": "OpenVAS Scanner"
                })

        return {
            "findings": new_findings,
            "skipped": skipped,
            "skip_reasons": skip_reasons
        }
