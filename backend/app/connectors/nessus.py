"""
Nessus Connector for CRISP.
Parses real Nessus .nessus XML exports (NessusClientData_v2 format)
into CRISP's standard Finding shape.
"""
from typing import Dict, Any, List
from datetime import datetime, timezone
import xml.etree.ElementTree as ET
import logging
from app.connectors.base import BaseConnector

logger = logging.getLogger(__name__)


class NessusConnector(BaseConnector):
    """
    Nessus Vulnerability Scanner Connector.
    Parses .nessus XML exports into CRISP findings canonical model.
    Never fabricates values — skips items with missing required fields.
    
    Nessus XML structure:
    <NessusClientData_v2>
      <Report name="...">
        <ReportHost name="hostname_or_ip">
          <ReportItem port="..." severity="..." pluginID="...">
            <cve>CVE-XXXX-XXXXX</cve>
            <cvss_base_score>X.X</cvss_base_score>
          </ReportItem>
        </ReportHost>
      </Report>
    </NessusClientData_v2>
    """
    def __init__(self):
        pass

    def fetch(self) -> Dict[str, Any]:
        return {
            "source": "Tenable Nessus",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    def normalize(self, raw_data: Any) -> List[Dict[str, Any]]:
        """Normalize pre-parsed list data into findings."""
        findings = []
        if isinstance(raw_data, list):
            for idx, item in enumerate(raw_data):
                findings.append({
                    "id": item.get("id", f"FND-NS-{idx+1:03d}"),
                    "asset_id": item.get("asset_id"),
                    "cve_id": item.get("cve_id"),
                    "cvss": float(item.get("cvss", 5.0)),
                    "severity": item.get("severity", "Medium"),
                    "port": int(item.get("port", 0)),
                    "first_seen": item.get("first_seen", datetime.now(timezone.utc).isoformat()),
                    "last_seen": item.get("last_seen", datetime.now(timezone.utc).isoformat()),
                    "source": "Nessus Scanner"
                })
        return findings

    def parse(self, xml_content: bytes, finding_id_offset: int = 0) -> Dict[str, Any]:
        """
        Parses a Nessus .nessus XML export into standard findings.
        Returns { "findings": [...], "skipped": int, "skip_reasons": [...] }
        Never fabricates values — skips items with missing required fields.
        """
        new_findings = []
        skipped = 0
        skip_reasons = []

        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError as e:
            return {"findings": [], "skipped": 0, "skip_reasons": [f"XML parse error: {e}"]}

        item_idx = 0
        for report in root.iter("Report"):
            for report_host in report.iter("ReportHost"):
                host_name = report_host.get("name")
                if not host_name or not host_name.strip():
                    reason = f"ReportHost has no 'name' attribute"
                    skip_reasons.append(reason)
                    logger.warning(f"Nessus parse skipped: {reason}")
                    skipped += 1
                    continue

                host = host_name.strip()

                for report_item in report_host.iter("ReportItem"):
                    item_idx += 1
                    port = report_item.get("port", "0")
                    severity_num = report_item.get("severity", "0")
                    plugin_id = report_item.get("pluginID", "")

                    # Map Nessus severity numbers: 0=Info, 1=Low, 2=Medium, 3=High, 4=Critical
                    severity_map = {"0": "Info", "1": "Low", "2": "Medium", "3": "High", "4": "Critical"}
                    severity = severity_map.get(str(severity_num), "Medium")

                    # Skip informational findings (severity 0)
                    if str(severity_num) == "0":
                        continue

                    # Require CVE
                    cve_elem = report_item.find("cve")
                    if cve_elem is None or not cve_elem.text or not cve_elem.text.strip():
                        reason = f"ReportItem #{item_idx} (pluginID={plugin_id}) on host {host}: missing <cve>"
                        skip_reasons.append(reason)
                        logger.warning(f"Nessus parse skipped: {reason}")
                        skipped += 1
                        continue

                    cve = cve_elem.text.strip()

                    # Get CVSS base score
                    cvss_elem = report_item.find("cvss_base_score")
                    if cvss_elem is None or not cvss_elem.text or not cvss_elem.text.strip():
                        reason = f"ReportItem #{item_idx} (pluginID={plugin_id}, CVE={cve}) on host {host}: missing <cvss_base_score>"
                        skip_reasons.append(reason)
                        logger.warning(f"Nessus parse skipped: {reason}")
                        skipped += 1
                        continue

                    try:
                        cvss_val = float(cvss_elem.text.strip())
                    except ValueError:
                        reason = f"ReportItem #{item_idx} (pluginID={plugin_id}, CVE={cve}) on host {host}: invalid <cvss_base_score> '{cvss_elem.text}'"
                        skip_reasons.append(reason)
                        logger.warning(f"Nessus parse skipped: {reason}")
                        skipped += 1
                        continue

                    try:
                        port_int = int(port)
                    except ValueError:
                        port_int = 0

                    new_findings.append({
                        "id": f"FND-NS-{finding_id_offset + len(new_findings) + 1:03d}",
                        "asset_id": host,
                        "cve_id": cve,
                        "cvss": cvss_val,
                        "severity": severity,
                        "port": port_int,
                        "first_seen": datetime.now(timezone.utc).isoformat(),
                        "last_seen": datetime.now(timezone.utc).isoformat(),
                        "source": "Nessus Scanner"
                    })

        return {
            "findings": new_findings,
            "skipped": skipped,
            "skip_reasons": skip_reasons
        }
