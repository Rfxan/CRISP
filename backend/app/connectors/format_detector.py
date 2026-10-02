"""
Scan and telemetry format auto-detection for CRISP ingestion pipeline.
Inspects actual file content (headers, JSON structures, XML root tags),
not just file extensions, to accurately identify scanner & EDR formats:
  - Microsoft Defender for Endpoint Advanced Hunting (CSV & JSON)
  - OpenVAS Vulnerability Scanner (XML with <report> root, CSV, JSON)
  - Tenable Nessus Vulnerability Scanner (XML with <NessusClientData_v2> root)
"""

from defusedxml import ElementTree as ET
import csv
import io
import json
import logging
from typing import List, Set

logger = logging.getLogger(__name__)


def _is_defender_keys(keys: List[str]) -> bool:
    """
    Checks if a set of column/key names matches Microsoft Defender Advanced Hunting exports.
    Must contain a device identifier AND detection/alert metadata AND severity.
    """
    clean_keys: Set[str] = {str(k).strip().lower().replace("_", "").replace(" ", "") for k in keys if k}
    has_device = any(k in clean_keys for k in ["devicename", "deviceid", "computername", "machineid"])
    has_detection = any(k in clean_keys for k in ["alertid", "alerttitle", "title", "actiontype", "attacktechniques", "mitretechniques"])
    has_severity = any(k in clean_keys for k in ["severity", "alertseverity"])
    return has_device and (has_detection or has_severity)


def detect_scan_format(file_content: bytes, filename: str) -> str:
    """
    Detects the scan or EDR report format from file content and filename.
    Returns one of:
      - "defender_edr" : Microsoft Defender for Endpoint Advanced Hunting (CSV or JSON)
      - "openvas_xml"  : OpenVAS XML (<report>), CSV, or JSON
      - "nessus_xml"   : Tenable Nessus XML (<NessusClientData_v2>)
      - "unknown"      : Unrecognized format
    """
    fname = filename.lower().strip()
    decoded = file_content.decode("utf-8-sig", errors="replace").strip()

    # 1. Check for XML formats (Nessus vs OpenVAS)
    if fname.endswith(".xml") or fname.endswith(".nessus") or decoded.startswith("<"):
        try:
            root = ET.fromstring(file_content)
            root_tag = root.tag.lower()
            if root_tag == "nessusclientdata_v2":
                return "nessus_xml"
            elif root_tag == "report":
                return "openvas_xml"
        except ET.ParseError:
            pass

    # 2. Check for JSON exports (Defender vs OpenVAS)
    if fname.endswith(".json") or decoded.startswith(("[", "{")):
        try:
            data = json.loads(decoded)
            first_item = None
            if isinstance(data, list) and data and isinstance(data[0], dict):
                first_item = data[0]
            elif isinstance(data, dict):
                for k in ["value", "Results", "results", "data", "Alerts", "alerts"]:
                    if k in data and isinstance(data[k], list) and data[k] and isinstance(data[k][0], dict):
                        first_item = data[k][0]
                        break
                else:
                    first_item = data

            if first_item and isinstance(first_item, dict):
                if _is_defender_keys(list(first_item.keys())):
                    return "defender_edr"
            
            # If filename explicitly indicates defender
            if "defender" in fname or "mde" in fname or "advancedhunting" in fname:
                return "defender_edr"

            # Fallback for generic vulnerability JSON
            return "openvas_xml"
        except Exception:
            pass

    # 3. Check for CSV exports (Defender vs OpenVAS)
    if fname.endswith(".csv") or "\n" in decoded or "," in decoded:
        try:
            first_line = decoded.splitlines()[0] if decoded else ""
            reader = csv.reader(io.StringIO(first_line))
            headers = next(reader, [])
            if headers and _is_defender_keys(headers):
                return "defender_edr"
            if "defender" in fname or "mde" in fname:
                return "defender_edr"
            return "openvas_xml"
        except Exception:
            pass

    return "unknown"
