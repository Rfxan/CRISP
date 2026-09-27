"""
Scan format auto-detection for CRISP ingestion pipeline.
Inspects actual file content (XML root tags), not just file extensions,
to distinguish between scanner formats.
"""
import xml.etree.ElementTree as ET
from typing import Optional


def detect_scan_format(file_content: bytes, filename: str) -> str:
    """
    Detects the scan report format from file content and filename.
    Returns one of: "openvas_xml", "nessus_xml", "unknown".
    
    Detection inspects the actual root XML tag:
      - OpenVAS reports use <report> as root
      - Nessus .nessus files use <NessusClientData_v2> as root
    Extension alone can't distinguish them since both are XML.
    """
    fname = filename.lower().strip()

    # JSON files are assumed to be pre-formatted or OpenVAS JSON exports
    if fname.endswith(".json"):
        return "openvas_xml"  # JSON is handled by OpenVAS connector

    # CSV files are assumed to be OpenVAS CSV exports
    if fname.endswith(".csv"):
        return "openvas_xml"  # CSV is handled by OpenVAS connector

    # XML files: inspect root tag to determine format
    if fname.endswith(".xml") or fname.endswith(".nessus"):
        try:
            # Parse just enough to find the root tag
            root = ET.fromstring(file_content)
            root_tag = root.tag.lower()

            if root_tag == "nessusclientdata_v2":
                return "nessus_xml"
            elif root_tag == "report":
                return "openvas_xml"
            else:
                # Unknown XML root — could be another scanner
                return "unknown"
        except ET.ParseError:
            return "unknown"

    return "unknown"
