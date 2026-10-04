"""
Generic Configurable Vendor Connector for CRISP.
Parses scanner reports based on human-confirmed field mapping configurations.
Reuses field navigation logic from sniffer.py.
"""
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from defusedxml import ElementTree as ET
from xml.etree.ElementTree import Element
import csv
import io
import json
import logging
import re
from app.connectors.base import BaseConnector
from app.connectors.sniffer import extract_field_value, _xml_nodes_for_path, _scalar_values

logger = logging.getLogger(__name__)


class GenericVendorConnector(BaseConnector):
    """
    Generic configurable connector driven by a saved vendor JSON configuration.
    Extracts findings in CRISP standard canonical shape:
    {
      "id": str,
      "asset_id": str,
      "cve_id": Optional[str],
      "cvss": Optional[float],
      "severity": str,
      "port": Optional[int],
      "issue_type": Optional[str],
      "first_seen": str,
      "last_seen": str,
      "source": str
    }
    """
    def __init__(self, vendor_config: Dict[str, Any]):
        self.config = vendor_config
        self.vendor_name = vendor_config.get("vendor_name", "Custom Vendor")
        self.vendor_slug = vendor_config.get("vendor_slug", "custom")
        self.format = vendor_config.get("format", "json").lower()
        self.record_path = vendor_config.get("record_path", "")
        self.field_mapping = vendor_config.get("field_mapping", {})

    def fetch(self) -> Dict[str, Any]:
        return {
            "source": self.vendor_name,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    def normalize(self, raw_data: Any) -> List[Dict[str, Any]]:
        return raw_data if isinstance(raw_data, list) else []

    def _extract_records_from_xml(self, content: bytes) -> List[Element]:
        """Finds all record elements matching the configured record path."""
        root = ET.fromstring(content)
        if not self.record_path:
            return list(root)

        # Path might be "report.results.result" -> search by tag or subpath
        leaf_tag = self.record_path.split(".")[-1]

        # Try relative search from root
        # If root tag is first part of record_path, strip it
        parts = self.record_path.split(".")
        root_tag = root.tag.split("}")[-1]
        if parts and parts[0] == root_tag:
            subpath = "/".join(parts[1:])
            records = _xml_nodes_for_path(root, parts[1:]) if subpath else [root]
            if records:
                return records

        records = [node for node in root.iter() if node.tag.split("}")[-1] == leaf_tag]
        return records

    def _extract_records_from_json(self, content: bytes) -> List[Dict[str, Any]]:
        """Finds all record dicts matching the configured record path."""
        text = content.decode("utf-8-sig", errors="ignore").strip()
        data = json.loads(text)

        if not self.record_path or self.record_path in ["root", "$"]:
            if isinstance(data, list):
                return data
            return [data] if isinstance(data, dict) else []

        # Traverse dot path in JSON
        curr = data
        for part in self.record_path.split("."):
            if isinstance(curr, dict) and part in curr:
                curr = curr[part]
            else:
                return []

        if isinstance(curr, list):
            return curr
        return [curr] if isinstance(curr, dict) else []

    def _extract_records_from_csv(self, content: bytes) -> List[Dict[str, Any]]:
        """Parses CSV into list of row dictionaries."""
        text = content.decode("utf-8-sig", errors="ignore").strip()
        f_io = io.StringIO(text)
        first_line = f_io.readline()
        f_io.seek(0)
        delimiter = ","
        if "\t" in first_line and first_line.count("\t") > first_line.count(","):
            delimiter = "\t"
        elif ";" in first_line and first_line.count(";") > first_line.count(","):
            delimiter = ";"

        reader = csv.DictReader(f_io, delimiter=delimiter)
        if reader.fieldnames:
            reader.fieldnames = [name.strip() for name in reader.fieldnames]
        return list(reader)

    def parse(self, file_content: bytes, finding_id_offset: int = 0) -> Dict[str, Any]:
        """
        Parses uploaded file using configured mapping.
        Returns:
          {
            "findings": List[Dict[str, Any]],
            "skipped": int,
            "skip_reasons": List[str]
          }
        Never substitutes fake values — records with missing required fields are skipped.
        """
        findings = []
        skipped = 0
        skip_reasons = []

        try:
            if self.format == "xml":
                records = self._extract_records_from_xml(file_content)
            elif self.format == "json":
                records = self._extract_records_from_json(file_content)
            elif self.format == "csv":
                records = self._extract_records_from_csv(file_content)
            else:
                return {
                    "findings": [],
                    "skipped": 0,
                    "skip_reasons": [f"Unsupported format '{self.format}' in vendor configuration"]
                }
        except Exception as e:
            return {
                "findings": [],
                "skipped": 0,
                "skip_reasons": [f"Error extracting records: {str(e)}"]
            }

        now_iso = datetime.now(timezone.utc).isoformat()
        prefix = self.vendor_slug.replace("-", "_").upper()[:4]

        for idx, rec in enumerate(records):
            record_num = idx + 1

            # 1. Asset ID (Required)
            raw_asset = extract_field_value(rec, self.field_mapping.get("asset_id"))
            if not raw_asset or not str(raw_asset).strip():
                reason = f"Record #{record_num}: missing required field 'asset_id' at path '{self.field_mapping.get('asset_id')}'"
                skipped += 1
                skip_reasons.append(reason)
                continue
            asset_id = str(raw_asset).strip()

            # 2. Severity (Required)
            raw_sev = extract_field_value(rec, self.field_mapping.get("severity"))
            if raw_sev is None or not str(raw_sev).strip():
                reason = f"Record #{record_num} on asset {asset_id}: missing required field 'severity' at path '{self.field_mapping.get('severity')}'"
                skipped += 1
                skip_reasons.append(reason)
                continue
            severity_str = str(raw_sev).strip().capitalize()
            severity_map = {
                "Critical": "Critical", "High": "High", "Medium": "Medium",
                "Low": "Low", "Info": "Info", "Information": "Info", "Informational": "Info", "Log": "Info", "Moderate": "Medium",
                "4": "Critical", "3": "High", "2": "Medium", "1": "Low", "0": "Info"
            }
            severity = severity_map.get(severity_str)
            if severity is None:
                skipped += 1
                skip_reasons.append(f"Record #{record_num}: unrecognized severity at path '{self.field_mapping.get('severity')}'")
                continue

            # 3. CVE ID (Optional if issue_type is present)
            raw_cve = extract_field_value(rec, self.field_mapping.get("cve_id"))
            cve_ids = list(dict.fromkeys(match.upper() for value in _scalar_values(raw_cve)
                                        for match in re.findall(r"\bCVE-\d{4}-\d{4,}\b", str(value), re.IGNORECASE)))

            # 4. Issue Type (Optional / used for non-CVE findings)
            raw_issue = extract_field_value(rec, self.field_mapping.get("issue_type"))
            issue_type = str(raw_issue).strip() if raw_issue and str(raw_issue).strip() else None

            # Must have at least cve_id OR issue_type
            if not cve_ids and not issue_type:
                reason = f"Record #{record_num} on asset {asset_id}: missing both 'cve_id' and 'issue_type'"
                skipped += 1
                skip_reasons.append(reason)
                continue

            # 5. CVSS (Optional)
            raw_cvss = extract_field_value(rec, self.field_mapping.get("cvss"))
            cvss = None
            if raw_cvss is not None and str(raw_cvss).strip():
                try:
                    numeric_cvss = float(str(raw_cvss).strip())
                    cvss = numeric_cvss if 0 <= numeric_cvss <= 10 else None
                except ValueError:
                    cvss = None

            # 6. Port (Optional)
            raw_port = extract_field_value(rec, self.field_mapping.get("port"))
            port = None
            if raw_port is not None and str(raw_port).strip():
                # Extract digits if e.g. "443/tcp"
                port_match = re.search(r"\d+", str(raw_port))
                if port_match:
                    try:
                        port = int(port_match.group(0))
                    except ValueError:
                        port = None

            for cve_id in cve_ids or [None]:
                finding_id = f"FND-{prefix}-{finding_id_offset + len(findings) + 1:03d}"
                findings.append({
                    "id": finding_id,
                    "asset_id": asset_id,
                    "cve_id": cve_id,
                    "cvss": cvss,
                    "severity": severity,
                    "port": port,
                    "issue_type": issue_type,
                    "first_seen": now_iso,
                    "last_seen": now_iso,
                    "source": self.vendor_name
                })

        return {
            "findings": findings,
            "skipped": skipped,
            "skip_reasons": skip_reasons
        }
