"""
Microsoft Defender for Endpoint (EDR) Connector for CRISP.
Deterministic parser for Microsoft Defender Advanced Hunting exports (CSV and JSON).

Maps:
  - DeviceName / DeviceId / ComputerName -> asset_id
  - Title / AlertTitle / ActionType + AlertId -> detection title / finding ID
  - Defender Severity -> CRISP canonical severity (Informational/Low/Medium/High/Critical)
  - MITRE ATT&CK technique IDs (e.g., T1059.001) -> mitre_techniques
  - Timestamp -> first_seen / last_seen

Note on CVEs:
  EDR detections represent active endpoint behaviors, process injections, or lateral movement,
  NOT vulnerability scan plugin outputs. EDR detections have NO CVE — we use the standard
  MISCONF-EDR-* convention with cve_id=None. Never invent CVE-shaped IDs.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import csv
import io
import json
import re
import logging
from app.connectors.base import BaseConnector

logger = logging.getLogger(__name__)

# Deterministic severity mapping: Defender severity string -> CRISP canonical severity.
# If an unknown/unrecognized severity is encountered, the parser fails LOUDLY.
DEFENDER_SEVERITY_MAP: Dict[str, str] = {
    "informational": "Info",
    "info": "Info",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "Critical"
}


class DefenderEDRConnector(BaseConnector):
    """
    Microsoft Defender for Endpoint Advanced Hunting Connector.
    Parses both CSV and JSON exports deterministically.
    """

    def __init__(self):
        pass

    def fetch(self) -> Dict[str, Any]:
        return {
            "source": "Microsoft Defender for Endpoint",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    def normalize(self, raw_data: Any) -> List[Dict[str, Any]]:
        if isinstance(raw_data, list):
            res = self._parse_items(raw_data, finding_id_offset=0)
            return res["findings"]
        return []

    def parse(self, content: bytes, filename: str = "defender.csv", finding_id_offset: int = 0) -> Dict[str, Any]:
        """
        Parses Microsoft Defender Advanced Hunting export (CSV or JSON).
        Fails LOUDLY if unmapped severities are encountered.
        """
        fname = filename.lower().strip()
        decoded = content.decode("utf-8-sig", errors="replace").strip()

        if fname.endswith(".json") or decoded.startswith(("[", "{")):
            return self._parse_json(decoded, finding_id_offset)
        else:
            return self._parse_csv(decoded, finding_id_offset)

    def _parse_json(self, text: str, finding_id_offset: int) -> Dict[str, Any]:
        try:
            data = json.loads(text)
        except Exception as e:
            raise ValueError(f"Invalid Microsoft Defender JSON export: {str(e)}")

        # Support array, or wrapping objects like {"value": [...]}, {"Results": [...]}, {"data": [...]}
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            for k in ["value", "Results", "results", "data", "Alerts", "alerts"]:
                if k in data and isinstance(data[k], list):
                    items = data[k]
                    break
            else:
                # Single alert dict
                items = [data]
        else:
            raise ValueError("Unrecognized Microsoft Defender JSON structure: root must be array or object with items.")

        return self._parse_items(items, finding_id_offset, format_name="json")

    def _parse_csv(self, text: str, finding_id_offset: int) -> Dict[str, Any]:
        stream = io.StringIO(text)
        reader = csv.DictReader(stream)
        if not reader.fieldnames:
            raise ValueError("Microsoft Defender CSV export is empty or missing headers.")

        items = list(reader)
        return self._parse_items(items, finding_id_offset, format_name="csv")

    def _parse_items(self, items: List[Dict[str, Any]], finding_id_offset: int, format_name: str = "auto") -> Dict[str, Any]:
        new_findings: List[Dict[str, Any]] = []
        skipped = 0
        skip_reasons: List[str] = []
        now_iso = datetime.now(timezone.utc).isoformat()

        for idx, row in enumerate(items, start=1):
            if not isinstance(row, dict):
                skipped += 1
                skip_reasons.append(f"Row #{idx}: Not a valid record object")
                continue

            # Build case-insensitive lookup
            ci_row = {str(k).strip().lower(): v for k, v in row.items() if k is not None}

            # 1. Resolve Asset / Device Name
            raw_device = (
                ci_row.get("devicename") or
                ci_row.get("computername") or
                ci_row.get("deviceid") or
                ci_row.get("machineid") or
                ci_row.get("host") or
                ""
            )
            device_name = str(raw_device).strip() if raw_device is not None else ""
            if not device_name:
                skipped += 1
                reason = f"Row #{idx}: Missing device/hostname (expected DeviceName, ComputerName, or DeviceId)"
                skip_reasons.append(reason)
                logger.warning(f"Defender parse skipped: {reason}")
                continue

            # 2. Resolve Severity - FAIL LOUDLY if unmapped!
            raw_sev = ci_row.get("severity") or ci_row.get("alertseverity")
            if raw_sev is None:
                raise ValueError(
                    f"Row #{idx} on device '{device_name}' is missing the 'Severity' field. "
                    f"Microsoft Defender exports require a valid Severity value."
                )

            sev_clean = str(raw_sev).strip()
            sev_key = sev_clean.lower()
            if sev_key not in DEFENDER_SEVERITY_MAP:
                allowed_severities = ", ".join(sorted(["Informational", "Low", "Medium", "High", "Critical"]))
                raise ValueError(
                    f"Unmapped Microsoft Defender severity: '{sev_clean}' on device '{device_name}'. "
                    f"Expected one of: {allowed_severities}. Please verify the export."
                )
            mapped_severity = DEFENDER_SEVERITY_MAP[sev_key]

            # 3. Resolve Title & AlertId
            alert_id_val = (
                ci_row.get("alertid") or 
                ci_row.get("id") or 
                ci_row.get("reportid") or 
                f"MDE-{idx:04d}"
            )
            alert_id = str(alert_id_val).strip()

            title_val = (
                ci_row.get("title") or 
                ci_row.get("alerttitle") or 
                ci_row.get("actiontype") or 
                "Endpoint Behavioral Detection"
            )
            title = str(title_val).strip()

            # 4. Resolve MITRE ATT&CK techniques
            mitre_raw = (
                ci_row.get("attacktechniques") or 
                ci_row.get("mitretechniques") or 
                ci_row.get("techniques") or 
                ci_row.get("category") or 
                ""
            )
            techniques = []
            if mitre_raw:
                matches = re.findall(r"T\d{4}(?:\.\d{3})?", str(mitre_raw), re.IGNORECASE)
                techniques = sorted(list({m.upper() for m in matches}))

            # 5. Resolve Timestamp
            raw_ts = (
                ci_row.get("timestamp") or 
                ci_row.get("timegenerated") or 
                ci_row.get("eventtime") or 
                ci_row.get("creationtime")
            )
            ts_str = str(raw_ts).strip() if raw_ts else now_iso

            # Format finding description
            desc_details = ci_row.get("description") or ci_row.get("alertdescription")
            if desc_details:
                desc = str(desc_details).strip()
            else:
                desc = f"Microsoft Defender detection: {title} (Alert: {alert_id})"
            if techniques:
                desc += f" [MITRE ATT&CK: {', '.join(techniques)}]"

            # Construct normalized finding
            finding_num = finding_id_offset + len(new_findings) + 1
            finding_id = f"FND-EDR-{finding_num:03d}"
            issue_type = f"MISCONF-EDR-{alert_id}" if alert_id else f"MISCONF-EDR-{title.replace(' ', '_')}"

            finding: Dict[str, Any] = {
                "id": finding_id,
                "asset_id": device_name,
                "cve_id": None,  # EDR detections have no CVE — strictly None
                "issue_type": issue_type,
                "cvss": None,
                "severity": mapped_severity,
                "port": None,
                "first_seen": ts_str,
                "last_seen": ts_str,
                "source": "Microsoft Defender for Endpoint",
                "description": desc,
                "mitre_techniques": techniques,
                "alert_id": alert_id
            }

            new_findings.append(finding)

        return {
            "findings": new_findings,
            "skipped": skipped,
            "skip_reasons": skip_reasons,
            "format": format_name
        }
