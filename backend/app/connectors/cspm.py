"""
CSPM Connector for CRISP.
Parses Prowler JSON exports into CRISP's standard Finding canonical model.
"""
from typing import Dict, Any, List
from datetime import datetime, timezone
import json
import logging
from app.connectors.base import BaseConnector

logger = logging.getLogger(__name__)


class ProwlerConnector(BaseConnector):
    """
    Prowler Cloud Security Posture Management (CSPM) Connector.
    Parses Prowler JSON outputs, extracting FAIL-status checks into standard findings.
    
    Prowler JSON finding structure:
      {
        "Findings": [
          {
            "CheckID": "s3_bucket_public_access",
            "Status": "FAIL",
            "Severity": "high",
            "ResourceArn": "arn:aws:s3:::crisp-customer-data",
            "Region": "ap-south-1",
            "StatusExtended": "S3 bucket crisp-customer-data has public access enabled"
          }
        ]
      }
    """
    def __init__(self):
        pass

    def fetch(self) -> Dict[str, Any]:
        return {
            "source": "Prowler CSPM",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    def normalize(self, raw_data: Any) -> List[Dict[str, Any]]:
        findings = []
        if isinstance(raw_data, list):
            for idx, item in enumerate(raw_data):
                findings.append({
                    "id": item.get("id", f"FND-CSPM-{idx+1:03d}"),
                    "asset_id": item.get("asset_id", "AWS-CLOUD-ENV"),
                    "cve_id": None,
                    "issue_type": item.get("issue_type", "misconfiguration"),
                    "cvss": None,
                    "severity": item.get("severity", "High"),
                    "port": None,
                    "first_seen": item.get("first_seen", datetime.now(timezone.utc).isoformat()),
                    "last_seen": item.get("last_seen", datetime.now(timezone.utc).isoformat()),
                    "source": "Prowler CSPM"
                })
        return findings

    def parse(self, json_report_content: bytes, finding_id_offset: int = 0) -> Dict[str, Any]:
        """
        Parses a Prowler JSON export into standard findings.
        Filters for Status == 'FAIL'.
        Returns { "findings": [...], "skipped": int, "skip_reasons": [...] }
        """
        new_findings = []
        skipped = 0
        skip_reasons = []

        try:
            text = json_report_content.decode("utf-8", errors="ignore").strip()
            data = json.loads(text)
        except Exception as e:
            return {"findings": [], "skipped": 0, "skip_reasons": [f"JSON parse error: {e}"]}

        # Support both {"Findings": [...]} and top-level list
        if isinstance(data, dict):
            items = data.get("Findings", [])
        elif isinstance(data, list):
            items = data
        else:
            return {"findings": [], "skipped": 0, "skip_reasons": ["Unrecognized Prowler JSON root structure"]}

        item_idx = 0
        now_iso = datetime.now(timezone.utc).isoformat()

        for item in items:
            item_idx += 1
            if not isinstance(item, dict):
                skipped += 1
                skip_reasons.append(f"Finding #{item_idx} is not a valid object")
                continue

            status = str(item.get("Status", "")).strip().upper()
            check_id = item.get("CheckID")
            resource_arn = item.get("ResourceArn") or item.get("ResourceId") or item.get("ResourceUid")
            raw_severity = str(item.get("Severity", "medium")).strip().lower()

            # Map severity to title case: low, medium, high, critical
            severity_map = {
                "critical": "Critical",
                "high": "High",
                "medium": "Medium",
                "low": "Low",
                "informational": "Info",
                "info": "Info"
            }
            severity = severity_map.get(raw_severity, "Medium")

            # Only process FAIL-status findings
            if status != "FAIL":
                # We skip PASS, MUTED, INFO, etc.
                continue

            if not check_id or not str(check_id).strip():
                reason = f"Finding #{item_idx}: missing CheckID"
                skip_reasons.append(reason)
                logger.warning(f"Prowler parse skipped: {reason}")
                skipped += 1
                continue

            if not resource_arn or not str(resource_arn).strip():
                reason = f"Finding #{item_idx} ({check_id}): missing ResourceArn"
                skip_reasons.append(reason)
                logger.warning(f"Prowler parse skipped: {reason}")
                skipped += 1
                continue

            asset_id = str(resource_arn).strip()

            new_findings.append({
                "id": f"FND-CSPM-{finding_id_offset + len(new_findings) + 1:03d}",
                "asset_id": asset_id,
                "cve_id": None,
                "issue_type": str(check_id).strip(),
                "cvss": None,
                "severity": severity,
                "port": None,
                "first_seen": now_iso,
                "last_seen": now_iso,
                "source": "Prowler CSPM",
                "description": item.get("StatusExtended") or f"Prowler check {check_id} failed on {asset_id}"
            })

        return {
            "findings": new_findings,
            "skipped": skipped,
            "skip_reasons": skip_reasons
        }
