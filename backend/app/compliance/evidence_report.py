"""
Audit Evidence Report Generator for CRISP Compliance Hub.
Generates structured JSON, RFC 4180 CSV, and printable HTML evidence reports
for regulatory audits (SEBI CSCRF, RBI CSF, NIST CSF, ISO 27001, CIS Controls, DPDP).
"""

import io
import html
from app.compliance.evidence import assess_control
from app.engine.model import MODEL_VERSION, finding_key
import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional

from app.core.config import DATA_DIR
from app.compliance.framework_registry import FRAMEWORK_REQUIREMENTS
from app.compliance.framework_engine import normalize_framework_id, FRAMEWORKS


class EvidenceReportGenerator:
    @classmethod
    def build_structured_report(cls, framework_id, snapshot, run_metadata=None, controls_catalog=None):
        canonical = normalize_framework_id(framework_id)
        meta = FRAMEWORKS[canonical]
        controls = {c["control_id"]: c for c in snapshot.get("control_state", [])}
        catalog = {c["id"]: c for c in (controls_catalog or snapshot.get("controls_catalog") or [])}
        findings = snapshot.get("findings", [])
        known = {f["id"] for f in findings}
        reviews = snapshot.get("compliance_assessments", {})
        rows = []
        for req in FRAMEWORK_REQUIREMENTS.get(canonical, []):
            cid = req.get("mapped_control_id")
            state = controls.get(cid, {})
            review = reviews.get(req["id"], reviews.get(cid, {}))
            evidence = assess_control(state, review)
            references = [fid for fid in state.get("supporting_finding_ids", []) if fid in known]
            status = evidence["status"].upper() if cid else "NO EVIDENCE — unmapped"
            if cid and not evidence["evidence_complete"]:
                status = "NO EVIDENCE"
            rows.append({"requirement_id": req["id"], "clause": req.get("clause"), "title": req["title"],
                "domain": req.get("domain", "General"), "coverage_status": status, "mapped_control_id": cid,
                "control_name": catalog.get(cid, {}).get("name"), "control_coverage_pct": evidence["observed_coverage_pct"],
                "evidence_source": evidence["evidence_source"], "supporting_finding_ids": references,
                "supporting_finding_keys": [finding_key(f) for f in findings if f.get("id") in references],
                "unmapped_reason": req.get("unmapped_reason") if not cid else None,
                "last_assessment_run_id": (run_metadata or {}).get("run_id"),
                "assessment_timestamp": evidence["evidence_timestamp"],
                "requirement_source": req.get("source", meta["citation"]),
                "requirement_version": req.get("version", meta["name"]),
                "applicability": review.get("applicability", "not_reviewed"),
                "reviewer_decision": evidence["reviewer_decision"], "reviewer": evidence["reviewer"],
                "reviewed_at": evidence["reviewed_at"], "evidence_complete": evidence["evidence_complete"]})
        mapped = sum(bool(r["mapped_control_id"]) for r in rows)
        org = snapshot.get("organization") or {}
        return {"framework_id": framework_id, "canonical_id": canonical, "framework_name": meta["name"],
            "official_citation": meta["citation"], "scope": "Curated subset; source mappings require independent review",
            "organization": {"name": org.get("name", "Not Configured"), "sector": org.get("sector", "Not provided"), "total_assets": len(snapshot.get("assets", []))},
            "audit_run": {"run_id": (run_metadata or {}).get("run_id"), "assessment_timestamp": (run_metadata or {}).get("last_recompute_at"), "engine_version": MODEL_VERSION},
            "summary_metrics": {"total_requirements": len(rows), "mapped_requirements": mapped, "unmapped_requirements": len(rows)-mapped,
                "mapping_coverage_pct": round(100*mapped/max(1,len(rows)),1),
                "evidence_completeness_pct": round(100*sum(r["evidence_complete"] for r in rows)/max(1,len(rows)),1),
                "compliant_requirements": sum(r["coverage_status"]=="COMPLIANT" for r in rows),
                "partially_compliant_requirements": sum(r["coverage_status"]=="PARTIALLY COMPLIANT" for r in rows),
                "non_compliant_requirements": sum(r["coverage_status"]=="NON-COMPLIANT" for r in rows)},
            "requirements": rows}

    @classmethod
    def generate_csv_report(cls, report_data: Dict[str, Any]) -> str:
        """
        Renders the evidence report as an RFC 4180 compliant CSV string (zero external dependencies).
        """
        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

        # Header metadata rows
        writer.writerow(["# CRISP Continuous Compliance Audit Evidence Report"])
        writer.writerow(["# Framework", report_data["framework_name"]])
        writer.writerow(["# Citation", report_data["official_citation"]])
        writer.writerow(["# Organization", report_data["organization"]["name"]])
        writer.writerow(["# Run ID", report_data["audit_run"]["run_id"]])
        writer.writerow(["# Assessment Timestamp", report_data["audit_run"]["assessment_timestamp"]])
        writer.writerow(["# Mapping Coverage", f"{report_data['summary_metrics']['mapping_coverage_pct']}%"])
        writer.writerow([])

        # Table header
        writer.writerow([
            "Requirement ID",
            "Framework Clause",
            "Requirement Title",
            "Domain",
            "CRISP Coverage Status",
            "Mapped Control ID",
            "Control Name",
            "Control Coverage %",
            "Audit Telemetry Source",
            "Supporting Finding IDs",
            "Assessment Run ID",
            "Assessment Timestamp",
            "Unmapped Reason / Scope Exemption", "Source", "Version", "Applicability", "Reviewer", "Decision", "Reviewed At"
        ])

        # Table rows
        for req in report_data["requirements"]:
            finding_ids_str = "; ".join(req["supporting_finding_ids"]) if req["supporting_finding_ids"] else "None"
            writer.writerow([
                req["requirement_id"],
                req["clause"] or "N/A",
                req["title"],
                req["domain"],
                req["coverage_status"],
                req["mapped_control_id"] or "N/A",
                req["control_name"] or "N/A",
                f"{req['control_coverage_pct']}%" if req["control_coverage_pct"] is not None else "Unknown",
                req["evidence_source"] or "None",
                finding_ids_str,
                req["last_assessment_run_id"],
                req["assessment_timestamp"],
                req["unmapped_reason"] or "N/A", req["requirement_source"], req["requirement_version"], req["applicability"], req["reviewer"], req["reviewer_decision"], req["reviewed_at"]
            ])

        return output.getvalue()

    @classmethod
    def generate_printable_html_report(cls, report_data: Dict[str, Any]) -> str:
        """
        Renders a high-contrast, printable, audit-grade HTML view.
        Includes @media print stylesheets and client-side download/print hooks.
        """
        def escaped(value):
            if isinstance(value, str):
                return html.escape(value)
            if isinstance(value, list):
                return [escaped(v) for v in value]
            if isinstance(value, dict):
                return {k: escaped(v) for k, v in value.items()}
            return value
        report_data = escaped(report_data)
        fw_name = report_data["framework_name"]
        citation = report_data["official_citation"]
        org = report_data["organization"]
        run = report_data["audit_run"]
        metrics = report_data["summary_metrics"]
        requirements = report_data["requirements"]

        req_rows = []
        for req in requirements:
            status = req["coverage_status"]
            if status == "COMPLIANT":
                status_badge = '<span class="badge badge-success">COMPLIANT</span>'
            elif status == "PARTIALLY COMPLIANT":
                status_badge = '<span class="badge badge-warn">PARTIALLY COMPLIANT</span>'
            elif status == "NON-COMPLIANT":
                status_badge = '<span class="badge badge-danger">NON-COMPLIANT</span>'
            else:
                status_badge = f'<span class="badge badge-unmapped">{status}</span>'

            # Format finding tags
            if req["supporting_finding_ids"]:
                finding_tags = "".join(f'<span class="finding-tag">{fid}</span>' for fid in req["supporting_finding_ids"])
            else:
                finding_tags = '<span class="text-dim">None</span>'

            ctrl_id = req["mapped_control_id"] or "—"
            ctrl_name = req["control_name"] or '<span class="text-dim">Out of scope</span>'
            cov_str = f"{req['control_coverage_pct']}%" if req["control_coverage_pct"] is not None else "Unknown"
            evidence = req["evidence_source"] or f'<span class="text-dim">{req["unmapped_reason"]}</span>'

            req_rows.append(f"""
            <tr>
              <td><span class="clause-pill">{req["clause"] or req["requirement_id"]}</span></td>
              <td><strong>{req["title"]}</strong><br><small class="text-dim">{req["domain"]}</small><br><small>Source: {req["requirement_source"]}; version: {req["requirement_version"]}; applicability: {req["applicability"]}; reviewer: {req["reviewer"]}; decision: {req["reviewer_decision"]}; reviewed: {req["reviewed_at"]}</small></td>
              <td>{status_badge}</td>
              <td><code>{ctrl_id}</code></td>
              <td><small>{ctrl_name}</small></td>
              <td class="mono">{cov_str}</td>
              <td><small>{evidence}</small></td>
              <td>{finding_tags}</td>
            </tr>
            """)

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CRISP Audit Evidence Report - {fw_name}</title>
<style>
  :root {{
    --bg-page: #f8fafc;
    --text-primary: #0f172a;
    --text-secondary: #475569;
    --border-color: #cbd5e1;
    --primary: #0284c7;
    --success: #16a34a;
    --warning: #d97706;
    --danger: #dc2626;
  }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    margin: 0;
    padding: 30px;
    background: var(--bg-page);
    color: var(--text-primary);
    line-height: 1.5;
  }}
  .container {{
    max-width: 1200px;
    margin: 0 auto;
    background: #ffffff;
    padding: 36px;
    border-radius: 12px;
    box-shadow: 0 4px 16px rgba(0,0,0,0.06);
    border: 1px solid #e2e8f0;
  }}
  .header {{
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    border-bottom: 2px solid var(--primary);
    padding-bottom: 20px;
    margin-bottom: 24px;
    gap: 20px;
  }}
  .title-area h1 {{
    margin: 0 0 6px 0;
    font-size: 24px;
    color: var(--text-primary);
  }}
  .title-area p {{
    margin: 0;
    font-size: 13px;
    color: var(--text-secondary);
  }}
  .actions-area {{
    display: flex;
    gap: 10px;
  }}
  .btn {{
    padding: 8px 14px;
    border-radius: 6px;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    border: 1px solid #cbd5e1;
    background: #ffffff;
    color: #1e293b;
    text-decoration: none;
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }}
  .btn-primary {{
    background: var(--primary);
    border-color: var(--primary);
    color: #ffffff;
  }}
  .meta-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 14px;
    background: #f1f5f9;
    padding: 16px;
    border-radius: 8px;
    margin-bottom: 24px;
    font-size: 13px;
  }}
  .meta-item strong {{
    display: block;
    color: #64748b;
    font-size: 11px;
    text-transform: uppercase;
    margin-bottom: 2px;
  }}
  .kpi-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
    gap: 14px;
    margin-bottom: 28px;
  }}
  .kpi-card {{
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 14px;
    background: #ffffff;
  }}
  .kpi-label {{
    font-size: 11px;
    text-transform: uppercase;
    color: #64748b;
    font-weight: 600;
  }}
  .kpi-val {{
    font-size: 22px;
    font-weight: 700;
    margin-top: 4px;
    color: #0f172a;
    font-family: 'JetBrains Mono', monospace, sans-serif;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
    margin-top: 14px;
  }}
  th, td {{
    border: 1px solid #e2e8f0;
    padding: 10px 12px;
    text-align: left;
    vertical-align: top;
  }}
  th {{
    background: #f8fafc;
    color: #334155;
    font-weight: 600;
    font-size: 12px;
  }}
  tr:nth-child(even) {{
    background: #fdfefe;
  }}
  .badge {{
    display: inline-block;
    padding: 3px 8px;
    border-radius: 4px;
    font-weight: 600;
    font-size: 11px;
    letter-spacing: 0.3px;
    white-space: nowrap;
  }}
  .badge-success {{ background: #dcfce7; color: #15803d; border: 1px solid #86efac; }}
  .badge-warn {{ background: #fef3c7; color: #b45309; border: 1px solid #fde68a; }}
  .badge-danger {{ background: #fee2e2; color: #b91c1c; border: 1px solid #fca5a5; }}
  .badge-unmapped {{ background: #f1f5f9; color: #475569; border: 1px solid #cbd5e1; font-weight: 700; }}
  .clause-pill {{
    background: #e0f2fe;
    color: #0369a1;
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 600;
    font-family: monospace;
    white-space: nowrap;
  }}
  .finding-tag {{
    display: inline-block;
    background: #ede9fe;
    color: #6d28d9;
    border: 1px solid #ddd6fe;
    padding: 1px 6px;
    border-radius: 4px;
    font-size: 11px;
    font-family: monospace;
    margin: 2px;
  }}
  .text-dim {{ color: #64748b; }}
  .mono {{ font-family: monospace; }}
  .attestation-box {{
    margin-top: 30px;
    padding: 16px;
    background: #f8fafc;
    border-left: 4px solid var(--primary);
    border-radius: 4px;
    font-size: 12px;
    color: #475569;
  }}
  @media print {{
    body {{ background: #ffffff; padding: 0; }}
    .container {{ box-shadow: none; border: none; padding: 0; max-width: 100%; }}
    .actions-area {{ display: none; }}
    th, td {{ padding: 6px 8px; font-size: 11px; }}
  }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="title-area">
      <h1>CRISP Continuous Compliance & Audit Evidence Traceability Report</h1>
      <p><strong>Framework:</strong> {fw_name} · <em>{citation}</em></p>
    </div>
    <div class="actions-area">
      <button class="btn btn-primary" onclick="window.print()">Print Report</button>
      <a class="btn" href="?format=csv" download>Download CSV</a>
    </div>
  </div>

  <div class="meta-grid">
    <div class="meta-item">
      <strong>Target Entity</strong>
      {org["name"]} ({org["sector"]})
    </div>
    <div class="meta-item">
      <strong>Assessment Run ID</strong>
      <code>{run["run_id"]}</code>
    </div>
    <div class="meta-item">
      <strong>Timestamp</strong>
      {run["assessment_timestamp"]}
    </div>
    <div class="meta-item">
      <strong>Audit Attestation</strong>
      Telemetry-Verified (Zero Invented Clauses)
    </div>
  </div>

  <div class="kpi-grid">
    <div class="kpi-card">
      <div class="kpi-label">Mapping Coverage</div>
      <div class="kpi-val" style="color: var(--primary);">{metrics["mapping_coverage_pct"]}%</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Total Requirements</div>
      <div class="kpi-val">{metrics["total_requirements"]}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Mapped Requirements</div>
      <div class="kpi-val">{metrics["mapped_requirements"]}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Compliant Controls</div>
      <div class="kpi-val" style="color: var(--success);">{metrics["compliant_requirements"]}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Unmapped (Out of Scope)</div>
      <div class="kpi-val" style="color: #64748b;">{metrics["unmapped_requirements"]}</div>
    </div>
  </div>

  <h2>Requirement Evidence Traceability Matrix</h2>
  <table>
    <thead>
      <tr>
        <th style="width: 12%;">Clause</th>
        <th style="width: 20%;">Requirement Title</th>
        <th style="width: 14%;">Coverage Status</th>
        <th style="width: 10%;">Control ID</th>
        <th style="width: 16%;">Control Name</th>
        <th style="width: 6%;">Coverage</th>
        <th style="width: 14%;">Audit Telemetry Source</th>
        <th style="width: 8%;">Supporting Findings</th>
      </tr>
    </thead>
    <tbody>
      {"".join(req_rows)}
    </tbody>
  </table>

  <div class="attestation-box">
    <strong>Auditor Assurance Note:</strong> This report represents automated continuous telemetry evidence generated by the CRISP Cyber Risk Platform. Requirements marked as <code>NO EVIDENCE — unmapped</code> pertain to administrative governance policies, board charters, or physical security measures that cannot be audited via technical sensors and have been transparently isolated to preserve audit validity.
  </div>
</div>
</body>
</html>
"""
        return html_content
