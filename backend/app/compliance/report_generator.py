from typing import Dict, Any
from datetime import datetime, timezone
from html import escape

class ReportGenerator:
    @staticmethod
    def generate_html_report(eval_data: Dict[str, Any], org_name: str = "Organization not configured") -> str:
        """
        Generates an audit-ready, beautifully styled HTML compliance evidence report.
        """
        def escaped(value):
            if isinstance(value, str):
                return escape(value)
            if isinstance(value, dict):
                return {k: escaped(v) for k, v in value.items()}
            if isinstance(value, list):
                return [escaped(v) for v in value]
            return value
        eval_data = escaped(eval_data)
        org_name = escape(org_name)
        fw_name = eval_data.get("framework_name", "Compliance Framework")
        cov_pct = eval_data.get("overall_coverage_pct", 0.0)
        compliant_n = eval_data.get("compliant_controls", 0)
        total_n = eval_data.get("total_controls_mapped", 0)
        gaps = eval_data.get("gaps", [])
        controls = eval_data.get("controls", [])
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        # HTML formatting
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>CRISP Compliance Evidence Report - {fw_name}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; color: #1e293b; background: #fff; line-height: 1.5; }}
  .header {{ border-bottom: 2px solid #0284c7; padding-bottom: 20px; margin-bottom: 30px; }}
  .header h1 {{ margin: 0 0 8px 0; color: #0f172a; font-size: 26px; }}
  .header .meta {{ color: #64748b; font-size: 14px; }}
  .badge {{ display: inline-block; padding: 4px 10px; border-radius: 6px; font-weight: 600; font-size: 13px; }}
  .badge-success {{ background: #dcfce7; color: #15803d; }}
  .badge-warn {{ background: #fef9c3; color: #a16207; }}
  .badge-danger {{ background: #fee2e2; color: #b91c1c; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 32px; }}
  .card {{ border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; background: #f8fafc; }}
  .card .label {{ font-size: 12px; text-transform: uppercase; color: #64748b; font-weight: 600; }}
  .card .value {{ font-size: 24px; font-weight: 700; color: #0f172a; margin-top: 6px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 14px; }}
  th, td {{ border: 1px solid #e2e8f0; padding: 10px 12px; text-align: left; }}
  th {{ background: #f1f5f9; color: #334155; font-weight: 600; }}
  tr:nth-child(even) {{ background: #f8fafc; }}
  .disclaimer {{ background: #f8fafc; border-left: 4px solid #0284c7; padding: 14px; font-size: 13px; color: #475569; margin-top: 30px; }}
  .sim-tag {{ font-size: 10px; background: #f1f5f9; border: 1px solid #cbd5e1; color: #475569; padding: 2px 5px; border-radius: 4px; }}
</style>
</head>
<body>
  <div class="header">
    <h1>CRISP Continuous Compliance & Evidence Report</h1>
    <div class="meta">
      <strong>Target Organization:</strong> {org_name} |
      <strong>Framework:</strong> {fw_name} |
      <strong>Generated:</strong> {ts}
    </div>
  </div>

  <div class="summary-grid">
    <div class="card">
      <div class="label">Overall Coverage</div>
      <div class="value">{cov_pct}%</div>
    </div>
    <div class="card">
      <div class="label">Controls Assessed</div>
      <div class="value">{total_n}</div>
    </div>
    <div class="card">
      <div class="label">Compliant Controls</div>
      <div class="value">{compliant_n}</div>
    </div>
    <div class="card">
      <div class="label">Identified Gaps</div>
      <div class="value" style="color: #b91c1c;">{len(gaps)}</div>
    </div>
  </div>

  <h2>Control Assessment & Evidence Registry</h2>
  <table>
    <thead>
      <tr>
        <th>Control ID</th>
        <th>Control Name</th>
        <th>Framework Requirement</th>
        <th>Coverage</th>
        <th>Status</th>
        <th>Audit Telemetry / Evidence Reference</th>
      </tr>
    </thead>
    <tbody>
"""
        for c in controls:
            status_cls = "badge-success" if c["status"] == "Compliant" else ("badge-warn" if c["status"] == "Partially Compliant" else "badge-danger")
            sim_badge = "<span class='sim-tag'>SIMULATED</span>" if c["is_simulated"] else "<span class='sim-tag' style='background:#e0f2fe; color:#0369a1;'>LIVE LAB</span>"
            html += f"""
      <tr>
        <td><strong>{c['control_id']}</strong></td>
        <td>{c['name']}</td>
        <td><small>{c['framework_clause']}</small></td>
        <td>{c['coverage_pct']}%</td>
        <td><span class="badge {status_cls}">{c['status']}</span></td>
        <td>{c['evidence_ref']} {sim_badge}</td>
      </tr>
"""

        html += f"""
    </tbody>
  </table>

  <h2>Identified Deficiencies & Prioritized Remedies</h2>
  <table>
    <thead>
      <tr>
        <th>Deficient Control</th>
        <th>Clause</th>
        <th>Current Coverage</th>
        <th>Target</th>
        <th>Estimated Remediation Capex + Opex</th>
      </tr>
    </thead>
    <tbody>
"""
        for g in gaps:
            html += f"""
      <tr>
        <td>{g['name']}</td>
        <td><small>{g['framework_clause']}</small></td>
        <td>{g['current_coverage_pct']}%</td>
        <td>70.0%</td>
        <td>₹{g['remediation_cost']:,.2f}</td>
      </tr>
"""

        html += f"""
    </tbody>
  </table>

  <div class="disclaimer">
    <strong>Regulatory Disclaimer:</strong> {eval_data.get('disclaimer')}<br>
    <strong>Source Citation:</strong> {eval_data.get('citation')}
  </div>
</body>
</html>
"""
        return html
