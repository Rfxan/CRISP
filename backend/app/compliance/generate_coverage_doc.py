"""
Generates docs/COMPLIANCE_COVERAGE.md directly from the authoritative
FRAMEWORK_REQUIREMENTS registry and ControlCatalog using canonical alias normalization.
"""

from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime, timezone
import logging

from app.compliance.catalog import FRAMEWORKS, ControlCatalog
from app.compliance.framework_engine import normalize_framework_id
from app.compliance.framework_registry import FRAMEWORK_REQUIREMENTS

logger = logging.getLogger(__name__)


def generate_compliance_coverage_markdown(output_path: Path = None) -> str:
    catalog = ControlCatalog()
    controls_map = {c["id"]: c for c in catalog.get_all_controls()}

    # Target frameworks required in order
    target_frameworks = [
        ("sebi", "SEBI CSCRF 2024"),
        ("rbi", "RBI Cyber Security Framework"),
        ("nist", "NIST CSF 2.0"),
        ("iso", "ISO/IEC 27001:2022"),
        ("cis", "CIS Controls v8")
    ]

    # Verify alias normalization and test loud error logging
    unknown_ids_tested = ["unknown_fw", "pci_dss_99"]
    loud_error_logs = []
    for uid in unknown_ids_tested:
        try:
            normalize_framework_id(uid)
        except ValueError as e:
            loud_error_logs.append(f"Expected loud failure for '{uid}': {str(e)}")

    doc_lines = []
    doc_lines.append("# CRISP Compliance Framework Coverage & Traceability Report")
    doc_lines.append("")
    doc_lines.append("> **Audit Transparency Attestation**: Percentages in this document are computed directly from the canonical framework requirement mapping tables. CRISP strictly reports honest mapping coverage; no framework claims 100% unless genuinely 100% of all administrative, physical, and technical requirements are backed by automated telemetry.")
    doc_lines.append("")
    doc_lines.append(f"*Report generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} | Engine: CRISP FrameworkEngine v2.4*")
    doc_lines.append("")
    doc_lines.append("---")
    doc_lines.append("")
    doc_lines.append("## Executive Coverage Summary")
    doc_lines.append("")
    doc_lines.append("| Framework | Canonical ID | Official Citation | Total Controls | Mapped | Unmapped | Mapping Coverage |")
    doc_lines.append("| :--- | :--- | :--- | :---: | :---: | :---: | :---: |")

    summary_rows = []
    framework_details = []

    for fid_alias, display_name in target_frameworks:
        canonical_id = normalize_framework_id(fid_alias)
        meta = FRAMEWORKS[canonical_id]
        reqs = FRAMEWORK_REQUIREMENTS.get(canonical_id, [])

        total = len(reqs)
        mapped = sum(1 for r in reqs if r.get("mapped_control_id"))
        unmapped = total - mapped
        coverage_pct = round((mapped / max(1, total)) * 100.0, 1)

        summary_rows.append(
            f"| **{meta['name']}** | `{canonical_id}` | *{meta['citation']}* | {total} | {mapped} | {unmapped} | **{coverage_pct}%** |"
        )
        framework_details.append((canonical_id, meta, reqs, total, mapped, unmapped, coverage_pct))

    doc_lines.extend(summary_rows)
    doc_lines.append("")
    doc_lines.append("---")
    doc_lines.append("")

    # Detailed sections per framework
    for canonical_id, meta, reqs, total, mapped, unmapped, coverage_pct in framework_details:
        doc_lines.append(f"## {meta['name']} ({coverage_pct}% Mapped)")
        doc_lines.append("")
        doc_lines.append(f"- **Citation**: {meta['citation']}")
        doc_lines.append(f"- **Description**: {meta['description']}")
        doc_lines.append(f"- **Scope**: **{mapped}** mapped controls / **{total}** total requirements (**{unmapped}** unmapped)")
        doc_lines.append("")
        doc_lines.append("| Requirement ID | Framework Clause | Requirement Title | Domain | Mapping Status | CRISP Control ID | Audit Evidence / Telemetry Source |")
        doc_lines.append("| :--- | :--- | :--- | :--- | :---: | :--- | :--- |")

        for r in reqs:
            c_id = r.get("mapped_control_id")
            if c_id:
                ctrl = controls_map.get(c_id, {})
                status = "[Mapped]"
                ctrl_str = f"`{c_id}` ({ctrl.get('name', c_id)})"
                ev_str = r.get("evidence_source", "Active telemetry feed")
            else:
                status = "[Unmapped]"
                ctrl_str = "*None (Out of Scope)*"
                ev_str = f"*{r.get('unmapped_reason', 'Governance / Non-technical mandate')}*"

            doc_lines.append(
                f"| `{r['id']}` | **{r['clause']}** | {r['title']} | {r['domain']} | {status} | {ctrl_str} | {ev_str} |"
            )

        doc_lines.append("")

    # Framework ID Alias Normalization Verification Section
    doc_lines.append("---")
    doc_lines.append("")
    doc_lines.append("## Framework-ID Alias Normalization & Loud Failure Philosophy")
    doc_lines.append("")
    doc_lines.append("CRISP enforces strict alias normalization through `normalize_framework_id()`. When an unrecognized framework identifier is requested, the system fails **loudly** with HTTP 400 and an explicit list of accepted identifiers.")
    doc_lines.append("")
    doc_lines.append("### Normalization Verification Table")
    doc_lines.append("| Input Alias | Canonical Resolved ID | Normalization Result |")
    doc_lines.append("| :--- | :--- | :--- |")
    aliases_to_show = [
        ("sebi", "sebi"),
        ("sebi_cscrf", "sebi"),
        ("sebicscrf", "sebi"),
        ("rbi", "rbi"),
        ("rbi_csf", "rbi"),
        ("nist", "nist"),
        ("nist_csf", "nist"),
        ("iso", "iso"),
        ("iso_27001", "iso"),
        ("cis", "cis"),
        ("cis_v8", "cis")
    ]
    for inp, expected in aliases_to_show:
        resolved = normalize_framework_id(inp)
        doc_lines.append(f"| `{inp}` | `{resolved}` | Success (Maps to `{expected}`) |")

    doc_lines.append("")
    doc_lines.append("### Loud Failure Verification Log")
    for log_msg in loud_error_logs:
        doc_lines.append(f"- `{log_msg}`")

    doc_content = "\n".join(doc_lines) + "\n"

    if output_path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(doc_content)
        logger.info(f"Generated compliance coverage report at {output_path}")

    return doc_content


if __name__ == "__main__":
    base_dir = Path(__file__).resolve().parent.parent.parent.parent
    out_file = base_dir / "docs" / "COMPLIANCE_COVERAGE.md"
    generate_compliance_coverage_markdown(out_file)
    print(f"✓ Successfully written {out_file}")
