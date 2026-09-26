from typing import Dict, Any, List
from app.compliance.catalog import ControlCatalog, FRAMEWORKS

class FrameworkEngine:
    def __init__(self, catalog: ControlCatalog = None):
        self.catalog = catalog or ControlCatalog()

    def evaluate_framework(self, framework_id: str, control_states: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Evaluates organizational compliance and evidence coverage for a target framework.
        """
        fw_meta = FRAMEWORKS.get(framework_id.lower(), FRAMEWORKS["sebi"])
        state_map = {cs["control_id"]: cs for cs in control_states}

        framework_controls = []
        covered_count = 0
        total_mapped = 0
        total_coverage_sum = 0.0

        gaps = []

        for ctrl in self.catalog.get_all_controls():
            c_id = ctrl["id"]
            fw_mapping = ctrl.get("frameworks", {}).get(framework_id.lower())
            if not fw_mapping:
                continue

            total_mapped += 1
            cs = state_map.get(c_id, {})
            cov_pct = cs.get("coverage_pct", 0.0)
            is_covered = cov_pct >= 70.0
            if is_covered:
                covered_count += 1
            total_coverage_sum += cov_pct

            ctrl_eval = {
                "control_id": c_id,
                "name": ctrl["name"],
                "framework_clause": fw_mapping,
                "coverage_pct": cov_pct,
                "status": "Compliant" if cov_pct >= 75.0 else ("Partially Compliant" if cov_pct >= 50.0 else "Non-Compliant"),
                "evidence_ref": cs.get("evidence_ref", "No telemetry evidence linked"),
                "is_simulated": cs.get("is_simulated", False)
            }
            framework_controls.append(ctrl_eval)

            if cov_pct < 70.0:
                cost = ctrl.get("capex", 0.0) + ctrl.get("annual_cost", 0.0)
                gaps.append({
                    "control_id": c_id,
                    "name": ctrl["name"],
                    "framework_clause": fw_mapping,
                    "current_coverage_pct": cov_pct,
                    "gap_shortfall_pct": round(70.0 - cov_pct, 1),
                    "remediation_cost": cost,
                    "mitigates": ctrl.get("mitigates", [])
                })

        overall_coverage = round(total_coverage_sum / max(1, total_mapped), 1) if total_mapped > 0 else 0.0
        gaps.sort(key=lambda g: g["remediation_cost"])

        # Special Regulatory Readiness Modules
        sebi_6h_readiness = self._check_sebi_6h_readiness(state_map)
        dpdp_readiness = self._check_dpdp_readiness(state_map)

        return {
            "framework_id": framework_id,
            "framework_name": fw_meta["name"],
            "description": fw_meta["description"],
            "citation": fw_meta["citation"],
            "disclaimer": "Indicative mapping for simulation and readiness assessment. Not an official regulatory certification.",
            "overall_coverage_pct": overall_coverage,
            "total_controls_mapped": total_mapped,
            "compliant_controls": covered_count,
            "gaps_count": len(gaps),
            "controls": framework_controls,
            "gaps": gaps,
            "sebi_6hour_readiness": sebi_6h_readiness,
            "dpdp_readiness": dpdp_readiness
        }

    def _check_sebi_6h_readiness(self, state_map: Dict[str, Any]) -> Dict[str, Any]:
        """
        Assesses SEBI CSCRF 6-hour incident detection, triage, and reporting capability.
        Mandated by SEBI Circular dated 20 Aug 2024.
        """
        siem_cov = state_map.get("CTRL-SIEM-01", {}).get("coverage_pct", 0.0)
        edr_cov = state_map.get("CTRL-EDR-01", {}).get("coverage_pct", 0.0)
        ir_cov = state_map.get("CTRL-IR-01", {}).get("coverage_pct", 0.0)

        readiness_score = round((siem_cov * 0.4) + (edr_cov * 0.3) + (ir_cov * 0.3), 1)
        is_ready = readiness_score >= 80.0

        return {
            "requirement": "SEBI CSCRF 6-Hour Incident Notification Mandate",
            "readiness_score_pct": readiness_score,
            "status": "READY" if is_ready else "AT RISK",
            "checklist": [
                {"item": "SIEM & SOC 24/7 Continuous Alert Telemetry", "coverage_pct": siem_cov, "pass": siem_cov >= 75},
                {"item": "EDR Active Host Containment & Process Forensics", "coverage_pct": edr_cov, "pass": edr_cov >= 90},
                {"item": "CERT-In / SEBI Playbook SLA & Retainer On-Call", "coverage_pct": ir_cov, "pass": ir_cov >= 75}
            ],
            "recommendation": "Maintain SOC alert triage MTTR under 45 minutes to fulfill the statutory 6-hour declaration window." if is_ready else "Urgent: Increase SIEM/SOC and EDR coverage to ensure detection and triage within the statutory 6-hour window."
        }

    def _check_dpdp_readiness(self, state_map: Dict[str, Any]) -> Dict[str, Any]:
        """
        Assesses Digital Personal Data Protection (DPDP) Act 2025 reasonable security safeguards.
        Statutory penalties up to ₹250 Cr for non-compliance.
        """
        enc_cov = state_map.get("CTRL-ENC-01", {}).get("coverage_pct", 0.0)
        dlp_cov = state_map.get("CTRL-DLP-01", {}).get("coverage_pct", 0.0)
        mfa_cov = state_map.get("CTRL-MFA-01", {}).get("coverage_pct", 0.0)
        pam_cov = state_map.get("CTRL-PAM-01", {}).get("coverage_pct", 0.0)

        safeguard_score = round((enc_cov + dlp_cov + mfa_cov + pam_cov) / 4.0, 1)

        return {
            "requirement": "DPDP Act 2025 Section 8(5) - Reasonable Security Safeguards",
            "safeguards_score_pct": safeguard_score,
            "status": "STRONG" if safeguard_score >= 80 else ("MODERATE" if safeguard_score >= 60 else "VULNERABLE"),
            "checklist": [
                {"item": "Encryption of Personal Data at Rest (TDE/HSM)", "coverage_pct": enc_cov, "pass": enc_cov >= 70},
                {"item": "Data Loss Prevention (DLP) across egress points", "coverage_pct": dlp_cov, "pass": dlp_cov >= 70},
                {"item": "Multi-Factor Authentication for Customer PII access", "coverage_pct": mfa_cov, "pass": mfa_cov >= 75},
                {"item": "Privileged Account Vaulting and Access Auditing", "coverage_pct": pam_cov, "pass": pam_cov >= 70}
            ],
            "penalty_exposure_cap": "₹250 Crore statutory limit (modeled as fat-tailed loss distribution)"
        }
