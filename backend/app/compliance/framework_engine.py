from typing import Dict, Any, List
from app.compliance.evidence import assess_control, reporting_readiness
from app.compliance.catalog import ControlCatalog, FRAMEWORKS
from app.compliance.framework_registry import FRAMEWORK_REQUIREMENTS

# Alias map: common alternative names -> canonical keys in FRAMEWORKS
FRAMEWORK_ALIASES = {
    "iso_27001": "iso", "iso27001": "iso", "iso/iec 27001": "iso",
    "nist_csf": "nist", "nistcsf": "nist",
    "cis_v8": "cis", "cisv8": "cis", "cis controls": "cis",
    "rbi_csf": "rbi",
    "sebi_cscrf": "sebi", "sebicscrf": "sebi",
    "dpdp_act": "dpdp",
}


def normalize_framework_id(framework_id: str) -> str:
    """
    Resolves framework_id to its canonical key via alias lookup.
    Raises ValueError if the ID is not recognized after normalization.
    """
    normalized = framework_id.lower().strip()
    # Direct match
    if normalized in FRAMEWORKS:
        return normalized
    # Alias match
    if normalized in FRAMEWORK_ALIASES:
        return FRAMEWORK_ALIASES[normalized]
    # No match — raise with valid options
    valid = sorted(set(list(FRAMEWORKS.keys()) + list(FRAMEWORK_ALIASES.keys())))
    raise ValueError(
        f"Unknown framework '{framework_id}'. Valid IDs: {', '.join(sorted(FRAMEWORKS.keys()))}. "
        f"Also accepted aliases: {', '.join(sorted(FRAMEWORK_ALIASES.keys()))}"
    )


class FrameworkEngine:
    def __init__(self, catalog: ControlCatalog = None):
        self.catalog = catalog or ControlCatalog()

    def evaluate_framework(self, framework_id: str, control_states: List[Dict[str, Any]], assessments=None, exercises=None) -> Dict[str, Any]:
        """
        Evaluates organizational compliance and evidence coverage for a target framework.
        Normalizes framework_id through alias map before lookup.
        Raises ValueError if framework_id is not recognized.
        """
        canonical_id = normalize_framework_id(framework_id)
        fw_meta = FRAMEWORKS[canonical_id]
        state_map = {cs["control_id"]: cs for cs in control_states}

        framework_controls = []
        covered_count = 0
        total_mapped = 0
        total_coverage_sum = 0.0

        gaps = []

        for ctrl in self.catalog.get_all_controls():
            c_id = ctrl["id"]
            fw_mapping = ctrl.get("frameworks", {}).get(canonical_id)
            if not fw_mapping:
                continue

            total_mapped += 1
            cs = state_map.get(c_id, {})
            cov_raw = cs.get("coverage_pct")
            cov_pct = cov_raw if cov_raw is not None else 0.0
            assessment = assess_control(cs, (assessments or {}).get(c_id))
            is_covered = assessment["status"] == "Compliant"
            if is_covered:
                covered_count += 1
            total_coverage_sum += cov_pct

            ctrl_eval = {
                "control_id": c_id,
                "name": ctrl["name"],
                "framework_clause": fw_mapping,
                "coverage_pct": cov_raw,
                **assessment,
                "evidence_ref": cs.get("evidence_ref", "No telemetry evidence linked"),
                "is_simulated": cs.get("is_simulated", False)
            }
            framework_controls.append(ctrl_eval)

            if not is_covered:
                cost = ctrl.get("capex", 0.0) + ctrl.get("annual_cost", 0.0)
                gaps.append({
                    "control_id": c_id,
                    "name": ctrl["name"],
                    "framework_clause": fw_mapping,
                    "current_coverage_pct": cov_pct,
                    "gap_shortfall_pct": round(max(0.0, 75.0 - cov_pct), 1),
                    "remediation_cost": cost,
                    "mitigates": ctrl.get("mitigates", [])
                })

        overall_coverage = round(total_coverage_sum / max(1, total_mapped), 1) if total_mapped > 0 else 0.0
        gaps.sort(key=lambda g: g["remediation_cost"])

        # Check canonical requirements registry for authoritative coverage calculation
        requirements = FRAMEWORK_REQUIREMENTS.get(canonical_id, [])
        total_framework_reqs = len(requirements) if requirements else total_mapped
        mapped_reqs = [r for r in requirements if r.get("mapped_control_id")]
        unmapped_reqs = [r for r in requirements if not r.get("mapped_control_id")]
        mapped_count = len(mapped_reqs) if requirements else total_mapped
        unmapped_count = len(unmapped_reqs) if requirements else 0
        mapping_coverage_pct = round((mapped_count / max(1, total_framework_reqs)) * 100.0, 1)
        requirement_assessments = [{"requirement_id": r["id"],
            **assess_control(state_map.get(r.get("mapped_control_id"), {}),
                (assessments or {}).get(r["id"], (assessments or {}).get(r.get("mapped_control_id"))))}
            for r in requirements]

        # Special Regulatory Readiness Modules
        sebi_6h_readiness = reporting_readiness(exercises)
        dpdp_readiness = self._check_dpdp_readiness(state_map)

        return {
            "framework_id": framework_id,
            "canonical_id": canonical_id,
            "framework_name": fw_meta["name"],
            "description": fw_meta["description"],
            "citation": fw_meta["citation"],
            "disclaimer": "Indicative mapping for simulation and readiness assessment. Not an official regulatory certification.",
            "overall_coverage_pct": overall_coverage,
            "scope": "Curated requirement subset; mapping coverage is not whole-framework compliance",
            "observed_control_coverage_pct": round(sum(c["observed_coverage_pct"] for c in framework_controls if c["observed_coverage_pct"] is not None) / max(1, sum(c["observed_coverage_pct"] is not None for c in framework_controls)), 1) if any(c["observed_coverage_pct"] is not None for c in framework_controls) else None,
            "evidence_completeness_pct": round(100 * sum(c["evidence_complete"] for c in framework_controls) / max(1, len(framework_controls)), 1),
            "assessed_compliance_pct": round(100 * covered_count / max(1, total_mapped), 1),
            "requirement_assessments": requirement_assessments,
            "assessed_requirement_compliance_pct": round(100*sum(r["status"] == "Compliant" for r in requirement_assessments)/max(1,len(requirement_assessments)),1),
            "mapping_coverage_pct": mapping_coverage_pct,
            "total_framework_requirements": total_framework_reqs,
            "mapped_requirements_count": mapped_count,
            "unmapped_requirements_count": unmapped_count,
            "unmapped_requirements": unmapped_reqs,
            "total_controls_mapped": total_mapped,
            "compliant_controls": covered_count,
            "gaps_count": len(gaps),
            "controls": framework_controls,
            "gaps": gaps,
            "sebi_6hour_readiness": sebi_6h_readiness,
            "dpdp_readiness": dpdp_readiness
        }

    def _check_sebi_6h_readiness(self, state_map, exercises=None):
        return reporting_readiness(exercises)

    def _check_dpdp_readiness(self, state_map: Dict[str, Any]) -> Dict[str, Any]:
        """
        Reports observed safeguards telemetry without asserting legal compliance.
        """
        observed = [assess_control(state_map.get(cid, {}))["observed_coverage_pct"]
                    for cid in ("CTRL-ENC-01", "CTRL-DLP-01", "CTRL-MFA-01", "CTRL-PAM-01")]
        known = [v for v in observed if v is not None]
        return {"requirement": "Personal-data safeguards telemetry (curated subset; independent legal assessment required)",
                "safeguards_score_pct": round(sum(known)/len(known),1) if known else None,
                "status": "NOT ASSESSED", "checklist": [],
                "penalty_exposure_cap": "Configured loss assumption; not an assessed legal liability"}
