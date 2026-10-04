import copy
import math
import json
from app.core.config import DATA_DIR
from app.core.errors import DomainValidationError
from app.engine.fair_engine import FAIREngine
from app.engine.model import finding_key, digest


def apply_actions(snapshot, actions):
    """One action interpreter shared by simulations, investments and benchmarks."""
    result = copy.deepcopy(snapshot)
    descriptions = []
    catalog = result.get("controls_catalog")
    if catalog is None:
        catalog = json.loads((DATA_DIR / "controls_catalog.json").read_text(encoding="utf-8"))
    catalog_ids = {c["id"] for c in catalog}
    for raw in actions:
        action = dict(raw)
        kind, target = action.get("type"), action.get("target_id")
        if kind == "segment_payment_network":
            kind, target = "increase_control_coverage", "CTRL-SEG-01"
            action["coverage_pct"] = 100
        if kind == "increase_control_coverage":
            coverage = float(action.get("coverage_pct", 100))
            if not math.isfinite(coverage) or not 0 <= coverage <= 100:
                raise DomainValidationError("Coverage must be between 0 and 100")
            if target not in catalog_ids:
                raise DomainValidationError("Unknown control target")
            states = result.setdefault("control_state", [])
            state = next((c for c in states if c["control_id"] == target), None)
            if state is None:
                state = {"control_id": target}
                states.append(state)
            state.update(coverage_pct=coverage, is_user_assumed=True, is_simulated=True,
                         evidence_ref="Counterfactual assumption")
            descriptions.append(f"Set {target} coverage to {coverage}%")
        elif kind in ("patch_finding", "patch_cve", "patch_all_kev"):
            findings = result.get("findings", [])
            def matches(f):
                if kind == "patch_all_kev":
                    return bool(result.get("cve_intel", {}).get(f.get("cve_id"), {}).get("in_kev"))
                if kind == "patch_finding":
                    return finding_key(f) == target or (f.get("id") == target and f.get("asset_id") == action.get("asset_id"))
                return (f.get("id") == target or f.get("cve_id") == target) and (not action.get("asset_id") or f.get("asset_id") == action["asset_id"])
            selected = [f for f in findings if matches(f)]
            if not selected and kind != "patch_all_kev":
                raise DomainValidationError("Finding target does not exist in this snapshot")
            result["findings"] = [f for f in findings if not matches(f)]
            if selected:
                result["assessment_state"] = {**result.get("assessment_state", {}), "status": "remediated"}
            descriptions.append(f"Remediated {len(selected)} finding(s)")
        else:
            raise DomainValidationError("Unsupported intervention type")
    return result, descriptions


class WhatIfSimulator:
    def __init__(self, engine=None):
        self.engine = engine or FAIREngine(trials=5000, seed=42)

    def simulate_intervention(self, snapshot, actions, seed=42, baseline=None):
        base = baseline or self.engine.run(snapshot, {"calculate_drivers": False}, seed)
        if base["org"]["eal"] is None:
            return {"status": base["status"], "message": base.get("message"), "seed": seed,
                    "run_id": None, "baseline": base["org"], "post_intervention": None,
                    "delta": {"eal_reduction": None, "var95_reduction": None}, "actions": actions,
                    "cost_of_delay": {"per_week_inr": None}, "new_curve": [], "baseline_curve": []}
        modified, descriptions = apply_actions(snapshot, actions)
        post = self.engine.run(modified, {"calculate_drivers": False}, seed)
        if post["org"]["eal"] is None:
            raise DomainValidationError("Intervention cannot be quantified with available business context")
        reduction = round(base["org"]["eal"] - post["org"]["eal"], 2)
        var_reduction = round(base["org"]["var95"] - post["org"]["var95"], 2)
        return {"status": post["status"], "applied_actions": descriptions, "actions": copy.deepcopy(actions),
                "seed": seed, "trials": post["trials"], "run_id": post["run_id"], "baseline_run_id": base["run_id"],
                "snapshot_hash": digest(snapshot), "model_version": post["model_version"],
                "assumptions_version": post["assumptions_version"], "baseline": base["org"], "post_intervention": post["org"],
                "delta": {"eal_reduction": reduction, "var95_reduction": var_reduction,
                          "pct_eal_reduction": round(reduction/max(1, base["org"]["eal"])*100, 2),
                          "pct_var95_reduction": round(var_reduction/max(1, base["org"]["var95"])*100, 2)},
                "cost_of_delay": {"per_week_inr": round(reduction/52, 2), "per_week_lakhs": round(reduction/5200000, 2),
                                  "rationale": "Annual expected-loss difference / 52; assumes constant exposure and immediate implementation."},
                "new_curve": post["curve"], "baseline_curve": base["curve"]}
