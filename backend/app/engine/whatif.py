import copy
from typing import Dict, Any, List
from app.engine.fair_engine import FAIREngine

class WhatIfSimulator:
    def __init__(self, engine: FAIREngine = None):
        self.engine = engine or FAIREngine(trials=5000, seed=42)

    def simulate_intervention(self, snapshot: Dict[str, Any], actions: List[Dict[str, Any]], seed: int = 42) -> Dict[str, Any]:
        """
        Clones snapshot, applies actions (e.g. increase control coverage, remove findings),
        and runs FAIR simulation on identical seed to get exact delta.
        """
        # Baseline simulation
        base_res = self.engine.run(snapshot, seed=seed)
        base_eal = base_res["org"]["eal"]
        base_var95 = base_res["org"]["var95"]

        # Clone snapshot
        cloned_snap = copy.deepcopy(snapshot)

        applied_actions = []
        for action in actions:
            act_type = action.get("type")
            target_id = action.get("target_id")

            if act_type == "increase_control_coverage":
                # target_id is control_id, value is new coverage_pct (e.g. 100.0)
                new_cov = float(action.get("coverage_pct", 100.0))
                for cs in cloned_snap.get("control_state", []):
                    if cs["control_id"] == target_id:
                        old_cov = cs.get("coverage_pct", 0.0)
                        cs["coverage_pct"] = new_cov
                        applied_actions.append(f"Upgraded {target_id} coverage from {old_cov}% to {new_cov}%")
                        break
            elif act_type == "patch_cve":
                # Remove finding with this CVE or target_id
                old_len = len(cloned_snap.get("findings", []))
                cloned_snap["findings"] = [f for f in cloned_snap.get("findings", []) if f["cve_id"] != target_id and f["id"] != target_id]
                removed_count = old_len - len(cloned_snap["findings"])
                applied_actions.append(f"Remediated CVE {target_id} ({removed_count} instances patched)")
            elif act_type == "patch_all_kev":
                # Patch all findings listed in CISA KEV
                cve_intel = cloned_snap.get("cve_intel", {})
                kev_cves = {cve for cve, data in cve_intel.items() if data.get("in_kev", False)}
                old_len = len(cloned_snap.get("findings", []))
                cloned_snap["findings"] = [f for f in cloned_snap.get("findings", []) if f["cve_id"] not in kev_cves]
                removed_count = old_len - len(cloned_snap["findings"])
                applied_actions.append(f"Patched all CISA KEV active exploits ({removed_count} findings eliminated)")
            elif act_type == "segment_payment_network":
                # Boost CTRL-SEG-01 to 100%
                for cs in cloned_snap.get("control_state", []):
                    if cs["control_id"] == "CTRL-SEG-01":
                        cs["coverage_pct"] = 100.0
                        applied_actions.append("Full micro-segmentation implemented on Payment Switch")

        # Post-intervention simulation on same seed
        post_res = self.engine.run(cloned_snap, seed=seed)
        post_eal = post_res["org"]["eal"]
        post_var95 = post_res["org"]["var95"]

        delta_eal = base_eal - post_eal
        delta_var95 = base_var95 - post_var95
        pct_eal_reduction = round((delta_eal / max(1.0, base_eal)) * 100, 2)
        pct_var95_reduction = round((delta_var95 / max(1.0, base_var95)) * 100, 2)

        # Cost of delay: financial exposure accumulating each week without these controls
        # Calculated as delta_eal / 52 (in ₹)
        cost_of_delay_per_week = round(delta_eal / 52.0, 2)

        return {
            "applied_actions": applied_actions,
            "seed": seed,
            "run_id": post_res["run_id"],
            "baseline": {
                "eal": round(base_eal, 2),
                "var95": round(base_var95, 2),
                "score": base_res["org"]["score"]
            },
            "post_intervention": {
                "eal": round(post_eal, 2),
                "var95": round(post_var95, 2),
                "score": post_res["org"]["score"]
            },
            "delta": {
                "eal_reduction": round(delta_eal, 2),
                "var95_reduction": round(delta_var95, 2),
                "pct_eal_reduction": pct_eal_reduction,
                "pct_var95_reduction": pct_var95_reduction
            },
            "cost_of_delay": {
                "per_week_inr": cost_of_delay_per_week,
                "per_week_lakhs": round(cost_of_delay_per_week / 100000.0, 2),
                "rationale": "Accumulated expected cyber loss increase per week of delaying implementation"
            },
            "new_curve": post_res["curve"],
            "baseline_curve": base_res["curve"]
        }
