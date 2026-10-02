"""Approximate ILP selection; all reported portfolio benefits use the FAIR simulator."""
import copy
import math
import numpy as np
import pulp
from app.engine.fair_engine import FAIREngine
from app.engine.whatif import WhatIfSimulator
from app.engine.model import finding_key, digest, assumptions


class InvestmentOptimizer:
    def __init__(self, controls_catalog, findings, cve_intel, snapshot=None, engine=None, seed=42, baseline=None):
        if snapshot is None:
            raise ValueError("Investment evaluation requires the original snapshot")
        self.snapshot = copy.deepcopy(snapshot)
        self.controls, self.findings, self.cve_intel = controls_catalog, findings, cve_intel
        self.engine = engine or FAIREngine(trials=5000, seed=seed)
        self.seed = seed
        self.simulator = WhatIfSimulator(self.engine)
        self.baseline = baseline or self.engine.run(self.snapshot, seed=seed)
        if self.baseline["org"]["eal"] is None:
            raise ValueError("Cannot optimize without quantified exposure")
        self.evaluations = {}
        self.plans = {}
        self.candidates = self._candidates()

    def _candidates(self):
        candidates = []
        drivers = {d["id"]: d for d in self.baseline["drivers"]}
        for f in self.findings:
            key = finding_key(f)
            d = drivers.get(key, {})
            if d.get("marginal_eal") is None:
                continue  # Never pretend an unmeasured screening estimate is an exact benefit.
            cost = float(f.get("patch_cost", 250000 if f.get("severity") == "Critical" else 150000))
            candidates.append({"id": key, "finding_id": f["id"], "asset_id": f["asset_id"], "cve_id": f.get("cve_id"),
                "driver_id": key, "type": "patch", "severity": f.get("severity"), "name": f.get("cve_id") or f["id"],
                "cost": cost, "cost_source": "provided" if "patch_cost" in f else "planning assumption",
                "objective_coefficient": max(0, d["marginal_eal"]), "cvss": f.get("cvss") or 0,
                "epss": self.cve_intel.get(f.get("cve_id"), {}).get("epss") or 0,
                "action": {"type": "patch_finding", "target_id": key}})
        states = {s["control_id"]: s for s in self.snapshot.get("control_state", [])}
        multiplier = assumptions(self.snapshot)["control_effectiveness_multiplier"]
        for c in self.controls:
            state = states.get(c["id"], {})
            coverage = (state.get("coverage_pct") or 0)/100
            if state.get("evidence_ref") == "Not Connected" and not state.get("is_user_assumed"):
                coverage = 0
            if coverage >= 1:
                continue
            eff = min(1, max(0, c.get("effectiveness_dist", {}).get("mean", .75)*multiplier))
            coefficient = sum(self.baseline["scenario_eals"].get(s, 0) for s in c.get("mitigates", [])) * (eff*(1-coverage)/max(1e-9, 1-eff*coverage))
            candidates.append({"id": c["id"], "name": c["name"], "type": "control", "category": c.get("category"),
                "cost": float(c.get("capex", 0)+c.get("annual_cost", 0)), "annual_cost": c.get("annual_cost", 0),
                "cost_source": "control catalog planning assumption", "frameworks": c.get("frameworks", {}),
                "objective_coefficient": coefficient,
                "action": {"type": "increase_control_coverage", "target_id": c["id"], "coverage_pct": 100}})
        for c in candidates:
            if not math.isfinite(c["cost"]) or c["cost"] < 0:
                raise ValueError("Action costs must be finite and nonnegative")
        return candidates

    def evaluate(self, selected, budget):
        actions = sorted([c["action"] for c in selected], key=lambda a: digest(a))
        key = digest(actions)
        if key not in self.evaluations:
            self.evaluations[key] = self.simulator.simulate_intervention(self.snapshot, actions, self.seed, self.baseline)
        sim = self.evaluations[key]
        spent = sum(c["cost"] for c in selected)
        reduction = sim["delta"]["eal_reduction"]
        items = [{**c, "estimated_reduction": None, "rosi": None,
                  "benefit_note": "Portfolio effects interact; individual objective coefficients are not additive realized savings."} for c in selected]
        return {"status": "Evaluated", "budget": budget, "total_spent": round(spent,2),
                "total_reduction": reduction, "remaining_eal": sim["post_intervention"]["eal"],
                "overall_rosi": round((reduction-spent)/spent,2) if spent else 0,
                "reduction_per_rupee": round(reduction/spent,3) if spent else 0,
                "selected_controls": [c for c in items if c["type"]=="control"],
                "selected_patches": [c for c in items if c["type"]=="patch"], "all_actions": items,
                "actions": actions, "evaluation": sim, "objective_estimate": round(sum(c["objective_coefficient"] for c in selected),2),
                "selection_method": "Additive single-action ILP surrogate; not a global optimum of the nonlinear loss model",
                "evaluation_method": "Shared FAIR counterfactual simulation",
                "excluded_candidates": len(self.findings)-sum(c["type"]=="patch" for c in self.candidates)}

    def optimize(self, base_eal=None, scenario_eals=None, budget=10000000., marginal_eals=None):
        if not math.isfinite(budget) or budget < 0:
            raise ValueError("Budget must be finite and nonnegative")
        if budget in self.plans:
            return copy.deepcopy(self.plans[budget])
        problem = pulp.LpProblem("CRISP_Approximate_Selection", pulp.LpMaximize)
        variables = [pulp.LpVariable(f"action_{i}", cat=pulp.LpBinary) for i in range(len(self.candidates))]
        problem += pulp.lpSum(c["objective_coefficient"]*x for c,x in zip(self.candidates,variables))
        problem += pulp.lpSum(c["cost"]*x for c,x in zip(self.candidates,variables)) <= budget
        problem.solve(pulp.PULP_CBC_CMD(msg=False, timeLimit=30))
        status = pulp.LpStatus[problem.status]
        if status != "Optimal":
            raise ValueError(f"Selection solver did not establish a feasible optimum: {status}")
        selected = [c for c,x in zip(self.candidates,variables) if (pulp.value(x) or 0) > .5]
        result = self.evaluate(selected, budget)
        result["status"] = "Optimal surrogate; simulated portfolio"
        self.plans[budget] = copy.deepcopy(result)
        return result

    def _greedy(self, candidates, budget, score):
        selected, spent = [], 0.
        for c in sorted(candidates, key=lambda c: (score(c), c["id"]), reverse=True):
            if spent+c["cost"] <= budget:
                selected.append(c); spent += c["cost"]
        return self.evaluate(selected, budget)

    def run_benchmark(self, base_eal=None, scenario_eals=None, budget=10000000., marginal_eals=None):
        plan = self.optimize(budget=budget)
        patches = [c for c in self.candidates if c["type"]=="patch"]
        cvss = self._greedy(patches, budget, lambda c:c["cvss"])
        epss = self._greedy(patches, budget, lambda c:c["epss"])
        common = self._greedy(self.candidates, budget, lambda c:c["objective_coefficient"]/max(1,c["cost"]))
        strategies = []
        for name, result, kind, universe in [
            ("Patch by CVSS Severity (Naive)",cvss,"baseline","patches only"),
            ("Patch by EPSS Probability (Threat Intel)",epss,"baseline","patches only"),
            ("Greedy benefit per rupee (same action set)",common,"baseline","patches and controls"),
            ("CRISP AI Investment Optimizer (ILP)",plan,"recommended","patches and controls")]:
            strategies.append({"strategy_name":name,"type":kind,"spend":result["total_spent"],
                "eal_reduction":result["total_reduction"],"remaining_eal":result["remaining_eal"],
                "reduction_per_rupee":result["reduction_per_rupee"],"actions_count":len(result["actions"]),
                "actions":result["actions"],"action_universe":universe,"description":"Evaluated using the same snapshot, assumptions, seed and trials."})
        def relative(other):
            return round((plan["total_reduction"]-other["total_reduction"])/other["total_reduction"]*100,1) if other["total_reduction"]>0 else None
        return {"budget":budget,"strategies":strategies,
                "reproducibility": {"snapshot_hash":digest(self.snapshot),"seed":self.seed,"trials":self.engine.trials,
                    "model_version":self.baseline["model_version"],"assumptions_version":self.baseline["assumptions_version"],
                    "assumptions":assumptions(self.snapshot),
                    "baseline_run_id":self.baseline["run_id"],"evaluation_method":"Shared FAIR counterfactual simulation",
                    "asset_count":len(self.snapshot.get("assets",[])),"finding_count":len(self.findings)},
                "headline":{"outperformance_vs_cvss_pct":relative(cvss),"outperformance_vs_epss_pct":relative(epss),
                    "outperformance_vs_common_actions_pct":relative(common),
                    "extra_rupees_saved":round(plan["total_reduction"]-cvss["total_reduction"],2),
                    "proof_summary":"Dataset-specific simulated comparison. Selection is approximate; no guaranteed outperformance."}}

    def generate_pareto_curve(self, base_eal=None, scenario_eals=None, marginal_eals=None, steps=15):
        points = []
        for b in np.linspace(1000000,50000000,steps):
            r = self.optimize(budget=float(b))
            points.append({"budget":float(b),"spent":r["total_spent"],"eal_reduction":r["total_reduction"],
                           "remaining_eal":r["remaining_eal"],"reduction_per_rupee":r["reduction_per_rupee"]})
        return {"curve":points,"knee_point":None,"method":"Simulated selected portfolios; no optimal-frontier guarantee"}
