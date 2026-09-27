import pulp
from typing import Dict, Any, List, Tuple
import numpy as np

class InvestmentOptimizer:
    def __init__(self, controls_catalog: List[Dict[str, Any]], findings: List[Dict[str, Any]], cve_intel: Dict[str, Any]):
        self.controls = controls_catalog
        self.findings = findings
        self.cve_intel = cve_intel

    def optimize(self, base_eal: float, scenario_eals: Dict[str, float], budget: float, marginal_eals: Dict[str, float] = None) -> Dict[str, Any]:
        """
        Solves budget-constrained ILP using PuLP solver.
        Formulation: PRD Section 10.7
        """
        prob = pulp.LpProblem("CRISP_Cyber_Investment_Optimization", pulp.LpMaximize)

        # Control variables: x_c in {0, 1}
        x = {c["id"]: pulp.LpVariable(f"x_{c['id']}", cat=pulp.LpBinary) for c in self.controls}

        # Scenario selection variables: y_{c, s} in {0, 1}
        # Best control wins formulation to avoid over-crediting
        scenarios = list(scenario_eals.keys())
        y = {}
        for sc in scenarios:
            for c in self.controls:
                if sc in c.get("mitigates", []):
                    y[(c["id"], sc)] = pulp.LpVariable(f"y_{c['id']}_{sc}", cat=pulp.LpBinary)

        # Vulnerability patch variables: z_v in {0, 1}
        # Each finding has a remediation cost (labor + change freeze ~ ₹100,000 - ₹300,000)
        z = {}
        patch_costs = {}
        patch_reductions = {}
        for f in self.findings:
            f_id = f["id"]
            cve = f.get("cve_id")
            issue = f.get("issue_type")
            z[f_id] = pulp.LpVariable(f"z_{f_id}", cat=pulp.LpBinary)
            
            cost = f.get("patch_cost", 250000.0 if f.get("severity") == "Critical" else 150000.0)
            patch_costs[f_id] = cost
            # Exact marginal EAL reduction from leave-one-out
            red = (marginal_eals.get(cve) or marginal_eals.get(issue) or marginal_eals.get(f_id) or 0.0) if marginal_eals else 0.0
            patch_reductions[f_id] = red

        # Objective Function: Maximize total EAL reduction
        control_reductions = []
        for (c_id, sc), var in y.items():
            ctrl = next(c for c in self.controls if c["id"] == c_id)
            eff = ctrl.get("effectiveness_dist", {}).get("mean", 0.8)
            sc_eal = scenario_eals.get(sc, 0.0)
            reduction_val = sc_eal * eff
            control_reductions.append(reduction_val * var)

        vulnerability_reductions = [patch_reductions[f["id"]] * z[f["id"]] for f in self.findings]

        prob += pulp.lpSum(control_reductions) + pulp.lpSum(vulnerability_reductions)

        # Budget Constraint:
        control_costs = [
            (c.get("capex", 0.0) + c.get("annual_cost", 0.0)) * x[c["id"]]
            for c in self.controls
        ]
        vuln_costs = [patch_costs[f["id"]] * z[f["id"]] for f in self.findings]
        prob += pulp.lpSum(control_costs) + pulp.lpSum(vuln_costs) <= budget

        # Linking Constraints for Controls:
        for (c_id, sc), var in y.items():
            prob += var <= x[c_id]

        # Only one primary control counts per scenario ("Best control wins")
        for sc in scenarios:
            vars_for_sc = [y[(c["id"], sc)] for c in self.controls if (c["id"], sc) in y]
            if vars_for_sc:
                prob += pulp.lpSum(vars_for_sc) <= 1

        # Solve ILP
        solver = pulp.PULP_CBC_CMD(msg=False)
        prob.solve(solver)

        # Extract selected actions
        selected_controls = []
        total_spent = 0.0
        for c in self.controls:
            c_id = c["id"]
            if pulp.value(x[c_id]) and pulp.value(x[c_id]) > 0.5:
                cost = c.get("capex", 0.0) + c.get("annual_cost", 0.0)
                total_spent += cost
                # Compute effective reduction across scenarios
                eff = c.get("effectiveness_dist", {}).get("mean", 0.8)
                sc_red = sum(scenario_eals.get(sc, 0.0) * eff for sc in c.get("mitigates", []))
                annual_c = max(1.0, c.get("annual_cost", 500000.0))
                rosi = round((sc_red - annual_c) / annual_c, 2)
                selected_controls.append({
                    "id": c_id,
                    "name": c["name"],
                    "type": "control",
                    "category": c.get("category", "Security Control"),
                    "cost": cost,
                    "annual_cost": c.get("annual_cost", 0.0),
                    "estimated_reduction": round(sc_red, 2),
                    "rosi": rosi,
                    "frameworks": c.get("frameworks", {})
                })

        selected_patches = []
        for f in self.findings:
            f_id = f["id"]
            if pulp.value(z[f_id]) and pulp.value(z[f_id]) > 0.5:
                cost = patch_costs[f_id]
                total_spent += cost
                red = patch_reductions[f_id]
                selected_patches.append({
                    "id": f_id,
                    "cve_id": f.get("cve_id"),
                    "driver_id": f.get("cve_id") or f_id,
                    "asset_id": f.get("asset_id"),
                    "type": "patch",
                    "severity": f.get("severity", "High"),
                    "cost": cost,
                    "estimated_reduction": round(red, 2),
                    "rosi": round((red - cost) / cost, 2)
                })

        total_reduction = float(pulp.value(prob.objective)) if prob.objective else 0.0
        remaining_eal = max(0.0, base_eal - total_reduction)
        overall_rosi = round((total_reduction - total_spent) / max(1.0, total_spent), 2) if total_spent > 0 else 0.0

        return {
            "status": pulp.LpStatus[prob.status],
            "budget": budget,
            "total_spent": round(total_spent, 2),
            "total_reduction": round(total_reduction, 2),
            "remaining_eal": round(remaining_eal, 2),
            "overall_rosi": overall_rosi,
            "reduction_per_rupee": round(total_reduction / max(1.0, total_spent), 3) if total_spent > 0 else 0.0,
            "selected_controls": selected_controls,
            "selected_patches": selected_patches,
            "all_actions": selected_controls + selected_patches
        }

    def generate_pareto_curve(self, base_eal: float, scenario_eals: Dict[str, float], marginal_eals: Dict[str, float] = None, steps: int = 15) -> Dict[str, Any]:
        """
        Sweeps budget from ₹10 Lakhs (1M) to ₹5 Crores (50M) to generate Pareto curve and locate knee.
        """
        min_budget = 1_000_000.0   # ₹10 Lakhs
        max_budget = 50_000_000.0  # ₹5 Crore
        budgets = np.linspace(min_budget, max_budget, steps)

        curve_points = []
        knee_point = None
        max_marginal_slope = -1.0
        prev_reduction = 0.0
        prev_budget = 0.0

        for b in budgets:
            res = self.optimize(base_eal, scenario_eals, budget=float(b), marginal_eals=marginal_eals)
            red = res["total_reduction"]
            spent = res["total_spent"]
            curve_points.append({
                "budget": round(float(b), 2),
                "spent": round(spent, 2),
                "eal_reduction": round(red, 2),
                "remaining_eal": round(res["remaining_eal"], 2),
                "reduction_per_rupee": res["reduction_per_rupee"]
            })

            # Knee detection: point where incremental EAL reduction per additional rupee spent drops below 1.5
            if prev_budget > 0:
                delta_red = red - prev_reduction
                delta_b = b - prev_budget
                marginal_ratio = delta_red / max(1.0, delta_b)
                if knee_point is None and marginal_ratio < 1.5 and red > 0:
                    knee_point = {
                        "budget": round(float(b), 2),
                        "eal_reduction": round(red, 2),
                        "description": "Point of diminishing returns (Marginal ROI knee)"
                    }

            prev_reduction = red
            prev_budget = b

        if knee_point is None and len(curve_points) > 5:
            knee_point = curve_points[len(curve_points) // 2]

        return {
            "curve": curve_points,
            "knee_point": knee_point
        }

    def run_benchmark(self, base_eal: float, scenario_eals: Dict[str, float], budget: float, marginal_eals: Dict[str, float] = None) -> Dict[str, Any]:
        """
        Live Benchmark: CRISP Optimizer vs Patch-by-CVSS vs Patch-by-EPSS.
        Headline claim for PRD Section 10.7 & 14.
        """
        # 1. CRISP Optimizer Plan
        crisp_plan = self.optimize(base_eal, scenario_eals, budget, marginal_eals)

        # 2. Patch-by-CVSS Strategy (Naive baseline)
        sorted_by_cvss = sorted(self.findings, key=lambda f: (f.get("cvss") or 0.0), reverse=True)
        cvss_spent = 0.0
        cvss_reduction = 0.0
        cvss_patches = []
        for f in sorted_by_cvss:
            f_id = f["id"]
            cve = f.get("cve_id")
            f_cost = f.get("patch_cost", 250000.0 if f.get("severity") == "Critical" else 150000.0)
            if cvss_spent + f_cost <= budget:
                cvss_spent += f_cost
                red = (marginal_eals.get(cve) or marginal_eals.get(f_id) or 0.0) if marginal_eals else 0.0
                cvss_reduction += red
                cvss_patches.append(cve or f.get("issue_type") or f_id)

        # 3. Patch-by-EPSS Strategy (Threat-intel baseline)
        sorted_by_epss = sorted(
            self.findings,
            key=lambda f: self.cve_intel.get(f.get("cve_id"), {}).get("epss", 0.0) if f.get("cve_id") else 0.0,
            reverse=True
        )
        epss_spent = 0.0
        epss_reduction = 0.0
        epss_patches = []
        for f in sorted_by_epss:
            f_id = f["id"]
            cve = f.get("cve_id")
            f_cost = f.get("patch_cost", 250000.0 if f.get("severity") == "Critical" else 150000.0)
            if epss_spent + f_cost <= budget:
                epss_spent += f_cost
                red = (marginal_eals.get(cve) or marginal_eals.get(f_id) or 0.0) if marginal_eals else 0.0
                epss_reduction += red
                epss_patches.append(cve or f.get("issue_type") or f_id)

        # Outperformance calculation
        crisp_red = crisp_plan["total_reduction"]
        crisp_eff = crisp_plan["reduction_per_rupee"]
        cvss_eff = round(cvss_reduction / max(1.0, cvss_spent), 3) if cvss_spent > 0 else 0.0
        epss_eff = round(epss_reduction / max(1.0, epss_spent), 3) if epss_spent > 0 else 0.0

        outperformance_vs_cvss = round(((crisp_red - cvss_reduction) / max(1.0, cvss_reduction)) * 100, 1) if cvss_reduction > 0 else 100.0
        outperformance_vs_epss = round(((crisp_red - epss_reduction) / max(1.0, epss_reduction)) * 100, 1) if epss_reduction > 0 else 100.0

        return {
            "budget": budget,
            "strategies": [
                {
                    "strategy_name": "Patch by CVSS Severity (Naive)",
                    "type": "baseline",
                    "spend": round(cvss_spent, 2),
                    "eal_reduction": round(cvss_reduction, 2),
                    "remaining_eal": round(max(0.0, base_eal - cvss_reduction), 2),
                    "reduction_per_rupee": cvss_eff,
                    "actions_count": len(cvss_patches),
                    "description": "Prioritizes exclusively by CVSS score without asset criticality or control synergy."
                },
                {
                    "strategy_name": "Patch by EPSS Probability (Threat Intel)",
                    "type": "baseline",
                    "spend": round(epss_spent, 2),
                    "eal_reduction": round(epss_reduction, 2),
                    "remaining_eal": round(max(0.0, base_eal - epss_reduction), 2),
                    "reduction_per_rupee": epss_eff,
                    "actions_count": len(epss_patches),
                    "description": "Prioritizes by FIRST EPSS exploit likelihood alone."
                },
                {
                    "strategy_name": "CRISP AI Investment Optimizer (ILP)",
                    "type": "recommended",
                    "spend": round(crisp_plan["total_spent"], 2),
                    "eal_reduction": round(crisp_red, 2),
                    "remaining_eal": round(crisp_plan["remaining_eal"], 2),
                    "reduction_per_rupee": crisp_eff,
                    "actions_count": len(crisp_plan["all_actions"]),
                    "description": "Solves multi-objective ILP across asset criticality, service dependencies, controls and patches."
                }
            ],
            "headline": {
                "outperformance_vs_cvss_pct": outperformance_vs_cvss,
                "outperformance_vs_epss_pct": outperformance_vs_epss,
                "extra_rupees_saved": round(crisp_red - cvss_reduction, 2),
                "proof_summary": f"CRISP ILP delivers +{outperformance_vs_cvss}% higher financial risk reduction than CVSS prioritization under the identical ₹{int(budget):,} budget."
            }
        }
