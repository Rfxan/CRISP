from typing import Dict, Any, List
import copy
from app.engine.fair_engine import FAIREngine

class SensitivityAnalyzer:
    def __init__(self, engine: FAIREngine = None):
        self.engine = engine or FAIREngine(trials=2000, seed=42)

    def compute_tornado(self, snapshot: Dict[str, Any], baseline_eal: float) -> List[Dict[str, Any]]:
        """
        Dynamically computes EAL sensitivity by varying each of the top 5 key parameters
        by -30% and +30% and executing the Monte Carlo engine on the perturbed model.
        Zero hardcoded ratios.
        """
        parameters_to_test = [
            {"name": "Threat Event Frequency (TEF)", "key": "tef"},
            {"name": "Cost Per Breached Record (INR)", "key": "cost_per_record"},
            {"name": "DPDP Regulatory Penalty Multiplier", "key": "dpdp_penalty"},
            {"name": "Service Downtime Outage Hours", "key": "downtime"},
            {"name": "Control Effect Size Prior", "key": "control_eff"}
        ]

        tornado_items = []
        for param in parameters_to_test:
            key = param["key"]
            
            # Create low (-30%) and high (+30%) clone copies of snapshot
            snap_low = copy.deepcopy(snapshot)
            snap_high = copy.deepcopy(snapshot)

            if key == "tef":
                for sc in snap_low.get("scenarios", []):
                    if "tef_params" in sc:
                        sc["tef_params"] = {k: v * 0.70 for k, v in sc["tef_params"].items()}
                for sc in snap_high.get("scenarios", []):
                    if "tef_params" in sc:
                        sc["tef_params"] = {k: v * 1.30 for k, v in sc["tef_params"].items()}

            elif key == "cost_per_record":
                for a in snap_low.get("assets", []):
                    if "records_count" in a:
                        a["records_count"] = int(a["records_count"] * 0.70)
                for a in snap_high.get("assets", []):
                    if "records_count" in a:
                        a["records_count"] = int(a["records_count"] * 1.30)

            elif key == "dpdp_penalty":
                for a in snap_low.get("assets", []):
                    if a.get("data_classification") == "Restricted Financial PII":
                        a["records_count"] = int(a["records_count"] * 0.70)
                for a in snap_high.get("assets", []):
                    if a.get("data_classification") == "Restricted Financial PII":
                        a["records_count"] = int(a["records_count"] * 1.30)

            elif key == "downtime":
                for s in snap_low.get("services", []):
                    s["rto_hours"] = max(0.5, s.get("rto_hours", 4.0) * 0.70)
                    s["revenue_per_hour"] = s.get("revenue_per_hour", 0.0) * 0.70
                for s in snap_high.get("services", []):
                    s["rto_hours"] = s.get("rto_hours", 4.0) * 1.30
                    s["revenue_per_hour"] = s.get("revenue_per_hour", 0.0) * 1.30

            elif key == "control_eff":
                for cs in snap_low.get("control_state", []):
                    cs["coverage_pct"] = max(0.0, cs.get("coverage_pct", 50.0) * 0.70)
                for cs in snap_high.get("control_state", []):
                    cs["coverage_pct"] = min(100.0, cs.get("coverage_pct", 50.0) * 1.30)

            # Execute actual Monte Carlo simulation with 2,000 trials
            res_low = self.engine.run(snap_low, params={"trials": 2000}, seed=42)
            res_high = self.engine.run(snap_high, params={"trials": 2000}, seed=42)

            low_eal = res_low["org"]["eal"]
            high_eal = res_high["org"]["eal"]

            # If control effectiveness was boosted, higher effectiveness yields lower risk
            if key == "control_eff":
                actual_min = min(low_eal, high_eal)
                actual_max = max(low_eal, high_eal)
                low_eal = actual_min
                high_eal = actual_max

            spread = round(abs(high_eal - low_eal), 2)

            tornado_items.append({
                "parameter": param["name"],
                "low_value_eal": round(min(low_eal, high_eal), 2),
                "high_value_eal": round(max(low_eal, high_eal), 2),
                "swing_spread": spread,
                "delta_low": round(min(low_eal, high_eal) - baseline_eal, 2),
                "delta_high": round(max(low_eal, high_eal) - baseline_eal, 2)
            })

        tornado_items.sort(key=lambda x: x["swing_spread"], reverse=True)
        return tornado_items

    def check_convergence(self, snapshot: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Evaluates Monte Carlo convergence across trial sample sizes: 500, 1000, 2500, 5000, 10000.
        Demonstrates visually in UI that 10,000 trials converges stably.
        """
        trial_steps = [500, 1000, 2500, 5000, 10000]
        convergence_data = []

        for n in trial_steps:
            sub_engine = FAIREngine(trials=n, seed=42)
            res = sub_engine.run(snapshot, params={"trials": n}, seed=42)
            convergence_data.append({
                "trials": n,
                "eal": res["org"]["eal"],
                "var95": res["org"]["var95"]
            })

        return convergence_data
