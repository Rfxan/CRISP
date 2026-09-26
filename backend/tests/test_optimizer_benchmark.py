import sys
import io
if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import json
from app.engine.fair_engine import FAIREngine
from app.engine.optimizer import InvestmentOptimizer

def test_optimizer_benchmark():
    data_dir = Path(__file__).resolve().parent.parent / "app" / "data"
    with open(data_dir / "seed_snapshot.json", "r", encoding="utf-8") as f:
        snapshot = json.load(f)
    with open(data_dir / "controls_catalog.json", "r", encoding="utf-8") as f:
        controls = json.load(f)

    engine = FAIREngine(trials=5000, seed=42)
    risk_res = engine.run(snapshot, seed=42)
    base_eal = risk_res["org"]["eal"]

    marginal_eals = {d["id"]: d["marginal_eal"] for d in risk_res["drivers"]}
    scenario_eals = {sc["id"]: base_eal / 6.0 for sc in snapshot["scenarios"]}

    optimizer = InvestmentOptimizer(controls, snapshot["findings"], snapshot["cve_intel"])
    budget = 10_000_000.0  # ₹1 Crore

    # Run Benchmark
    benchmark = optimizer.run_benchmark(base_eal, scenario_eals, budget, marginal_eals)
    strategies = {s["strategy_name"]: s for s in benchmark["strategies"]}

    crisp_res = strategies["CRISP AI Investment Optimizer (ILP)"]
    cvss_res = strategies["Patch by CVSS Severity (Naive)"]
    epss_res = strategies["Patch by EPSS Probability (Threat Intel)"]

    print("\n--- BENCHMARK RESULTS AT BUDGET ₹1 CRORE ---")
    print(f"CRISP EAL Reduction: ₹{crisp_res['eal_reduction']:,.2f} (Efficiency: {crisp_res['reduction_per_rupee']}x)")
    print(f"CVSS  EAL Reduction: ₹{cvss_res['eal_reduction']:,.2f} (Efficiency: {cvss_res['reduction_per_rupee']}x)")
    print(f"EPSS  EAL Reduction: ₹{epss_res['eal_reduction']:,.2f} (Efficiency: {epss_res['reduction_per_rupee']}x)")
    print(f"Headline: {benchmark['headline']['proof_summary']}")

    assert crisp_res["eal_reduction"] > cvss_res["eal_reduction"], "CRISP must achieve higher total risk reduction than naive CVSS!"
    assert benchmark["headline"]["outperformance_vs_cvss_pct"] > 20.0, "CRISP must beat CVSS by significant margin!"
    assert crisp_res["spend"] <= budget, "Optimizer must strictly respect budget!"

if __name__ == "__main__":
    test_optimizer_benchmark()
    print("SUCCESS: Optimizer benchmark test passed!")
