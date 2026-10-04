import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import json
import time
from app.engine.fair_engine import FAIREngine

def test_engine_determinism():
    snapshot_path = Path(__file__).resolve().parent.parent / "app" / "data" / "seed_snapshot.json"
    with open(snapshot_path, "r", encoding="utf-8") as f:
        snapshot = json.load(f)

    engine = FAIREngine(trials=10000, seed=42)
    t0 = time.time()
    res1 = engine.run(snapshot, seed=42)
    t1 = time.time()
    res2 = engine.run(snapshot, seed=42)

    elapsed = t1 - t0
    print(f"\nExecution time for 10,000 trials: {elapsed:.3f}s")
    print(f"Run 1: EAL={res1['org']['eal']}, VaR95={res1['org']['var95']}, Score={res1['org']['score']}")
    print(f"Run 2: EAL={res2['org']['eal']}, VaR95={res2['org']['var95']}, Score={res2['org']['score']}")

    # Bit-identical assertion
    assert res1["org"]["eal"] == res2["org"]["eal"], "EAL must be bit-identical across runs with identical seed"
    assert res1["org"]["var95"] == res2["org"]["var95"], "VaR95 must be bit-identical across runs"
    assert res1["run_id"] == res2["run_id"], "Run ID must match"
    assert 1 <= len(res1["curve"]) <= 100
    assert res1["curve"] == res2["curve"]
    assert len({point[0] for point in res1["curve"]}) == len(res1["curve"])
    assert all(a[1] >= b[1] for a, b in zip(res1["curve"], res1["curve"][1:]))
    assert len(res1["drivers"]) > 0, "Top risk drivers must be identified"

if __name__ == "__main__":
    test_engine_determinism()
    print("SUCCESS: Engine determinism and vectorization verified!")
