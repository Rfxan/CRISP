"""Reproduce a benchmark from an explicit snapshot without importing the API."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.core.config import DATA_DIR
from app.engine.fair_engine import FAIREngine
from app.engine.optimizer import InvestmentOptimizer


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', type=Path, help='Input snapshot JSON; use app/data/seed_snapshot.json for an explicitly synthetic example')
    parser.add_argument('--budget', type=float, default=10_000_000)
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--trials', type=int, default=5000)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    snapshot = json.loads(args.snapshot.read_text(encoding='utf-8'))
    snapshot.setdefault('controls_catalog', json.loads((DATA_DIR/'controls_catalog.json').read_text(encoding='utf-8')))
    engine = FAIREngine(trials=args.trials, seed=args.seed)
    optimizer = InvestmentOptimizer(snapshot['controls_catalog'], snapshot.get('findings', []), snapshot.get('cve_intel', {}),
                                    snapshot=snapshot, engine=engine, seed=args.seed)
    result = optimizer.run_benchmark(budget=args.budget)
    result['dataset'] = str(args.snapshot)
    rendered = json.dumps(result, indent=2, ensure_ascii=True, allow_nan=False)
    if args.output:
        args.output.write_text(rendered, encoding='utf-8')
    else:
        print(rendered)


if __name__ == '__main__':
    main()
