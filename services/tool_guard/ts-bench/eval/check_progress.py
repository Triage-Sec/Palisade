"""Check progress of a running evaluation."""

import json
import sys
from pathlib import Path
from evaluate import compute_metrics, PAPER_RESULTS, print_comparison, EvalResult

def check(results_dir: str = "./results", dataset: str = "agentharm"):
    d = Path(results_dir)
    preds_path = d / f"{dataset}_preds.json"
    labels_path = d / f"{dataset}_labels.json"

    if not preds_path.exists():
        print(f"No results found at {preds_path}")
        return

    with open(preds_path) as f:
        preds = json.load(f)
    with open(labels_path) as f:
        labels = json.load(f)

    total_map = {
        "agentharm": 731,
        "asb": 5231,
        "agentdojo": 1220,
    }
    total = total_map.get(dataset, len(preds))
    parse_errors = sum(1 for p in preds if p is None)

    print(f"Progress: {len(preds)}/{total} samples ({len(preds)/total*100:.1f}%)")
    print(f"Parse errors: {parse_errors}")

    result = EvalResult(
        dataset=dataset,
        total_samples=total,
        predictions=preds,
        labels=labels,
        parse_errors=parse_errors,
    )

    for mode in ["strict", "loose"]:
        metrics = compute_metrics(result, mode)
        print_comparison(dataset, metrics, mode)


if __name__ == "__main__":
    dataset = sys.argv[1] if len(sys.argv) > 1 else "agentharm"
    results_dir = sys.argv[2] if len(sys.argv) > 2 else "./results"
    check(results_dir, dataset)
