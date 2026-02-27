#!/usr/bin/env python3
"""Step 4: Evaluate the distilled classifier against TS-Bench.

Runs the classifier (PyTorch or ONNX) on all 3 TS-Bench datasets and
compares accuracy, F1, recall against the TS-Guard 7B teacher.

Usage:
    # Evaluate PyTorch checkpoint:
    python eval_classifier.py --checkpoint ./checkpoints/best_model

    # Evaluate ONNX model:
    python eval_classifier.py --onnx ./onnx_model/model.onnx

    # Evaluate on specific dataset:
    python eval_classifier.py --checkpoint ./checkpoints/best_model --dataset agentharm
"""

import argparse
import json
import os
import time
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import torch
from tqdm import tqdm
from sklearn.metrics import accuracy_score, f1_score, recall_score, precision_score

from train_classifier import (
    ToolSafetyClassifier,
    ToolSafetyDataset,
    TSGUARD_PROMPT_TEMPLATE,
    compute_composite_score,
)


# ── TS-Guard 7B reference results (from paper Table 3, strict scoring) ─────

TEACHER_RESULTS = {
    "agentharm": {"acc": 0.8482, "f1": 0.9017, "recall": 0.9695},
    "asb": {"acc": 0.9493, "f1": 0.9472, "recall": 0.9377},
    "agentdojo": {"acc": 0.9172, "f1": 0.8882, "recall": 0.8409},
}


# ── Data loading ────────────────────────────────────────────────────────────

def find_tsbench_root() -> Path:
    script_dir = Path(__file__).parent
    candidates = [
        script_dir.parent / "ToolSafe" / "TS-Bench",
        script_dir / "TS-Bench",
        Path("TS-Bench"),
        Path("ToolSafe") / "TS-Bench",
    ]
    for c in candidates:
        if c.exists():
            return c
    raise FileNotFoundError("Cannot find TS-Bench directory.")


DATASET_FILES = {
    "agentharm": [
        "agentharm-traj/harmful_steps.json",
        "agentharm-traj/benign_steps.json",
    ],
    "asb": [
        "asb-traj/test/DPI_attack_success.json",
        "asb-traj/test/OPI_attack_success.json",
        "asb-traj/test/atttack_failure.json",
    ],
    "agentdojo": [
        "agentdojo-traj/workspace.json",
        "agentdojo-traj/travel.json",
        "agentdojo-traj/slack.json",
        "agentdojo-traj/banking.json",
    ],
}


def load_dataset(data_dir: Path, dataset_name: str) -> list[dict]:
    samples = []
    for rel_path in DATASET_FILES[dataset_name]:
        path = data_dir / rel_path
        if not path.exists():
            print(f"  WARNING: {path} not found")
            continue
        with open(path) as f:
            data = json.load(f)
        samples.extend(data)
    return samples


# ── Inference ───────────────────────────────────────────────────────────────

def predict_pytorch(model, tokenizer, samples, device, max_length=1024, batch_size=8):
    """Run inference with PyTorch model, return predictions and latencies."""
    model.eval()
    all_preds = []
    all_latencies = []

    for i in tqdm(range(0, len(samples), batch_size), desc="Predicting"):
        batch_samples = samples[i : i + batch_size]
        prompts = []
        for s in batch_samples:
            agent_action = {
                "interaction_history": s.get("history", ""),
                "current_action": s.get("current_action", ""),
            }
            prompts.append(TSGUARD_PROMPT_TEMPLATE.format(
                user_request=s["instruction"],
                agent_action=agent_action,
                env_info=s.get("env_info", ""),
            ))

        encoding = tokenizer(
            prompts,
            max_length=max_length,
            truncation=True,
            padding=True,
            return_tensors="pt",
        ).to(device)

        t0 = time.perf_counter()
        with torch.no_grad():
            logits_m, logits_a, logits_h = model(
                encoding["input_ids"], encoding["attention_mask"]
            )
        latency = (time.perf_counter() - t0) * 1000  # ms

        preds_m = logits_m.argmax(1).cpu().tolist()
        preds_a = logits_a.argmax(1).cpu().tolist()
        preds_h = logits_h.argmax(1).cpu().tolist()

        for m, a, h in zip(preds_m, preds_a, preds_h):
            all_preds.append({
                "malicious": m,
                "attacked": a,
                "harmfulness": h,
                "composite": compute_composite_score(m, a, h),
            })
        all_latencies.append(latency / len(batch_samples))  # per-sample

    return all_preds, all_latencies


def predict_onnx(onnx_path, tokenizer, samples, max_length=1024, batch_size=1):
    """Run inference with ONNX model, return predictions and latencies."""
    import onnxruntime as ort

    providers = ort.get_available_providers()
    use_gpu = "CUDAExecutionProvider" in providers
    session_providers = (
        ["CUDAExecutionProvider", "CPUExecutionProvider"]
        if use_gpu
        else ["CPUExecutionProvider"]
    )
    session = ort.InferenceSession(onnx_path, providers=session_providers)
    print(f"  ONNX provider: {session.get_providers()[0]}")

    all_preds = []
    all_latencies = []

    for i in tqdm(range(0, len(samples), batch_size), desc="Predicting (ONNX)"):
        batch_samples = samples[i : i + batch_size]
        prompts = []
        for s in batch_samples:
            agent_action = {
                "interaction_history": s.get("history", ""),
                "current_action": s.get("current_action", ""),
            }
            prompts.append(TSGUARD_PROMPT_TEMPLATE.format(
                user_request=s["instruction"],
                agent_action=agent_action,
                env_info=s.get("env_info", ""),
            ))

        encoding = tokenizer(
            prompts,
            max_length=max_length,
            truncation=True,
            padding="max_length",
            return_tensors="np",
        )

        t0 = time.perf_counter()
        logits_m, logits_a, logits_h = session.run(None, {
            "input_ids": encoding["input_ids"],
            "attention_mask": encoding["attention_mask"],
        })
        latency = (time.perf_counter() - t0) * 1000

        preds_m = np.argmax(logits_m, axis=1).tolist()
        preds_a = np.argmax(logits_a, axis=1).tolist()
        preds_h = np.argmax(logits_h, axis=1).tolist()

        for m, a, h in zip(preds_m, preds_a, preds_h):
            all_preds.append({
                "malicious": m,
                "attacked": a,
                "harmfulness": h,
                "composite": compute_composite_score(m, a, h),
            })
        all_latencies.append(latency / len(batch_samples))

    return all_preds, all_latencies


# ── Evaluation ──────────────────────────────────────────────────────────────

def evaluate_dataset(preds, labels, dataset_name):
    """Compute metrics and print comparison with teacher."""

    # Strict scoring: 0→0, 0.5→1, 1→1
    def to_strict(v):
        return 0 if v == 0.0 else 1

    pred_strict = [to_strict(p["composite"]) for p in preds]
    label_strict = [to_strict(float(l)) for l in labels]

    acc = accuracy_score(label_strict, pred_strict)
    f1 = f1_score(label_strict, pred_strict, average="binary", zero_division=0)
    recall = recall_score(label_strict, pred_strict, average="binary", zero_division=0)
    precision = precision_score(label_strict, pred_strict, average="binary", zero_division=0)

    teacher = TEACHER_RESULTS.get(dataset_name, {})

    return {
        "n_samples": len(preds),
        "accuracy": acc,
        "f1": f1,
        "recall": recall,
        "precision": precision,
        "teacher_accuracy": teacher.get("acc"),
        "teacher_f1": teacher.get("f1"),
        "teacher_recall": teacher.get("recall"),
    }


def print_results(results: dict, latencies: list, dataset_name: str):
    """Pretty-print results with teacher comparison."""
    w = 70
    print(f"\n{'='*w}")
    print(f"  {dataset_name.upper()} — {results['n_samples']} samples")
    print(f"{'='*w}")

    metrics = [
        ("Accuracy", "accuracy", "teacher_accuracy"),
        ("F1", "f1", "teacher_f1"),
        ("Recall", "recall", "teacher_recall"),
    ]

    print(f"  {'Metric':<12} {'Student':>10} {'Teacher (7B)':>14} {'Delta':>10}")
    print(f"  {'-'*46}")
    for label, key, teacher_key in metrics:
        student_val = results[key]
        teacher_val = results.get(teacher_key)
        if teacher_val is not None:
            delta = student_val - teacher_val
            delta_str = f"{delta:+.2%}"
        else:
            delta_str = "N/A"
        print(f"  {label:<12} {student_val:>10.2%} {teacher_val or 0:>14.2%} {delta_str:>10}")

    if latencies:
        avg_lat = sum(latencies) / len(latencies)
        p50 = sorted(latencies)[len(latencies) // 2]
        p99 = sorted(latencies)[int(len(latencies) * 0.99)]
        print(f"\n  Latency — avg: {avg_lat:.1f}ms, p50: {p50:.1f}ms, p99: {p99:.1f}ms")
    print(f"{'='*w}")


# ── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Evaluate distilled classifier")
    parser.add_argument("--checkpoint", help="Path to PyTorch best_model dir")
    parser.add_argument("--onnx", help="Path to ONNX model file")
    parser.add_argument("--data-dir", help="Path to TS-Bench directory")
    parser.add_argument("--dataset", choices=["agentharm", "asb", "agentdojo", "all"], default="all")
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--max-length", type=int, default=1024)
    args = parser.parse_args()

    if not args.checkpoint and not args.onnx:
        parser.error("Must provide --checkpoint or --onnx")

    data_dir = Path(args.data_dir) if args.data_dir else find_tsbench_root()
    datasets = list(DATASET_FILES.keys()) if args.dataset == "all" else [args.dataset]

    # Load model
    if args.onnx:
        from transformers import AutoTokenizer
        # Look for tokenizer in same directory as ONNX model
        onnx_dir = str(Path(args.onnx).parent)
        tokenizer = AutoTokenizer.from_pretrained(onnx_dir, trust_remote_code=True)
        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token
        predict_fn = lambda samples: predict_onnx(
            args.onnx, tokenizer, samples, args.max_length, batch_size=1
        )
        print(f"Using ONNX model: {args.onnx}")
    else:
        config_path = Path(args.checkpoint) / "config.json"
        with open(config_path) as f:
            config = json.load(f)

        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        tokenizer = AutoTokenizer.from_pretrained(args.checkpoint, trust_remote_code=True)
        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token

        model = ToolSafetyClassifier(config["base_model_name"])
        ckpt = torch.load(
            str(Path(args.checkpoint) / "model.pt"), map_location=device, weights_only=False
        )
        model.load_state_dict(ckpt["model_state_dict"])
        model = model.to(device)
        print(f"Using PyTorch model on {device}")

        predict_fn = lambda samples: predict_pytorch(
            model, tokenizer, samples, device, args.max_length, args.batch_size
        )

    # Evaluate each dataset
    all_results = {}
    for ds_name in datasets:
        print(f"\n--- Loading {ds_name} ---")
        samples = load_dataset(data_dir, ds_name)
        print(f"  {len(samples)} samples")

        labels = [s["score"] for s in samples]

        preds, latencies = predict_fn(samples)

        results = evaluate_dataset(preds, labels, ds_name)
        print_results(results, latencies, ds_name)
        all_results[ds_name] = results

    # Summary
    if len(datasets) > 1:
        print(f"\n{'='*70}")
        print(f"  SUMMARY")
        print(f"{'='*70}")
        print(f"  {'Dataset':<12} {'ACC':>8} {'F1':>8} {'Recall':>8} {'vs Teacher F1':>14}")
        print(f"  {'-'*50}")
        for ds_name, results in all_results.items():
            teacher_f1 = results.get("teacher_f1", 0)
            delta_f1 = results["f1"] - teacher_f1 if teacher_f1 else 0
            print(f"  {ds_name:<12} {results['accuracy']:>8.2%} {results['f1']:>8.2%} "
                  f"{results['recall']:>8.2%} {delta_f1:>+14.2%}")
        print(f"{'='*70}")


if __name__ == "__main__":
    main()
