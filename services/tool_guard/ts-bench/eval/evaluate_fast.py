"""
Faster TS-Bench evaluation using batched inference.

Groups samples into batches for more efficient GPU/MPS utilization.
Also supports 8-bit quantization for faster inference on limited hardware.
"""

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from collections import Counter
from dataclasses import dataclass, field

import torch
from tqdm import tqdm
from sklearn.metrics import accuracy_score, f1_score, recall_score

# Import shared components from evaluate.py
from evaluate import (
    TSGUARD_PROMPT_TEMPLATE,
    parse_tsguard_output,
    filter_valid_pairs,
    load_dataset,
    format_prompt,
    DATASET_FILES,
    PAPER_RESULTS,
    print_comparison,
    EvalResult,
    compute_metrics,
    _save_intermediate,
)


class TSGuardModelBatched:
    """TS-Guard model with batched inference support."""

    def __init__(self, model_id_or_path: str, max_new_tokens: int = 1024, quantize_8bit: bool = False):
        from transformers import AutoModelForCausalLM, AutoTokenizer

        self.max_new_tokens = max_new_tokens

        print(f"Loading tokenizer from {model_id_or_path}...")
        self.tokenizer = AutoTokenizer.from_pretrained(
            model_id_or_path, trust_remote_code=True,
            padding_side="left",  # Important for batched generation
        )
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token

        if torch.cuda.is_available():
            device = "cuda"
            dtype = torch.bfloat16
        elif torch.backends.mps.is_available():
            device = "mps"
            dtype = torch.float16
        else:
            device = "cpu"
            dtype = torch.float32

        print(f"Loading model to {device} ({dtype})...")

        load_kwargs = dict(
            torch_dtype=dtype,
            trust_remote_code=True,
            low_cpu_mem_usage=True,
        )

        if quantize_8bit and device == "cuda":
            from transformers import BitsAndBytesConfig
            load_kwargs["quantization_config"] = BitsAndBytesConfig(load_in_8bit=True)
            load_kwargs["device_map"] = "auto"
        elif device == "cuda":
            load_kwargs["device_map"] = "auto"

        self.model = AutoModelForCausalLM.from_pretrained(
            model_id_or_path, **load_kwargs
        )
        if device == "mps":
            self.model = self.model.to(device)
        self.model.eval()

        self.device = device
        total_params = sum(p.numel() for p in self.model.parameters())
        print(f"Model loaded: {total_params/1e9:.2f}B params on {device}")

    def generate_batch(self, prompts: list[str]) -> list[str]:
        """Generate responses for a batch of prompts."""
        messages_batch = [[{"role": "user", "content": p}] for p in prompts]
        texts = [
            self.tokenizer.apply_chat_template(m, tokenize=False, add_generation_prompt=True)
            for m in messages_batch
        ]

        inputs = self.tokenizer(
            texts,
            return_tensors="pt",
            padding=True,
            truncation=True,
            max_length=4096,
        )
        inputs = {k: v.to(self.model.device) for k, v in inputs.items()}

        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=self.max_new_tokens,
                temperature=0.1,
                do_sample=True,
                top_p=0.9,
                pad_token_id=self.tokenizer.pad_token_id,
            )

        responses = []
        for i in range(len(prompts)):
            input_len = inputs["input_ids"][i].shape[0]
            response = self.tokenizer.decode(
                outputs[i][input_len:], skip_special_tokens=True
            )
            responses.append(response)

        return responses

    def generate(self, prompt: str) -> str:
        """Single prompt generation (fallback)."""
        return self.generate_batch([prompt])[0]


def evaluate_dataset_batched(
    model: TSGuardModelBatched,
    dataset_name: str,
    batch_size: int = 4,
    limit: int | None = None,
    output_dir: Path | None = None,
    resume: bool = True,
) -> EvalResult:
    """Run batched evaluation on a dataset."""

    samples = load_dataset(dataset_name)
    if limit:
        samples = samples[:limit]

    result = EvalResult(dataset=dataset_name, total_samples=len(samples))

    # Resume
    start_idx = 0
    if resume and output_dir:
        preds_path = output_dir / f"{dataset_name}_preds.json"
        labels_path = output_dir / f"{dataset_name}_labels.json"
        outputs_path = output_dir / f"{dataset_name}_outputs.json"
        if preds_path.exists() and labels_path.exists():
            with open(preds_path) as f:
                result.predictions = json.load(f)
            with open(labels_path) as f:
                result.labels = json.load(f)
            if outputs_path.exists():
                with open(outputs_path) as f:
                    result.raw_outputs = json.load(f)
            start_idx = len(result.predictions)
            if start_idx > 0:
                print(f"  Resuming from sample {start_idx}/{len(samples)}")

    remaining = samples[start_idx:]
    start_time = time.time()

    # Process in batches
    for batch_start in tqdm(
        range(0, len(remaining), batch_size),
        total=(len(remaining) + batch_size - 1) // batch_size,
        desc=f"Evaluating {dataset_name} (batch={batch_size})",
    ):
        batch = remaining[batch_start:batch_start + batch_size]
        prompts = [format_prompt(s) for s in batch]

        try:
            responses = model.generate_batch(prompts)
        except RuntimeError as e:
            # OOM fallback: process one at a time
            if "out of memory" in str(e).lower():
                print(f"\n  OOM with batch_size={batch_size}, falling back to batch_size=1")
                responses = [model.generate(p) for p in prompts]
            else:
                raise

        for sample, response in zip(batch, responses):
            rating, details = parse_tsguard_output(response)

            if rating == "error":
                result.parse_errors += 1
                result.predictions.append(None)
            else:
                result.predictions.append(rating)

            result.labels.append(sample["score"])
            result.raw_outputs.append({
                "sample_id": sample.get("id-interaction", ""),
                "segment_id": sample.get("id-segment", 0),
                "response": response[:2000],
                "parsed_rating": rating if rating != "error" else None,
                "parsed_details": details,
                "label": sample["score"],
            })

        # Checkpoint every 10 batches
        if output_dir and (batch_start // batch_size + 1) % 10 == 0:
            _save_intermediate(result, output_dir)

    result.total_time_s = time.time() - start_time

    if output_dir:
        _save_intermediate(result, output_dir)

    return result


def main():
    parser = argparse.ArgumentParser(description="Fast TS-Bench evaluation (batched)")
    parser.add_argument("--model-id", default="MurrayTom/TS-Guard")
    parser.add_argument("--model-path", default=None)
    parser.add_argument("--dataset", default="agentharm", choices=["agentharm", "asb", "agentdojo", "all"])
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--batch-size", type=int, default=4)
    parser.add_argument("--score-mode", default="strict", choices=["strict", "loose", "exact"])
    parser.add_argument("--output-dir", default="./results", help="Directory for output files")
    parser.add_argument("--quantize-8bit", action="store_true", help="Use 8-bit quantization (CUDA only)")
    parser.add_argument("--no-resume", action="store_true")
    parser.add_argument("--max-new-tokens", type=int, default=1024)
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    model_source = args.model_path or args.model_id
    model = TSGuardModelBatched(
        model_source,
        max_new_tokens=args.max_new_tokens,
        quantize_8bit=args.quantize_8bit,
    )

    datasets = list(DATASET_FILES.keys()) if args.dataset == "all" else [args.dataset]

    all_metrics = {}
    for ds_name in datasets:
        print(f"\n{'#' * 70}")
        print(f"# Evaluating: {ds_name}")
        print(f"{'#' * 70}")

        result = evaluate_dataset_batched(
            model, ds_name,
            batch_size=args.batch_size,
            limit=args.limit,
            output_dir=output_dir,
            resume=not args.no_resume,
        )

        metrics = compute_metrics(result, args.score_mode)
        all_metrics[ds_name] = metrics
        print_comparison(ds_name, metrics, args.score_mode)

    # Summary
    print(f"\n\n{'=' * 70}")
    print(f"  SUMMARY ({args.score_mode} mode)")
    print(f"{'=' * 70}")
    for ds_name, metrics in all_metrics.items():
        print(f"  {ds_name:<12}  ACC={metrics['accuracy']:.4f}  F1={metrics['f1']:.4f}  Recall={metrics['recall']:.4f}")

    summary_path = output_dir / "summary.json"
    with open(summary_path, "w") as f:
        json.dump({
            "model": model_source,
            "score_mode": args.score_mode,
            "batch_size": args.batch_size,
            "results": all_metrics,
            "paper_results": PAPER_RESULTS,
        }, f, indent=2)
    print(f"\n  Results saved to {summary_path}")


if __name__ == "__main__":
    main()
