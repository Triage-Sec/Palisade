"""Export the prompt guard model to ONNX format.

Usage:
    python services/prompt_guard/scripts/export_onnx.py [output_dir]

Output directory defaults to services/prompt_guard/model/
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

MODEL_NAME = "qualifire/prompt-injection-jailbreak-sentinel-v2"
DEFAULT_OUTPUT = "services/prompt_guard/model"


def export(output_dir: str) -> None:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    print(f"Loading model: {MODEL_NAME}")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)
    model.eval()

    # Dummy input for tracing
    dummy = tokenizer("test input", return_tensors="pt", truncation=True, max_length=512)

    print("Exporting to ONNX...")
    torch.onnx.export(
        model,
        (dummy["input_ids"], dummy["attention_mask"]),
        str(out / "model.onnx"),
        input_names=["input_ids", "attention_mask"],
        output_names=["logits"],
        dynamic_axes={
            "input_ids": {0: "batch", 1: "seq"},
            "attention_mask": {0: "batch", 1: "seq"},
            "logits": {0: "batch"},
        },
        opset_version=18,
    )

    # Save tokenizer files for local loading
    tokenizer.save_pretrained(str(out))

    # Copy config.json for id2label mapping
    config_src = Path(torch.hub.get_dir()).parent / "huggingface" / "hub"
    # Simpler: just save it directly
    model.config.to_json_file(str(out / "config.json"))

    print(f"Exported to {out}/")
    print(f"  model.onnx: {(out / 'model.onnx').stat().st_size / 1024 / 1024:.1f} MB")
    for f in sorted(out.iterdir()):
        print(f"  {f.name}")


if __name__ == "__main__":
    output = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_OUTPUT
    export(output)
