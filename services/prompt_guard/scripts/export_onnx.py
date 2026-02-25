"""Export the prompt guard model to ONNX format via optimum.

Usage:
    pip install optimum[onnxruntime] transformers
    python services/prompt_guard/scripts/export_onnx.py [output_dir]

Output directory defaults to services/prompt_guard/model/
"""

from __future__ import annotations

import sys
from pathlib import Path

from optimum.onnxruntime import ORTModelForSequenceClassification
from transformers import AutoTokenizer

MODEL_NAME = "qualifire/prompt-injection-jailbreak-sentinel-v2"
DEFAULT_OUTPUT = "services/prompt_guard/model"


def export(output_dir: str) -> None:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    print(f"Loading and exporting model: {MODEL_NAME}")
    model = ORTModelForSequenceClassification.from_pretrained(MODEL_NAME, export=True)
    model.save_pretrained(str(out))

    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    tokenizer.save_pretrained(str(out))

    print(f"Exported to {out}/")
    for f in sorted(out.iterdir()):
        size_mb = f.stat().st_size / 1024 / 1024
        print(f"  {f.name}: {size_mb:.1f} MB")


if __name__ == "__main__":
    output = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_OUTPUT
    export(output)
