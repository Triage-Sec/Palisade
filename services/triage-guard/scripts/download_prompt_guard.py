#!/usr/bin/env python3
"""Download the prompt guard model from HuggingFace and save locally.

Usage:
    # Default (saves to models/prompt_guard/ relative to this script)
    cd services/triage-guard && python scripts/download_prompt_guard.py

    # Custom output directory (used by Dockerfile)
    python download_prompt_guard.py --output /download/prompt_guard

Set HF_TOKEN env var if the model is gated.
"""

import argparse
from pathlib import Path

from transformers import AutoModelForSequenceClassification, AutoTokenizer

MODEL_NAME = "qualifire/prompt-injection-jailbreak-sentinel-v2"
DEFAULT_OUTPUT = Path(__file__).resolve().parent.parent / "models" / "prompt_guard"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    output_dir = args.output
    print(f"Downloading {MODEL_NAME} to {output_dir} ...")
    output_dir.mkdir(parents=True, exist_ok=True)

    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    tokenizer.save_pretrained(str(output_dir))
    print(f"  Tokenizer saved to {output_dir}")

    model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)
    model.save_pretrained(str(output_dir))
    print(f"  Model saved to {output_dir}")

    print("Done.")


if __name__ == "__main__":
    main()
