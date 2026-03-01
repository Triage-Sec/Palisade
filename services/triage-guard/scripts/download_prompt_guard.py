#!/usr/bin/env python3
"""Download the prompt guard model from HuggingFace and save locally.

Run once before Docker build:
    cd services/triage-guard
    python scripts/download_prompt_guard.py

Set HF_TOKEN env var if the model is gated.
"""

from pathlib import Path

from transformers import AutoModelForSequenceClassification, AutoTokenizer

MODEL_NAME = "qualifire/prompt-injection-jailbreak-sentinel-v2"
OUTPUT_DIR = Path(__file__).resolve().parent.parent / "models" / "prompt_guard"


def main():
    print(f"Downloading {MODEL_NAME} ...")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    tokenizer.save_pretrained(str(OUTPUT_DIR))
    print(f"  Tokenizer saved to {OUTPUT_DIR}")

    model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)
    model.save_pretrained(str(OUTPUT_DIR))
    print(f"  Model saved to {OUTPUT_DIR}")

    print("Done.")


if __name__ == "__main__":
    main()
