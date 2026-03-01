"""Prompt injection / jailbreak detection model."""

from __future__ import annotations

import time

import structlog
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

logger = structlog.get_logger()


class PromptGuardModel:
    """Wraps the qualifire/prompt-injection-jailbreak-sentinel-v2 classifier."""

    def __init__(self, model_path: str, device: str = "cpu") -> None:
        self._model_path = model_path
        self._device = device

        logger.info("loading_prompt_guard", path=model_path, device=device)
        start = time.monotonic()

        self._tokenizer = AutoTokenizer.from_pretrained(model_path)
        self._model = AutoModelForSequenceClassification.from_pretrained(
            model_path,
            torch_dtype=torch.float16 if device == "cuda" else torch.float32,
        )
        self._model.to(device)
        self._model.eval()

        elapsed_ms = (time.monotonic() - start) * 1000
        logger.info("prompt_guard_loaded", device=device, elapsed_ms=round(elapsed_ms, 1))

        self._warmup()

    @property
    def ready(self) -> bool:
        return self._model is not None

    def classify(self, text: str) -> tuple[str, float]:
        """Classify text. Returns (label, confidence)."""
        start = time.monotonic()

        inputs = self._tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=512,
            padding=True,
        )
        inputs = {k: v.to(self._device) for k, v in inputs.items()}

        with torch.no_grad():
            outputs = self._model(**inputs)

        probs = torch.softmax(outputs.logits, dim=-1)
        predicted_idx = torch.argmax(probs, dim=-1).item()
        confidence = probs[0][predicted_idx].item()
        label = self._model.config.id2label[predicted_idx]

        elapsed_ms = (time.monotonic() - start) * 1000
        logger.debug(
            "prompt_guard_inference",
            label=label,
            confidence=round(confidence, 4),
            elapsed_ms=round(elapsed_ms, 2),
        )

        return label, confidence

    def _warmup(self) -> None:
        logger.info("warming_up_prompt_guard")
        start = time.monotonic()
        self.classify("This is a warmup sentence.")
        elapsed_ms = (time.monotonic() - start) * 1000
        logger.info("prompt_guard_warmup_complete", elapsed_ms=round(elapsed_ms, 1))
