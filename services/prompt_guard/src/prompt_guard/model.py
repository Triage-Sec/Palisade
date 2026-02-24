"""HuggingFace model loading and inference."""

from __future__ import annotations

import time

import structlog
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

logger = structlog.get_logger()


class PromptGuardModel:
    """Wraps a HuggingFace text classifier for prompt injection detection."""

    def __init__(self, model_name: str, device: str = "") -> None:
        self._model_name = model_name
        self._device = self._resolve_device(device)

        logger.info("loading_model", model=model_name, device=self._device)
        start = time.monotonic()

        self._tokenizer = AutoTokenizer.from_pretrained(model_name)
        self._model = AutoModelForSequenceClassification.from_pretrained(
            model_name,
            torch_dtype=torch.float16 if self._device == "cuda" else torch.float32,
        )
        self._model.to(self._device)
        self._model.eval()

        elapsed_ms = (time.monotonic() - start) * 1000
        logger.info("model_loaded", model=model_name, device=self._device, elapsed_ms=round(elapsed_ms, 1))

        self._warmup()

    @property
    def model_name(self) -> str:
        return self._model_name

    @property
    def device(self) -> str:
        return self._device

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
            "inference_complete",
            label=label,
            confidence=round(confidence, 4),
            elapsed_ms=round(elapsed_ms, 2),
        )

        return label, confidence

    def _warmup(self) -> None:
        """Run dummy inference to JIT CUDA kernels."""
        logger.info("warming_up_model")
        start = time.monotonic()
        self.classify("This is a warmup sentence.")
        elapsed_ms = (time.monotonic() - start) * 1000
        logger.info("warmup_complete", elapsed_ms=round(elapsed_ms, 1))

    @staticmethod
    def _resolve_device(device: str) -> str:
        if device:
            return device
        if torch.cuda.is_available():
            return "cuda"
        return "cpu"
