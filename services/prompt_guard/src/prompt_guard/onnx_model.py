"""ONNX Runtime model for prompt injection detection (CPU-optimized)."""

from __future__ import annotations

import time

import numpy as np
import structlog
from tokenizers import Tokenizer

logger = structlog.get_logger()


class ONNXPromptGuardModel:
    """ONNX Runtime inference — no PyTorch dependency, CPU-only."""

    def __init__(self, model_path: str) -> None:
        import onnxruntime as ort

        self._model_name = "qualifire/prompt-injection-jailbreak-sentinel-v2"

        logger.info("loading_onnx_model", path=model_path)
        start = time.monotonic()

        # ONNX Runtime session with CPU optimizations
        opts = ort.SessionOptions()
        opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        opts.intra_op_num_threads = 4
        opts.inter_op_num_threads = 1

        self._session = ort.InferenceSession(
            f"{model_path}/model.onnx",
            sess_options=opts,
            providers=["CPUExecutionProvider"],
        )

        # Load tokenizer from local files (baked into image)
        self._tokenizer = Tokenizer.from_file(f"{model_path}/tokenizer.json")
        self._tokenizer.enable_truncation(max_length=512)
        self._tokenizer.enable_padding()

        # Label mapping from config
        import json
        with open(f"{model_path}/config.json") as f:
            config = json.load(f)
        self._id2label = {int(k): v for k, v in config["id2label"].items()}

        elapsed_ms = (time.monotonic() - start) * 1000
        logger.info("onnx_model_loaded", elapsed_ms=round(elapsed_ms, 1))

        self._warmup()

    @property
    def model_name(self) -> str:
        return self._model_name

    @property
    def device(self) -> str:
        return "cpu-onnx"

    @property
    def ready(self) -> bool:
        return self._session is not None

    def classify(self, text: str) -> tuple[str, float]:
        """Classify text. Returns (label, confidence)."""
        start = time.monotonic()

        encoding = self._tokenizer.encode(text)
        input_ids = np.array([encoding.ids], dtype=np.int64)
        attention_mask = np.array([encoding.attention_mask], dtype=np.int64)

        outputs = self._session.run(
            None,
            {"input_ids": input_ids, "attention_mask": attention_mask},
        )

        logits = outputs[0][0]
        probs = _softmax(logits)
        predicted_idx = int(np.argmax(probs))
        confidence = float(probs[predicted_idx])
        label = self._id2label[predicted_idx]

        elapsed_ms = (time.monotonic() - start) * 1000
        logger.debug(
            "onnx_inference_complete",
            label=label,
            confidence=round(confidence, 4),
            elapsed_ms=round(elapsed_ms, 2),
        )

        return label, confidence

    def _warmup(self) -> None:
        """Run dummy inference to prime ONNX session."""
        logger.info("warming_up_onnx_model")
        start = time.monotonic()
        self.classify("This is a warmup sentence.")
        elapsed_ms = (time.monotonic() - start) * 1000
        logger.info("onnx_warmup_complete", elapsed_ms=round(elapsed_ms, 1))


def _softmax(x: np.ndarray) -> np.ndarray:
    e = np.exp(x - np.max(x))
    return e / e.sum()
