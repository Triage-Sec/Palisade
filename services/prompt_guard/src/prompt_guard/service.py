"""PromptGuardService gRPC implementation."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import grpc
import structlog

from prompt_guard.gen.prompt_guard.v1 import prompt_guard_pb2, prompt_guard_pb2_grpc

if TYPE_CHECKING:
    from prompt_guard.model import PromptGuardModel

logger = structlog.get_logger()


class PromptGuardServicer(prompt_guard_pb2_grpc.PromptGuardServiceServicer):
    """Implements the PromptGuardService gRPC interface."""

    def __init__(self, model: PromptGuardModel) -> None:
        self._model = model

    def Classify(
        self,
        request: prompt_guard_pb2.ClassifyRequest,
        context: grpc.ServicerContext,
    ) -> prompt_guard_pb2.ClassifyResponse:
        if not request.text:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "text is required")

        start = time.monotonic()
        label, confidence = self._model.classify(request.text)
        elapsed_ms = (time.monotonic() - start) * 1000

        logger.info(
            "classify",
            label=label,
            confidence=round(confidence, 4),
            latency_ms=round(elapsed_ms, 2),
            text_len=len(request.text),
        )

        return prompt_guard_pb2.ClassifyResponse(
            label=label,
            confidence=confidence,
            latency_ms=elapsed_ms,
            model_name=self._model.model_name,
        )

    def ClassifyBatch(
        self,
        request: prompt_guard_pb2.ClassifyBatchRequest,
        context: grpc.ServicerContext,
    ) -> prompt_guard_pb2.ClassifyBatchResponse:
        results = []
        for text in request.texts:
            start = time.monotonic()
            label, confidence = self._model.classify(text)
            elapsed_ms = (time.monotonic() - start) * 1000
            results.append(
                prompt_guard_pb2.ClassifyResponse(
                    label=label,
                    confidence=confidence,
                    latency_ms=elapsed_ms,
                    model_name=self._model.model_name,
                )
            )

        logger.info("classify_batch", count=len(request.texts))
        return prompt_guard_pb2.ClassifyBatchResponse(results=results)

    def ModelInfo(
        self,
        request: prompt_guard_pb2.ModelInfoRequest,
        context: grpc.ServicerContext,
    ) -> prompt_guard_pb2.ModelInfoResponse:
        return prompt_guard_pb2.ModelInfoResponse(
            model_name=self._model.model_name,
            ready=self._model.ready,
            device=self._model.device,
        )
