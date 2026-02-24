"""Typed configuration from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    """Service configuration loaded from environment variables."""

    port: int = 50052
    model_name: str = "qualifire/prompt-injection-jailbreak-sentinel-v2"
    max_workers: int = 4
    log_level: str = "info"
    device: str = ""  # empty = auto-detect (cuda if available, else cpu)

    @classmethod
    def from_env(cls) -> Config:
        return cls(
            port=int(os.getenv("PROMPT_GUARD_PORT", "50052")),
            model_name=os.getenv(
                "PROMPT_GUARD_MODEL_NAME",
                "qualifire/prompt-injection-jailbreak-sentinel-v2",
            ),
            max_workers=int(os.getenv("PROMPT_GUARD_MAX_WORKERS", "4")),
            log_level=os.getenv("PROMPT_GUARD_LOG_LEVEL", "info"),
            device=os.getenv("PROMPT_GUARD_DEVICE", ""),
        )
