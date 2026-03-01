"""Environment-based configuration for Triage Guard."""

from __future__ import annotations

import os

import torch


def get_device(override: str = "") -> str:
    """Resolve device: explicit override > CUDA > CPU."""
    device = override or os.environ.get("TRIAGE_GUARD_DEVICE", "")
    if device:
        return device
    return "cuda" if torch.cuda.is_available() else "cpu"


PORT: int = int(os.environ.get("TRIAGE_GUARD_PORT", "8080"))
LOG_LEVEL: str = os.environ.get("TRIAGE_GUARD_LOG_LEVEL", "info")

PROMPT_GUARD_MODEL_PATH: str = os.environ.get(
    "PROMPT_GUARD_MODEL_PATH", "/app/models/prompt_guard"
)
TOOL_GUARD_CHECKPOINT_PATH: str = os.environ.get(
    "TOOL_GUARD_CHECKPOINT_PATH", "/app/models/tool_guard"
)

DEVICE: str = get_device()
