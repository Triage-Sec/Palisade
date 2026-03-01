"""Triage Guard — Unified ML inference service for prompt and tool safety."""

from __future__ import annotations

from contextlib import asynccontextmanager

import structlog
import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel

from triage_guard import config
from triage_guard.prompt_guard import PromptGuardModel
from triage_guard.tool_guard import ToolGuardModel

structlog.configure(
    wrapper_class=structlog.make_filtering_bound_logger(
        structlog.get_level_from_name(config.LOG_LEVEL)
    ),
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.JSONRenderer(),
    ],
)

logger = structlog.get_logger()

# Global model references set during lifespan
_prompt_guard: PromptGuardModel | None = None
_tool_guard: ToolGuardModel | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _prompt_guard, _tool_guard

    device = config.DEVICE
    logger.info("starting_triage_guard", device=device)

    _prompt_guard = PromptGuardModel(config.PROMPT_GUARD_MODEL_PATH, device=device)
    _tool_guard = ToolGuardModel(config.TOOL_GUARD_CHECKPOINT_PATH, device=device)

    logger.info("all_models_loaded")
    yield

    logger.info("shutting_down")
    _prompt_guard = None
    _tool_guard = None


app = FastAPI(title="Triage Guard", lifespan=lifespan)


# ── Request / Response schemas ──────────────────────────────────────────────


class PromptGuardRequest(BaseModel):
    text: str


class PromptGuardResponse(BaseModel):
    label: str
    confidence: float
    latency_ms: float


class ToolGuardRequest(BaseModel):
    user_request: str
    interaction_history: str = ""
    current_action: str = ""
    env_info: str = ""


class ToolGuardResponse(BaseModel):
    malicious: str
    attacked: str
    harmfulness: float
    composite_score: float
    latency_ms: float


class HealthResponse(BaseModel):
    status: str
    models: dict[str, bool]


# ── Routes ──────────────────────────────────────────────────────────────────


@app.post("/v1/prompt-guard", response_model=PromptGuardResponse)
async def prompt_guard_endpoint(req: PromptGuardRequest):
    import time

    start = time.monotonic()
    label, confidence = _prompt_guard.classify(req.text)
    elapsed_ms = (time.monotonic() - start) * 1000

    return PromptGuardResponse(
        label=label,
        confidence=round(confidence, 4),
        latency_ms=round(elapsed_ms, 2),
    )


@app.post("/v1/tool-guard", response_model=ToolGuardResponse)
async def tool_guard_endpoint(req: ToolGuardRequest):
    result = _tool_guard.classify(
        user_request=req.user_request,
        interaction_history=req.interaction_history,
        current_action=req.current_action,
        env_info=req.env_info,
    )
    return ToolGuardResponse(**result)


@app.get("/health", response_model=HealthResponse)
async def health():
    pg_ready = _prompt_guard is not None and _prompt_guard.ready
    tg_ready = _tool_guard is not None and _tool_guard.ready
    status = "ok" if (pg_ready and tg_ready) else "degraded"
    return HealthResponse(
        status=status,
        models={"prompt_guard": pg_ready, "tool_guard": tg_ready},
    )


if __name__ == "__main__":
    uvicorn.run(
        "triage_guard.main:app",
        host="0.0.0.0",
        port=config.PORT,
        log_level=config.LOG_LEVEL,
    )
