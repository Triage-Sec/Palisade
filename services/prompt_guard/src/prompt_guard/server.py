"""gRPC server bootstrap and graceful shutdown."""

from __future__ import annotations

import signal
import sys
from concurrent import futures
from threading import Event

import grpc
import structlog
from grpc_health.v1 import health, health_pb2, health_pb2_grpc
from grpc_reflection.v1alpha import reflection

from prompt_guard.config import Config
from prompt_guard.gen.prompt_guard.v1 import prompt_guard_pb2, prompt_guard_pb2_grpc
from prompt_guard.model import PromptGuardModel
from prompt_guard.service import PromptGuardServicer

logger = structlog.get_logger()

SERVICE_NAME = "triage.prompt_guard.v1.PromptGuardService"


def configure_logging(level: str) -> None:
    """Configure structlog with JSON output."""
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            _level_to_int(level),
        ),
    )


def _level_to_int(level: str) -> int:
    return {
        "debug": 10,
        "info": 20,
        "warn": 30,
        "warning": 30,
        "error": 40,
    }.get(level.lower(), 20)


def serve() -> None:
    """Start the gRPC server."""
    cfg = Config.from_env()
    configure_logging(cfg.log_level)

    logger.info(
        "starting_prompt_guard",
        port=cfg.port,
        model=cfg.model_name,
        max_workers=cfg.max_workers,
        device=cfg.device or "auto",
    )

    # Load model (downloads from HuggingFace Hub on first run)
    model = PromptGuardModel(cfg.model_name, cfg.device)

    # gRPC server
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=cfg.max_workers),
        options=[
            ("grpc.max_receive_message_length", 4 * 1024 * 1024),
            ("grpc.max_send_message_length", 4 * 1024 * 1024),
            ("grpc.keepalive_time_ms", 30_000),
            ("grpc.keepalive_timeout_ms", 5_000),
            ("grpc.keepalive_permit_without_calls", 1),
        ],
    )

    # Register service
    servicer = PromptGuardServicer(model)
    prompt_guard_pb2_grpc.add_PromptGuardServiceServicer_to_server(servicer, server)

    # Health checks
    health_servicer = health.HealthServicer()
    health_pb2_grpc.add_HealthServicer_to_server(health_servicer, server)
    health_servicer.set(SERVICE_NAME, health_pb2.HealthCheckResponse.SERVING)

    # Reflection for grpcurl debugging
    reflection.enable_server_reflection(
        [
            prompt_guard_pb2.DESCRIPTOR.services_by_name["PromptGuardService"].full_name,
            reflection.SERVICE_NAME,
            health.SERVICE_NAME,
        ],
        server,
    )

    server.add_insecure_port(f"[::]:{cfg.port}")

    # Graceful shutdown
    stop_event = Event()

    def _shutdown(signum: int, _frame: object) -> None:
        sig_name = signal.Signals(signum).name
        logger.info("received_signal", signal=sig_name)
        health_servicer.set(SERVICE_NAME, health_pb2.HealthCheckResponse.NOT_SERVING)
        server.stop(grace=10)
        stop_event.set()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    server.start()
    logger.info("prompt_guard_listening", addr=f"[::]:{cfg.port}")

    stop_event.wait()
    logger.info("prompt_guard_stopped")


def main() -> None:
    """Entrypoint."""
    try:
        serve()
    except Exception:
        logger.exception("fatal_error")
        sys.exit(1)


if __name__ == "__main__":
    main()
