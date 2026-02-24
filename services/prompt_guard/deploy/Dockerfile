# === Builder ===
FROM python:3.11-slim AS builder

WORKDIR /build

# Create venv and install dependencies first (cached layer).
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY services/prompt_guard/pyproject.toml ./
RUN pip install --no-cache-dir ".[dev]" && \
    pip install --no-cache-dir grpcio-health-checking grpcio-reflection

# Copy proto and generate stubs.
COPY proto/ /proto/
COPY services/prompt_guard/ ./

RUN python -m grpc_tools.protoc \
    -I /proto \
    --python_out=src/prompt_guard/gen \
    --grpc_python_out=src/prompt_guard/gen \
    --pyi_out=src/prompt_guard/gen \
    /proto/prompt_guard/v1/prompt_guard.proto && \
    sed -i 's/from prompt_guard\.v1 import/from prompt_guard.gen.prompt_guard.v1 import/' \
    src/prompt_guard/gen/prompt_guard/v1/prompt_guard_pb2_grpc.py

# === Runtime ===
# PyTorch ships its own CUDA libraries bundled in the wheel.
# No need for the nvidia/cuda base image — python:3.11-slim is sufficient.
# The g4dn instance provides the NVIDIA driver; PyTorch handles the rest.
FROM python:3.11-slim

RUN useradd -r -d /app promptguard

WORKDIR /app

# Copy venv from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code (with generated proto stubs)
COPY --from=builder /build/src/ ./src/

# Pre-download model during build for fast cold starts.
# If HF_TOKEN is not set, model download is skipped (container will download on first start).
ARG HF_TOKEN=""
ENV HF_HOME=/app/.cache/huggingface
RUN if [ -n "$HF_TOKEN" ]; then \
    HF_TOKEN="$HF_TOKEN" python -c "\
from transformers import AutoModelForSequenceClassification, AutoTokenizer; \
AutoTokenizer.from_pretrained('qualifire/prompt-injection-jailbreak-sentinel-v2'); \
AutoModelForSequenceClassification.from_pretrained('qualifire/prompt-injection-jailbreak-sentinel-v2')"; \
    else echo "HF_TOKEN not set, skipping model pre-download"; fi

ENV PYTHONPATH=/app/src
ENV PYTHONUNBUFFERED=1

USER promptguard

EXPOSE 50052

ENTRYPOINT ["python", "-m", "prompt_guard.server"]
