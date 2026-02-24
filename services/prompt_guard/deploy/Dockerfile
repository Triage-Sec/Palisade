# === Builder ===
# Install Python dependencies in a builder stage to keep the runtime image clean.
FROM nvidia/cuda:12.4.1-runtime-ubuntu22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.11 python3.11-venv python3-pip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Create venv and install dependencies first (cached layer).
RUN python3.11 -m venv /opt/venv
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
    /proto/prompt_guard/v1/prompt_guard.proto

# === Runtime ===
FROM nvidia/cuda:12.4.1-runtime-ubuntu22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.11 python3.11-venv \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r promptguard && useradd -r -g promptguard -d /app promptguard

WORKDIR /app

# Copy venv from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code (with generated proto stubs)
COPY --from=builder /build/src/ ./src/

# Optional: pre-download model during build for faster cold starts.
# Uncomment the next two lines for production images:
# ENV HF_HOME=/app/.cache/huggingface
# RUN python -c "from transformers import AutoModelForSequenceClassification, AutoTokenizer; AutoTokenizer.from_pretrained('qualifire/prompt-injection-jailbreak-sentinel-v2'); AutoModelForSequenceClassification.from_pretrained('qualifire/prompt-injection-jailbreak-sentinel-v2')"

ENV PYTHONPATH=/app/src
ENV PYTHONUNBUFFERED=1

USER promptguard

EXPOSE 50052

ENTRYPOINT ["python", "-m", "prompt_guard.server"]
