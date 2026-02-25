# === Stage 1: Export ONNX model ===
FROM python:3.11-slim AS exporter

WORKDIR /export

# Install optimum + transformers for export (no PyTorch needed at runtime)
RUN pip install --no-cache-dir "optimum[onnxruntime]" transformers

# Copy export script
COPY services/prompt_guard/scripts/export_onnx.py ./

# HF_TOKEN is mounted as a secret so it never appears in any image layer.
RUN --mount=type=secret,id=hf_token,env=HF_TOKEN python export_onnx.py /export/model

# === Stage 2: Generate gRPC stubs ===
FROM python:3.11-slim AS builder

WORKDIR /build

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install runtime dependencies — onnxruntime-gpu for CUDA acceleration.
# PyTorch is NOT needed at runtime; ONNX Runtime handles GPU inference directly.
RUN pip install --no-cache-dir \
    onnxruntime-gpu \
    tokenizers \
    numpy \
    grpcio \
    grpcio-tools \
    grpcio-health-checking \
    grpcio-reflection \
    structlog

# Generate proto stubs
COPY proto/ /proto/
COPY services/prompt_guard/src/ ./src/

RUN python -m grpc_tools.protoc \
    -I /proto \
    --python_out=src/prompt_guard/gen \
    --grpc_python_out=src/prompt_guard/gen \
    --pyi_out=src/prompt_guard/gen \
    /proto/prompt_guard/v1/prompt_guard.proto && \
    sed -i 's/from prompt_guard\.v1 import/from prompt_guard.gen.prompt_guard.v1 import/' \
    src/prompt_guard/gen/prompt_guard/v1/prompt_guard_pb2_grpc.py

# === Stage 3: Runtime (slim, ONNX Runtime GPU — no PyTorch) ===
FROM python:3.11-slim

RUN useradd -r -d /app promptguard

WORKDIR /app

# Copy venv from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code (with generated proto stubs)
COPY --from=builder /build/src/ ./src/

# Copy ONNX model from exporter
COPY --from=exporter /export/model/ ./model/

ENV PYTHONPATH=/app/src
ENV PYTHONUNBUFFERED=1
ENV PROMPT_GUARD_RUNTIME=onnx
ENV PROMPT_GUARD_ONNX_MODEL_PATH=/app/model

USER promptguard

EXPOSE 50052

ENTRYPOINT ["python", "-m", "prompt_guard.server"]
