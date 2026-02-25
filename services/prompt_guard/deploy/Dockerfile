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

# Install runtime dependencies — onnxruntime-gpu with CUDA/cuDNN pip packages.
# The [cuda,cudnn] extras pull NVIDIA libraries as pip wheels (~2GB) so we
# don't need the nvidia/cuda base image. PyTorch is NOT needed at runtime.
RUN pip install --no-cache-dir \
    "onnxruntime-gpu[cuda,cudnn]" \
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

# === Stage 3: Runtime (python:3.11-slim + CUDA from pip — no PyTorch) ===
FROM python:3.11-slim

RUN useradd -r -d /app promptguard

WORKDIR /app

# Copy venv from builder (includes onnxruntime-gpu + NVIDIA CUDA/cuDNN pip packages)
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# NVIDIA CUDA pip packages install into site-packages/nvidia/*/lib/ which is
# not on the default library search path. onnxruntime-gpu needs these at runtime.
ENV LD_LIBRARY_PATH="/opt/venv/lib/python3.11/site-packages/nvidia/cuda_runtime/lib:\
/opt/venv/lib/python3.11/site-packages/nvidia/cublas/lib:\
/opt/venv/lib/python3.11/site-packages/nvidia/cudnn/lib:\
/opt/venv/lib/python3.11/site-packages/nvidia/cufft/lib:\
/opt/venv/lib/python3.11/site-packages/nvidia/curand/lib:\
/opt/venv/lib/python3.11/site-packages/nvidia/cuda_nvrtc/lib"

# Copy application code (with generated proto stubs)
COPY --from=builder /build/src/ ./src/

# Copy ONNX model from exporter
COPY --from=exporter /export/model/ ./model/

# NVIDIA container runtime exposes GPUs via these env vars
ENV NVIDIA_VISIBLE_DEVICES=all
ENV NVIDIA_DRIVER_CAPABILITIES=compute,utility

ENV PYTHONPATH=/app/src
ENV PYTHONUNBUFFERED=1
ENV PROMPT_GUARD_RUNTIME=onnx
ENV PROMPT_GUARD_ONNX_MODEL_PATH=/app/model

USER promptguard

EXPOSE 50052

ENTRYPOINT ["python", "-m", "prompt_guard.server"]
