# === Stage 1: Download prompt guard model from HuggingFace ===
FROM python:3.11-slim AS model-downloader

WORKDIR /download

# CPU-only torch is enough for downloading/saving model files
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu && \
    pip install --no-cache-dir transformers

COPY services/triage-guard/scripts/download_prompt_guard.py ./
RUN --mount=type=secret,id=hf_token,env=HF_TOKEN \
    python download_prompt_guard.py --output /download/prompt_guard

# === Stage 2: Install Python dependencies ===
FROM python:3.11-slim AS builder

WORKDIR /build

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install PyTorch with CUDA support + runtime deps
COPY services/triage-guard/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    --index-url https://download.pytorch.org/whl/cu121 \
    --extra-index-url https://pypi.org/simple/

# === Stage 3: Runtime ===
FROM python:3.11-slim

RUN useradd -r -d /app triageguard

WORKDIR /app

# Copy venv from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application source
COPY services/triage-guard/src/ ./src/

# Prompt guard model — downloaded from HuggingFace in stage 1
COPY --from=model-downloader /download/prompt_guard/ ./models/prompt_guard/

# Tool guard checkpoint — pre-staged in build context (downloaded from S3 in CI,
# or extracted locally via: tar xzf qwen3_0.6b_distillation.gz -C models/tool_guard/)
COPY services/triage-guard/models/tool_guard/ ./models/tool_guard/

# NVIDIA container runtime env vars for GPU passthrough
ENV NVIDIA_VISIBLE_DEVICES=all
ENV NVIDIA_DRIVER_CAPABILITIES=compute,utility

ENV PYTHONPATH=/app/src
ENV PYTHONUNBUFFERED=1
ENV PROMPT_GUARD_MODEL_PATH=/app/models/prompt_guard
ENV TOOL_GUARD_CHECKPOINT_PATH=/app/models/tool_guard

USER triageguard

EXPOSE 8080

ENTRYPOINT ["uvicorn", "triage_guard.main:app", "--host", "0.0.0.0", "--port", "8080"]
