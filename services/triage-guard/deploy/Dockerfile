# === Stage 1: Install Python dependencies ===
FROM python:3.11-slim AS builder

WORKDIR /build

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install PyTorch with CUDA support + runtime deps
COPY services/triage-guard/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    --index-url https://download.pytorch.org/whl/cu121 \
    --extra-index-url https://pypi.org/simple/

# === Stage 2: Runtime ===
FROM python:3.11-slim

RUN useradd -r -d /app triageguard

WORKDIR /app

# Copy venv from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application source
COPY services/triage-guard/src/ ./src/

# Copy pre-downloaded models (no HuggingFace access at build time)
COPY services/triage-guard/models/prompt_guard/ ./models/prompt_guard/
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
