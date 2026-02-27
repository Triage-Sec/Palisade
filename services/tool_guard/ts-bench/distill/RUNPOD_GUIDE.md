# Distilling TS-Guard 7B → Qwen3-0.6B Classifier

## RunPod Setup

**GPU**: A100 80GB (recommended) or A100 40GB
**Container Image**: `runpod/pytorch:2.4.0-py3.11-cuda12.4.1-devel-ubuntu22.04`
**Volume**: Mount a persistent volume at `/workspace` (50GB+)

## Step 0: Environment Setup

```bash
# Redirect HuggingFace cache to volume (avoid filling container disk)
export HF_HOME=/workspace/.cache/huggingface

# Clone repo
cd /workspace
git clone https://github.com/triageai/Palisade.git
cd Palisade/services/tool_guard/ts-bench

# Clone ToolSafe (has TS-Bench evaluation data)
apt-get update && apt-get install -y git-lfs
git clone https://github.com/MurrayTom/ToolSafe.git
cd ToolSafe && git lfs install && git lfs pull && cd ..

# Install dependencies
pip install vllm requests scikit-learn tqdm transformers accelerate torch onnx onnxruntime-gpu numpy
```

## Step 1: Generate Teacher Labels (~30 min)

Start TS-Guard 7B on vLLM, then run the labeler.

**Terminal 1 — Start vLLM server:**
```bash
export HF_HOME=/workspace/.cache/huggingface
cd /workspace/Palisade/services/tool_guard/ts-bench
vllm serve MurrayTom/TS-Guard --port 8000
```

Wait for `Uvicorn running on http://0.0.0.0:8000` then open **Terminal 2**.

**Terminal 2 — Run labeler:**
```bash
export HF_HOME=/workspace/.cache/huggingface
cd /workspace/Palisade/services/tool_guard/ts-bench

python distill/generate_labels.py \
  --url http://localhost:8000 \
  --output distill/labeled_data.json
```

This sends all 7,182 TS-Bench samples through the 7B model.
- Expected time: ~20-30 min on A100 with vLLM
- Checkpoints every 100 samples (safe to interrupt and `--resume`)
- Output: `distill/labeled_data.json` (~50MB)

**After labeling is done, stop the vLLM server** (Ctrl+C in Terminal 1).
The 7B model uses ~15GB VRAM — we need that memory for training.

## Step 2: Train Classifier (~15-30 min)

```bash
cd /workspace/Palisade/services/tool_guard/ts-bench

python distill/train_classifier.py \
  --data distill/labeled_data.json \
  --base-model Qwen/Qwen3-0.6B \
  --output-dir distill/checkpoints \
  --epochs 5 \
  --batch-size 4 \
  --lr 2e-5 \
  --max-length 1024
```

Expected output:
```
Epoch 1/5 (120s)
  Train loss: 0.4521
  Val acc    — malicious: 0.890, attacked: 0.920, harmfulness: 0.850
  Composite  — ACC: 0.850, F1: 0.870, Recall: 0.900
...
Epoch 5/5 (120s)
  Composite  — ACC: 0.880, F1: 0.900, Recall: 0.920
```

Best model saved to `distill/checkpoints/best_model/`.

## Step 3: Evaluate Against TS-Bench

```bash
cd /workspace/Palisade/services/tool_guard/ts-bench

python distill/eval_classifier.py \
  --checkpoint distill/checkpoints/best_model \
  --dataset all \
  --batch-size 16
```

Expected output — comparison with TS-Guard 7B teacher:
```
  SUMMARY
  Dataset      ACC       F1   Recall   vs Teacher F1
  agentharm   XX.XX%  XX.XX%  XX.XX%        -X.XX%
  asb         XX.XX%  XX.XX%  XX.XX%        -X.XX%
  agentdojo   XX.XX%  XX.XX%  XX.XX%        -X.XX%
```

**Key question: is the F1 drop acceptable?**
- < 3% drop: Ship it
- 3-5% drop: Acceptable for ~50x latency improvement
- > 5% drop: Consider larger model (Qwen3-1.7B) or more training data

## Step 4: Export to ONNX

```bash
cd /workspace/Palisade/services/tool_guard/ts-bench

python distill/export_onnx.py \
  --checkpoint distill/checkpoints/best_model \
  --output distill/onnx_model \
  --validate
```

Expected output:
```
ONNX model size: ~1200 MB
  Safe weather query:
    Composite: 0.0       [PASS]
    Latency:   5.2ms
  Credit card exfiltration:
    Composite: 1.0       [PASS]
    Latency:   5.1ms
```

## Step 5: Download the Model

The ONNX model is in `distill/onnx_model/`. Download it:
```bash
# Option A: zip and download via RunPod UI
cd /workspace/Palisade/services/tool_guard/ts-bench/distill
tar czf /workspace/onnx_model.tar.gz onnx_model/

# Option B: push to HuggingFace
pip install huggingface_hub
huggingface-cli login
huggingface-cli upload YOUR_ORG/palisade-tool-guard onnx_model/
```

## Expected Performance

| Metric | TS-Guard 7B | Qwen3-0.6B Classifier | Improvement |
|--------|------------|----------------------|-------------|
| Latency (GPU) | ~200-500ms | **~5-10ms** | **40-100x** |
| Latency (CPU) | N/A | **~30-50ms** | Feasible |
| ONNX size | N/A | **~1.2 GB** | Deployable |
| AgentHarm F1 | 90.2% | TBD | TBD |
| ASB F1 | 94.7% | TBD | TBD |
| AgentDojo F1 | 88.8% | TBD | TBD |

## Deployment (After This)

The ONNX model deploys exactly like `prompt_guard`:
- Same Dockerfile pattern (Python + onnxruntime-gpu)
- Same EC2 g4dn.xlarge (T4 GPU) or ECS Fargate (CPU)
- Same gRPC wrapper
- Guard service calls it as another detector in the fan-out
