# Running TS-Bench Evaluation on RunPod (A100)

## 1. Create the Pod

- **GPU**: A100 (80GB) — overkill for 7B but fast and no memory worries
- **Template**: `runpod/pytorch:2.4.0-py3.11-cuda12.4.1-devel-ubuntu22.04` (or similar)
- **Disk**: 50GB+ (model is ~15GB, data is small)
- **Cloud type**: Community or Secure — doesn't matter for this

## 2. SSH In and Set Up

```bash
# Clone ToolSafe repo + pull LFS data files
git lfs install
git clone https://github.com/MurrayTom/ToolSafe.git
cd ToolSafe
git lfs pull

# Verify data is real JSON (not LFS pointers)
python3 -c "import json; d=json.load(open('TS-Bench/agentharm-traj/harmful_steps.json')); print(len(d), 'samples')"
# Should print: 525 samples
```

## 3. Install Dependencies

```bash
pip install vllm transformers scikit-learn tqdm
```

vLLM pulls in torch + CUDA automatically. On an A100 this should just work.

## 4. Upload Eval Scripts

From your Mac:

```bash
# From ts-bench/eval/ directory
scp -P <PORT> evaluate.py evaluate_fast.py check_progress.py requirements.txt root@<RUNPOD_IP>:~/ToolSafe/eval/
```

Or just copy-paste `evaluate.py` into a file on the pod — it's self-contained.

## 5. Run the Evaluation

### Smoke test (10 samples, ~30 seconds)

```bash
cd ~/ToolSafe/eval
python3 evaluate.py --dataset agentharm --limit 10 --output-dir ./results
```

First run downloads the model from HuggingFace (~15GB, takes a few minutes).

### Full benchmark — all 3 datasets (~7.2K samples)

```bash
python3 evaluate.py --dataset all --output-dir ./results
```

Expected time on A100 with transformers: ~1-2 hours total.

### Even faster with vLLM (optional)

If you want to use vLLM instead of transformers, swap the model loading in
`evaluate.py` to use `vllm.LLM` — this is what the original ToolSafe code does.
The key change in `TSGuardModel.__init__`:

```python
from vllm import LLM, SamplingParams

self.llm = LLM(model=model_id_or_path)
self.sampling = SamplingParams(max_tokens=2048, temperature=0.1, top_p=0.9)
```

And in `generate()`:

```python
outputs = self.llm.chat(
    [{"role": "user", "content": prompt}],
    sampling_params=self.sampling,
)
return outputs[0].outputs[0].text.strip()
```

With vLLM on A100: ~20-30 minutes for the full benchmark.

## 6. Check Progress

While it's running, in another terminal:

```bash
cd ~/ToolSafe/eval
python3 check_progress.py agentharm
python3 check_progress.py asb
python3 check_progress.py agentdojo
```

## 7. Expected Results (Paper Table 3, strict mode)

| Dataset    |  ACC  |  F1   | Recall | Samples |
|------------|-------|-------|--------|---------|
| AgentHarm  | 84.8% | 90.2% | 97.0%  |     731 |
| ASB        | 95.0% | 94.8% | 93.9%  |   5,231 |
| AgentDojo  | 91.7% | 86.2% | 89.5%  |   1,220 |

## 8. Download Results

```bash
# From your Mac
scp -r -P <PORT> root@<RUNPOD_IP>:~/ToolSafe/eval/results ./ts-bench/eval/results_a100
```

Key output files:
- `results/summary.json` — metrics comparison vs paper
- `results/<dataset>_preds.json` — raw predictions
- `results/<dataset>_outputs.json` — full model responses + parsed fields
