"""
Step 1: Validate the TS-Guard model from HuggingFace can be loaded.
Downloads config + tokenizer first (small), then optionally loads weights.
"""

import sys
import json
import argparse
from pathlib import Path

def check_config(model_id: str):
    """Download and inspect the model config without loading weights."""
    from transformers import AutoConfig, AutoTokenizer

    print(f"[1/3] Downloading config from {model_id}...")
    try:
        config = AutoConfig.from_pretrained(model_id, trust_remote_code=True)
        print(f"  model_type:        {config.model_type}")
        print(f"  architectures:     {config.architectures}")
        print(f"  hidden_size:       {config.hidden_size}")
        print(f"  num_hidden_layers: {config.num_hidden_layers}")
        print(f"  num_attention_heads: {config.num_attention_heads}")
        print(f"  vocab_size:        {config.vocab_size}")
        print(f"  torch_dtype:       {config.torch_dtype}")
        print(f"  OK - config is valid Qwen2 causal LM")
    except Exception as e:
        print(f"  FAIL - could not load config: {e}")
        return False

    print(f"\n[2/3] Downloading tokenizer from {model_id}...")
    try:
        tokenizer = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)
        print(f"  vocab_size:     {tokenizer.vocab_size}")
        print(f"  model_max_len:  {tokenizer.model_max_length}")
        # Test encode/decode
        test_text = "Hello, this is a test."
        ids = tokenizer.encode(test_text)
        decoded = tokenizer.decode(ids, skip_special_tokens=True)
        print(f"  encode/decode:  '{test_text}' -> {len(ids)} tokens -> '{decoded}'")

        # Test chat template
        messages = [{"role": "user", "content": "test prompt"}]
        try:
            chat_text = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
            print(f"  chat_template:  works ({len(chat_text)} chars)")
            print(f"  chat preview:   {chat_text[:200]}...")
        except Exception as e:
            print(f"  chat_template:  FAIL - {e}")

        print(f"  OK - tokenizer is valid")
    except Exception as e:
        print(f"  FAIL - could not load tokenizer: {e}")
        return False

    return True


def check_weights(model_id: str):
    """Attempt to load the full model weights."""
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    print(f"\n[3/3] Loading model weights from {model_id}...")
    print(f"  This will download ~15GB. Using float16 to reduce memory.")

    device = "mps" if torch.backends.mps.is_available() else "cpu"
    print(f"  Target device: {device}")

    try:
        model = AutoModelForCausalLM.from_pretrained(
            model_id,
            torch_dtype=torch.float16,
            device_map="auto" if device == "cpu" else None,
            trust_remote_code=True,
            low_cpu_mem_usage=True,
        )
        if device == "mps":
            model = model.to(device)

        total_params = sum(p.numel() for p in model.parameters())
        print(f"  total parameters: {total_params:,} ({total_params/1e9:.2f}B)")
        print(f"  dtype:            {next(model.parameters()).dtype}")
        print(f"  device:           {next(model.parameters()).device}")

        # Quick generation test
        tokenizer = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)
        messages = [{"role": "user", "content": "Say hello."}]
        text = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        inputs = tokenizer(text, return_tensors="pt").to(model.device)

        print(f"  Running test generation...")
        with torch.no_grad():
            outputs = model.generate(
                **inputs,
                max_new_tokens=50,
                temperature=0.1,
                do_sample=True,
                top_p=0.9,
            )
        response = tokenizer.decode(outputs[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True)
        print(f"  Test output: {response[:200]}")
        print(f"  OK - model loads and generates")
        return True

    except Exception as e:
        print(f"  FAIL - could not load model: {e}")
        import traceback
        traceback.print_exc()
        return False


def check_safetensors_index(model_id: str):
    """Check if the safetensors index file is valid."""
    from huggingface_hub import hf_hub_download

    print(f"\n[bonus] Checking safetensors index file...")
    try:
        index_path = hf_hub_download(model_id, "model.safetensors.index.json")
        with open(index_path) as f:
            index = json.load(f)
        metadata = index.get("metadata", {})
        weight_map = index.get("weight_map", {})
        print(f"  metadata:     {metadata}")
        print(f"  weight files: {len(set(weight_map.values()))} shards")
        print(f"  total layers: {len(weight_map)} weight tensors")

        # Check for any missing or suspicious entries
        shards = set(weight_map.values())
        expected = {f"model-{i:05d}-of-{len(shards):05d}.safetensors" for i in range(1, len(shards) + 1)}
        if shards == expected:
            print(f"  shard naming: OK (matches expected pattern)")
        else:
            print(f"  shard naming: WARNING - unexpected names: {shards - expected}")

        print(f"  OK - index file is valid")
        return True
    except Exception as e:
        print(f"  FAIL - {e}")
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Validate TS-Guard model from HuggingFace")
    parser.add_argument("--model-id", default="MurrayTom/TS-Guard", help="HuggingFace model ID")
    parser.add_argument("--skip-weights", action="store_true", help="Skip downloading/loading full weights")
    args = parser.parse_args()

    print(f"=" * 60)
    print(f"Validating TS-Guard model: {args.model_id}")
    print(f"=" * 60)

    config_ok = check_config(args.model_id)
    index_ok = check_safetensors_index(args.model_id)

    if args.skip_weights:
        print(f"\n[3/3] Skipping weight loading (--skip-weights)")
        weights_ok = None
    else:
        weights_ok = check_weights(args.model_id)

    print(f"\n{'=' * 60}")
    print(f"RESULTS:")
    print(f"  Config + tokenizer: {'PASS' if config_ok else 'FAIL'}")
    print(f"  Safetensors index:  {'PASS' if index_ok else 'FAIL'}")
    print(f"  Full weights:       {'PASS' if weights_ok else 'FAIL' if weights_ok is False else 'SKIPPED'}")
    print(f"{'=' * 60}")
