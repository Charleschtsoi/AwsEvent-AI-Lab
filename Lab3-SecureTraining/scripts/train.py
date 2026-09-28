#!/usr/bin/env python3
"""QLoRA fine-tune of Qwen3-1.7B with Unsloth (Lab 3 · step 12).

Security properties this script relies on (enforced by the Job, not by Python):
  * loads ONLY the verified local copy in ./base (HF_HUB_OFFLINE=1, no egress)
  * reads ONLY the cleaned dataset (output of scan_pii.py + fuzzy_scan.py)
  * writes adapters as safetensors, never pickle
Run:  python scripts/train.py --base base/ --data data/clean.jsonl --out out/
"""
import argparse, hashlib, json, os, platform, sys, pathlib

os.environ.setdefault("HF_HUB_OFFLINE", "1")          # never pull weights mid-run
os.environ.setdefault("HF_DATASETS_OFFLINE", "1")

from unsloth import FastLanguageModel                    # noqa: E402  (import after env)
from datasets import load_dataset                        # noqa: E402
from trl import SFTTrainer, SFTConfig                    # noqa: E402

def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""): h.update(chunk)
    return h.hexdigest()

ap = argparse.ArgumentParser()
ap.add_argument("--base", default="base/")
ap.add_argument("--data", default="data/clean.jsonl")
ap.add_argument("--out", default="out/")
ap.add_argument("--max-steps", type=int, default=60)
ap.add_argument("--gguf", action="store_true", help="also export q4_k_m GGUF for Ollama")
a = ap.parse_args()

# refuse pickle-format weights outright
bad = [p for p in pathlib.Path(a.base).rglob("*") if p.suffix in {".bin", ".pt", ".pth", ".pkl", ".ckpt"}]
if bad:
    sys.exit(f"BLOCK: pickle-format files in base model: {bad}")

model, tok = FastLanguageModel.from_pretrained(
    model_name=a.base, max_seq_length=2048, load_in_4bit=True,   # QLoRA: frozen 4-bit base
    trust_remote_code=False)
model = FastLanguageModel.get_peft_model(
    model, r=16, lora_alpha=16, lora_dropout=0, bias="none",
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    use_gradient_checkpointing="unsloth", random_state=3407)

def to_text(ex):
    msgs = [{"role": "user", "content": ex["instruction"]}, {"role": "assistant", "content": ex["output"]}]
    return {"text": tok.apply_chat_template(msgs, tokenize=False)}

ds = load_dataset("json", data_files=a.data, split="train").map(to_text)
SFTTrainer(model=model, processing_class=tok, train_dataset=ds,
           args=SFTConfig(dataset_text_field="text", per_device_train_batch_size=2,
                          gradient_accumulation_steps=4, max_steps=a.max_steps, learning_rate=2e-4,
                          logging_steps=5, output_dir=os.path.join(a.out, "ckpt"), seed=3407,
                          report_to="none")).train()

adapter = os.path.join(a.out, "adapter")
model.save_pretrained(adapter, safe_serialization=True)
tok.save_pretrained(adapter)
if a.gguf:
    model.save_pretrained_gguf(os.path.join(a.out, "gguf"), tok, quantization_method="q4_k_m")

# provenance record → feeds the AIBOM in step 14
prov = {
    "base_model_dir": a.base,
    "base_files": {p.name: sha256(p) for p in sorted(pathlib.Path(a.base).glob("*.safetensors"))},
    "dataset": {"path": a.data, "sha256": sha256(a.data)},
    "adapter_files": {p.name: sha256(p) for p in sorted(pathlib.Path(adapter).glob("*.safetensors"))},
    "hyperparams": {"method": "QLoRA", "load_in_4bit": True, "r": 16, "lora_alpha": 16, "max_steps": a.max_steps},
    "python": platform.python_version(),
}
json.dump(prov, open(os.path.join(a.out, "provenance.json"), "w"), indent=2)
print("done →", adapter)
