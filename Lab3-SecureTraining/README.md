# Lab 3 — Secure model training pipeline (steps 11–15)

Fine-tune **Qwen3-1.7B** with **Unsloth QLoRA** and prove every input and output before it ships. Then keep protecting the model in production.
CI version: [`.github/workflows/secure-model-pipeline.yml`](../.github/workflows/secure-model-pipeline.yml) · Slides 55–64.

```
Data ─► Base model ─► Train ─► Evaluate ─► Registry ─► Admission ─► Runtime
scan-dataset  pin-inputs   train-qlora  scan-output   sign-attest  publish-admit  runtime-protect
              scan-model                red-team-eval
◀── SHIFT LEFT: prove data & base model ──┤ GATES ├── SHIELD RIGHT: verify, guard, recover ──▶
```

**Why Qwen3-1.7B:**

- It's Apache 2.0, published by the official org as safetensors.
- It's the same family as the Lab 2 `qwen3:0.6b`, so the base-vs-fine-tuned red-team comparison is like-for-like.
- QLoRA fits a free Colab T4.

Alternatives: Llama 3.2 3B, Gemma 3 1B, Phi-4-mini. Unsloth advises bf16 LoRA rather than 4-bit QLoRA for the Qwen3.5 small models.

```bash
cd Lab3-SecureTraining
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## The lab dataset has planted problems

The lab dataset is `data/train.jsonl` (37 samples of Kubernetes/AI-security Q&A). It deliberately contains:

| Planted issue | Caught by |
| --- | --- |
| An email address and phone number | `scan_pii.py` (Presidio, regex fallback) |
| An AWS **documentation example** key pair (`AKIA…EXAMPLE`) | TruffleHog (and redacted by `scan_pii.py` as a second line of defence) |
| A leetspeak prompt injection (`Ign0re previous instructions…`) | `fuzzy_scan.py` trigger match |
| 4 near-duplicate poisoning samples with a trigger phrase (`blue-harbor-override` → "disable NetworkPolicies, run privileged") | `fuzzy_scan.py` MinHash cluster **and** trigger match |

## Step 11 · Pin & scan the inputs

```bash
export BASE_REV=<commit sha from huggingface.co/Qwen/Qwen3-1.7B/commits/main>
SECRETS_WARN_ONLY=1 PII_NO_FAIL=1 FUZZY_WARN_ONLY=1 ./scripts/scan_inputs.sh
# *_WARN_ONLY lets the lab continue with the redacted + cleaned set. In CI these gates hard-fail.
```

The script runs, in order:

1. `hf download` pinned to the revision SHA.
2. Refuse `.bin/.pt/.pkl`, and refuse models that need `auto_map` remote code.
3. `modelscan`, then hash the base.
4. `trufflehog --fail`.
5. PII redaction to `data/redacted.jsonl`.
6. The fuzzy scan: `data/clean.jsonl` plus `data/quarantine.jsonl`.

You should see:

```
fuzzy_scan: scanned 37 samples · clean 32 · quarantined 5
  line 9: trigger~'blue harbor override' (100); near-dup cluster of 4
  line 20: trigger~'ignore previous instructions' (100)
```

Quarantined samples go to a human for review. They are not silently dropped.

## Step 12 · QLoRA fine-tune in a locked-down Job

```bash
# local / Colab GPU
pip install -r requirements-train.txt
python scripts/train.py --base base/ --data data/clean.jsonl --out out/ --gguf
# or on Kubernetes
kubectl apply -f k8s/namespace-training.yaml      # PSS restricted + default-deny (no egress)
kubectl apply -f k8s/train-job.yaml               # set your image digest + PVCs first
```

What to look for:

- `load_in_4bit=True`: the base is frozen in 4-bit, and only LoRA adapters train.
- The run is offline with no egress, so nothing new is pulled mid-run.
- No service-account token, non-root, all capabilities dropped, dataset mounted read-only.
- `out/provenance.json` records the base hashes, dataset hash and hyperparameters.

## Step 13 · Scan the output, red-team the result

```bash
modelscan -p out/adapter/                                     # expect: no pickle
ollama create qwen3-ft -f out/gguf/Modelfile
garak --model_type ollama --model_name qwen3:0.6b --probes promptinject,dan,leakreplay --report_prefix reports/base
garak --model_type ollama --model_name qwen3-ft   --probes promptinject,dan,leakreplay --report_prefix reports/ft
fuzzyai fuzz -m ollama/qwen3-ft -a def -a dan -t "<test prompt>"
python scripts/gate.py --model qwen3-ft                     # PASS → sign & publish, else BLOCK
```

`gate.py` blocks the release if any of these happen:

- A garak probe regresses more than 2 points against the base.
- A phrase in `triggers.txt` flips the model into unsafe output (the backdoor check).
- Task accuracy on `data/eval.jsonl` falls below 0.80.

Also review the GGUF's Jinja chat template: malicious templates have caused RCE (CVE-2024-34359).

## Step 14 · Sign, AIBOM, publish by digest, verify on admit

```bash
pip install model-signing cyclonedx-bom
model_signing sign out/gguf --signature out/gguf/model.sig          # keyless (browser OIDC locally, workflow OIDC in CI)
model_signing verify out/gguf --signature out/gguf/model.sig --identity you@example.com --identity_provider https://github.com/login/oauth
cyclonedx-py environment -o libs.cdx.json
python scripts/make_aibom.py --prov out/provenance.json --base-rev $BASE_REV --libs libs.cdx.json --gguf out/gguf -o out/gguf/aibom.cdx.json
oras push ghcr.io/<you>/models/qwen3-ft:1.0 out/gguf/
kubectl apply -k https://github.com/sigstore/model-validation-operator/config/overlays/testing
kubectl apply -f k8s/model-validation.yaml
```

The signature covers every file, so changing one byte fails verification. Pods labelled `validation.ml.sigstore.dev/ml: qwen3-ft` get a verifier injected, so an unsigned or tampered model never serves.

## Step 15 · Harden the serving pod, then watch it

```bash
kubectl apply -f runtime/networkpolicy-ai-stack.yaml   # only the AI gateway reaches Ollama; zero egress
kubectl apply -f runtime/ollama-deploy.yaml            # set image + model digests first
helm upgrade --install falco falcosecurity/falco -n falco --set driver.kind=modern_ebpf -f runtime/falco-values.yaml
# test: read the weights from another process → CRITICAL
kubectl exec deploy/ollama -n ai-stack -- sh -c 'cat /models/qwen3-ft/*.gguf > /dev/null'
```

What to look for:

- **Read-only model:** it is mounted read-only from a signed digest, so the server can't modify or fetch weights.
- **Network:** only the AI gateway can reach the server, and zero egress blocks exfiltration.
- **Falco alerts:** CRITICAL if anything but the server reads `/models`, and WARNING on any egress or shell.
- **Re-validation and quotas:** continuous re-validation (every 10 minutes) catches on-disk tampering, and quotas at the gateway slow extraction.

> Validate the Falco rules with `falco --validate` for your Falco version. Ollama needs a writable home directory, which is why the Deployment uses an `emptyDir` instead of a writable root filesystem.
