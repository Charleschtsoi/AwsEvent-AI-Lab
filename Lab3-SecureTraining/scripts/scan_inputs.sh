#!/usr/bin/env bash
# Lab 3 · step 11 — pin & scan the inputs. Any failure stops the script (and the CI job).
set -euo pipefail
BASE_REPO="${BASE_REPO:-Qwen/Qwen3-1.7B}"
BASE_REV="${BASE_REV:?set BASE_REV to the commit SHA you reviewed on huggingface.co}"
DATA="${DATA:-data/train.jsonl}"

echo "== 1. pin the official base model by commit SHA"
hf download "$BASE_REPO" --revision "$BASE_REV" --local-dir base/ \
  --include "*.safetensors" "*.json" "*.txt" "tokenizer*" "merges.txt" "vocab.json"

echo "== 2. refuse pickle formats outright"
if find base/ -type f \( -name '*.bin' -o -name '*.pt' -o -name '*.pth' -o -name '*.pkl' -o -name '*.ckpt' \) | grep -q .; then
  echo "BLOCK: pickle-format weights present"; exit 1; fi
grep -l '"auto_map"' base/*.json && { echo "BLOCK: model requires custom remote code"; exit 1; } || true

echo "== 3. scan before anything loads the weights"
modelscan -p base/
sha256sum base/*.safetensors > base.sha256

echo "== 4. dataset: secrets"
trufflehog filesystem "$(dirname "$DATA")" --fail --no-update || { echo "secrets found"; [ -n "${SECRETS_WARN_ONLY:-}" ] || exit 1; }

echo "== 5. dataset: PII (redact, fail if found — review then re-run with --no-fail)"
python scripts/scan_pii.py "$DATA" --out data/redacted.jsonl ${PII_NO_FAIL:+--no-fail}

echo "== 6. dataset: fuzzy scan (near-dups + trigger phrases)"
if ! python scripts/fuzzy_scan.py data/redacted.jsonl --denylist triggers.txt \
      --minhash-threshold 0.85 --ratio 90 --out data/clean.jsonl --quarantine data/quarantine.jsonl; then
  echo "quarantined samples → data/quarantine.jsonl (review them; clean set = data/clean.jsonl)"
  [ -n "${FUZZY_WARN_ONLY:-}" ] || exit 1
fi
sha256sum data/clean.jsonl > data.sha256
echo "inputs OK"
