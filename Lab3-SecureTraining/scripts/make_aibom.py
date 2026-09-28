#!/usr/bin/env python3
"""Build a minimal CycloneDX 1.6 ML-BOM (AIBOM) from train.py's provenance.json (Lab 3 · step 14).

Lists: base model (pinned revision + file hashes), dataset (hash), fine-tuned adapter/GGUF (hashes)
and, if given, the Python library SBOM from `cyclonedx-py environment`.
Usage: python make_aibom.py --prov out/provenance.json --base-repo Qwen/Qwen3-1.7B \
         --base-rev <sha> [--libs libs.cdx.json] [--gguf out/gguf] -o aibom.cdx.json
"""
import argparse, hashlib, json, pathlib, uuid, datetime

def sha(p):
    h = hashlib.sha256(); h.update(pathlib.Path(p).read_bytes()); return h.hexdigest()

ap = argparse.ArgumentParser()
ap.add_argument("--prov", default="out/provenance.json")
ap.add_argument("--base-repo", default="Qwen/Qwen3-1.7B")
ap.add_argument("--base-rev", required=True)
ap.add_argument("--libs")
ap.add_argument("--gguf")
ap.add_argument("-o", "--out", default="aibom.cdx.json")
a = ap.parse_args()
prov = json.load(open(a.prov))
H = lambda d: [{"alg": "SHA-256", "content": v} for v in d.values()]

base = {"type": "machine-learning-model", "bom-ref": "base-model", "name": a.base_repo, "version": a.base_rev,
        "licenses": [{"license": {"id": "Apache-2.0"}}], "hashes": H(prov["base_files"]),
        "externalReferences": [{"type": "distribution", "url": f"https://huggingface.co/{a.base_repo}/tree/{a.base_rev}"}]}
data = {"type": "data", "bom-ref": "dataset", "name": pathlib.Path(prov["dataset"]["path"]).name,
        "hashes": [{"alg": "SHA-256", "content": prov["dataset"]["sha256"]}],
        "data": [{"type": "dataset", "name": "fine-tune set", "classification": "scanned: PII redacted, secrets 0, fuzzy-scan quarantined"}]}
adapter = {"type": "machine-learning-model", "bom-ref": "qwen3-ft", "name": "qwen3-ft", "version": "1.0",
           "hashes": H(prov["adapter_files"]),
           "modelCard": {"modelParameters": {"approach": {"type": "supervised"}, "task": "text-generation",
                                             "datasets": [{"ref": "dataset"}]},
                         "properties": [{"name": f"hyperparam:{k}", "value": str(v)} for k, v in prov["hyperparams"].items()]}}
if a.gguf:
    adapter["hashes"] += [{"alg": "SHA-256", "content": sha(p)} for p in sorted(pathlib.Path(a.gguf).glob("*.gguf"))]
comps = [base, data, adapter]
deps = [{"ref": "qwen3-ft", "dependsOn": ["base-model", "dataset"]}]
if a.libs:
    libs = json.load(open(a.libs)).get("components", [])
    comps += libs
    deps[0]["dependsOn"] += [c["bom-ref"] for c in libs if "bom-ref" in c]
bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
       "metadata": {"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "component": {"type": "machine-learning-model", "name": "qwen3-ft", "bom-ref": "root"}},
       "components": comps, "dependencies": deps}
json.dump(bom, open(a.out, "w"), indent=2)
print(f"AIBOM → {a.out} ({len(comps)} components)")
