# AI on Kubernetes — Supply Chain Security & Defense-in-Depth Lab

**Author:** Bill Ho · CKA / CKAD / CKS / CAISP / AIGP / CIPM
**Edition:** 2026, updated for Kubernetes v1.37
**Slides:** [`AI_on_K8S_Supply_Chain_Security.pdf`](AI_on_K8S_Supply_Chain_Security.pdf) (70 slides)

This lab goes with the talk *AI on Kubernetes: supply chain security & defense-in-depth for cloud-native AI*. It has **3 labs and 15 hands-on steps**. You start with a cluster, add a guarded LLM, and finish with a securely fine-tuned model that is signed, verified and protected at runtime.

| Deck section | Covered in this repo |
| --- | --- |
| 01 Why AI on Kubernetes | Reference architecture (below) |
| 02 Why security first | 2025–26 incidents: LiteLLM / TeamPCP, NVIDIAScape, tj-actions, ingress-nginx EOL |
| 03 Supply chain security 101 | The expanding supply chain — DevSecOps vs ModelOps (slides 17–26), then SBOM · signing · provenance · VEX · policy |
| 04 Securing the K8s platform | **Lab 1** (steps 1–6) + [`devsecops-app.yml`](.github/workflows/devsecops-app.yml) |
| 05 Securing the AI stack | **Lab 2** (steps 7–10) |
| 06 Secure model training pipeline | **Lab 3** (steps 11–15) + [`secure-model-pipeline.yml`](.github/workflows/secure-model-pipeline.yml) |
| 07 Putting it together | Secured reference architecture & action plan (below) |

---

## Prerequisites

Docker Desktop · `kind` · `kubectl` · `helm` · Python 3.10–3.12 · Ollama (optional)
Lab 3 training needs an NVIDIA GPU (a free Colab T4 or an 8 GB+ laptop GPU is enough for Qwen3-1.7B QLoRA). Every scan and gate step runs on CPU.

```bash
brew install kind kubectl helm checkov syft grype cosign trufflehog
```

> **Note:** kind's default CNI does not enforce NetworkPolicy. For the NetworkPolicy steps, create the cluster with `disableDefaultCNI: true` and install Calico or Cilium.

---

## Repository layout

```
.github/workflows/
  devsecops-app.yml          # slides 34–35: app DevSecOps as a workflow (7 required jobs)
  secure-model-pipeline.yml  # slides 56–57: model pipeline as a workflow (8 jobs + runtime)
Lab1-Platform/kyverno/       # step 5: verify-image policies (key-based + keyless)
AIApp/                       # step 10: Open WebUI + Ollama, Portkey AI gateway
ModelScan/                   # step 7: benign vs trojanized Keras models
LLMRedteam/                  # step 8: garak notes
SASTTest/  SCATest/          # SAST (Bandit/Semgrep) and SCA (Grype/Syft) samples
LLMChatbot/                  # sample app (+ Dockerfile) built by devsecops-app.yml
Lab3-SecureTraining/         # steps 11–15: scripts, dataset, K8s manifests, runtime hardening
```

---

## The two pipelines: shift left, shield right

Both pipelines have the same shape. A **concept slide** shows the stages, and a **workflow slide** shows the same stages as GitHub Actions jobs. Every job is a required status check: a red ✗ stops the run.

| DevSecOps (app) — slide 34 → 35 | MLSecOps (model) — slide 56 → 57 |
| --- | --- |
| IDE → `pre-commit` | Data → `scan-dataset` |
| Code repo → `sast-secrets` · `sca-iac` | Base model → `pin-inputs` · `scan-model` |
| CI build → `build-image` | Train → `train-qlora` |
| Registry → `scan-image` | Evaluate → `scan-output` · `red-team-eval` |
| — → `sign-attest` | Registry → `sign-attest` |
| GitOps / Admission → `deploy-gitops` | Admission → `publish-admit` |
| Runtime → `runtime-shield` (in cluster) | Runtime → `runtime-protect` (in cluster) |

**Roll it out in phases.** Set `ENFORCE` in `devsecops-app.yml`:

1. **Crawl (weeks 1–2):** every job runs in audit mode (`ENFORCE: "false"`). Build a baseline and pin actions and scanners by SHA.
2. **Walk (months 1–2):** block leaked secrets and fixable criticals on PRs, and SBOM + sign every image.
3. **Run (this quarter):** set `ENFORCE: "true"` and switch Kyverno to `Enforce`. Runtime alerts go to on-call.

**Hardening already built into the workflows:**

- Every third-party action is pinned by commit SHA (tj-actions and TeamPCP are the reason).
- Signing is keyless OIDC, so there are no long-lived keys to steal.
- `persist-credentials: false` on every checkout.
- Token permissions are least-privilege per job.
- `environment: production` gates deploy/publish behind a required reviewer.

**Before the first run:**

- Create the `production` environment with a required reviewer.
- Add repo variables `QWEN3_BASE_REV` (the Hugging Face commit SHA you reviewed), `ORAS_VERSION` and `ORAS_SHA256`.
- Register an ephemeral self-hosted runner with the labels `gpu, ephemeral` for the training job.

---

## Lab 1 — Platform (steps 1–6)

### Step 1 · kind cluster playground
```bash
kind create cluster --name kind-aws
kubectl get nodes && kubectl get pods -A
```
All control-plane pods (etcd, kube-apiserver, scheduler, coredns) should be `Running`. kind is disposable, so it's safe to break. Don't benchmark production posture on it.

### Step 2 · kube-bench — CIS benchmark
```bash
git clone https://github.com/aquasecurity/kube-bench.git && cd kube-bench
kubectl apply -f job.yaml
kubectl logs job/kube-bench
```
Review the PASS / FAIL / WARN summary, `1.1.x` file permissions and `5.x` policies. Example fix: `seccompProfile: {type: RuntimeDefault}`. On EKS/AKS/GKE use the matching `job-eks.yaml` etc.

### Step 3 · Checkov — IaC, manifests & Helm
```bash
checkov -d . --framework kubernetes,dockerfile
```
Watch for `CKV_K8S_*` (privileged, runAsRoot, no limits), `CKV_DOCKER_3` (no non-root USER) and `CKV_DOCKER_7` (`latest` tag). Fail the PR on HIGH.

### Step 4 · Syft + Grype — SBOM first, then CVEs
```bash
docker pull nginx
syft nginx -o cyclonedx-json > nginx.cdx.json
grype sbom:nginx.cdx.json --only-fixed      # re-scan the SBOM daily; no need to re-pull
```
Patch what has a fix. For "won't fix", add a VEX statement or a compensating control. Pin scanner versions: a scanner is privileged supply-chain code.

### Step 5 · Sign with cosign, enforce with Kyverno (bonus)
```bash
IMG=ttl.sh/demo-$RANDOM:1h
docker tag nginx $IMG && docker push $IMG
cosign generate-key-pair && cosign sign --key cosign.key $IMG && cosign verify --key cosign.pub $IMG
helm repo add kyverno https://kyverno.github.io/kyverno/
helm install kyverno kyverno/kyverno -n kyverno --create-namespace
kubectl apply -f Lab1-Platform/kyverno/verify-image.yaml   # paste cosign.pub first
```
Unsigned `ttl.sh/*` images are denied, and signed images are admitted and rewritten to a digest. For production, use [`verify-image-keyless.yaml`](Lab1-Platform/kyverno/verify-image-keyless.yaml), which trusts images signed by this repo's workflow.

### Step 6 · Falco — eBPF runtime detection
```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts && helm repo update
helm install falco falcosecurity/falco -n falco --create-namespace --set tty=true --set driver.kind=modern_ebpf
kubectl run web --image=nginx && kubectl exec -it web -- sh -c 'cat /etc/shadow'
kubectl logs -n falco -l app.kubernetes.io/name=falco -c falco
```
You should see "Terminal shell in container" and "Read sensitive file untrusted". Forward alerts with Falcosidekick to your SIEM or Slack.

---

## Lab 2 — AI stack (steps 7–10)

### Step 7 · ModelScan — unsafe model files
```bash
cd ModelScan && python3.12 -m venv .venv && source .venv/bin/activate
pip install modelscan==0.8.5
modelscan -p keras_model.h5 ; modelscan -p keras_model_trojanized.h5
```
A CRITICAL finding means os/exec/eval calls inside the serialized model. ModelScan detects serialization attacks, **not** neural backdoors in the weights. Gate it in CI before a model enters the registry.

### Step 8 · garak — LLM vulnerability scanner
```bash
pip install -U garak
garak --model_type ollama --model_name qwen3:0.6b --probes promptinject,dan,leakreplay
```
Keep the HTML + JSONL report as a **baseline**. Lab 3 compares the fine-tuned model against it.

### Step 9 · FuzzyAI — jailbreak fuzzing
```bash
python3.10 -m venv fuzzyai-env && source fuzzyai-env/bin/activate
pip install git+https://github.com/cyberark/FuzzyAI.git
fuzzyai fuzz -m ollama/qwen3:0.6b -a def -a dan -a art -t "<test prompt>"
```
`jailbreak? = True` means a guardrail gap. Use a harmful-behaviour test set, not ad-hoc prompts.

### Step 10 · Deploy the AI app, then add a gateway
```bash
kubectl apply -f AIApp/ai-app.yaml
kubectl port-forward svc/open-webui-service -n ai-stack 8080:80
kubectl apply -f AIApp/portkey.yaml
kubectl port-forward svc/portkey-service -n ai-stack 8090:8787
kubectl apply -f Lab3-SecureTraining/runtime/networkpolicy-ai-stack.yaml   # only gateway → Ollama
```
The app calls the gateway, never the model directly. Re-run garak and FuzzyAI **through the gateway** and compare. Pin the gateway image by digest: AI gateways are high-value targets (LiteLLM, March 2026).

---

## Lab 3 — Secure model training pipeline (steps 11–15)

Fine-tune **Qwen3-1.7B** (Apache 2.0, same family as the Lab 2 model) with **Unsloth QLoRA**, and gate every input and output. Full guide: [`Lab3-SecureTraining/README.md`](Lab3-SecureTraining/README.md).

| Step | What | Files |
| --- | --- | --- |
| 11 | Pin & scan the inputs: base model (revision SHA, no pickle, ModelScan) and dataset (TruffleHog, Presidio PII, fuzzy scan) | `scripts/scan_inputs.sh`, `scan_pii.py`, `fuzzy_scan.py`, `triggers.txt` |
| 12 | QLoRA fine-tune in a locked-down Job (offline, no egress, non-root, read-only data) | `scripts/train.py`, `k8s/train-job.yaml`, `k8s/namespace-training.yaml` |
| 13 | Scan the output, red-team the result against the base baseline | `scripts/gate.py`, `data/eval.jsonl` |
| 14 | Sign (OpenSSF Model Signing), AIBOM (CycloneDX ML-BOM), publish by digest, verify on admit | `scripts/make_aibom.py`, `k8s/model-validation.yaml` |
| 15 | Harden the serving pod, then watch it | `runtime/ollama-deploy.yaml`, `runtime/falco-values.yaml`, `runtime/networkpolicy-ai-stack.yaml` |

**Runtime: protect the model while it serves.**

| Threat | Control |
| --- | --- |
| Prompt injection & jailbreak (OWASP LLM01) | Input/output guardrails at the AI gateway |
| Model extraction & runaway cost (LLM10) | Per-app auth, rate limits, token quotas |
| Weight theft | Zero-egress NetworkPolicy, no `kubectl exec`, RBAC on model storage, encryption at rest |
| Tampering & model swap | Signed digest mounted read-only, re-verified every 10 minutes |
| Runtime compromise | Falco / Tetragon model-specific rules |
| Leakage & drift (LLM02) | Output PII redaction, logs → SIEM, behavioural baselines |
| **Recover** | Immutable, off-cluster backups of model registry, vector DB & config (e.g. Veeam Kasten) |

---

## Secured reference architecture

```
BUILD-TIME GATES   SBOM/AIBOM · sign images & models · model & data scan · LLM red teaming
                   └──► Admission: verify signatures · Pod Security 'restricted'
KUBERNETES (default-deny NetworkPolicy between namespaces)
  User → Gateway API + WAF → App pod → AI gateway + guardrails → vLLM / Ollama
                                            │                        │
                          DSPM ┄┄► Milvus (vector DB)          PV (encrypted)
PLATFORM CONTROLS  KSPM (kube-bench) · CWPP (Falco) · CDR/XDR (SIEM) · Identity (RBAC, agents) · Backup & DR (Kasten)
```

## What to do on Monday

| This week | This quarter | This year |
| --- | --- | --- |
| Inventory NodePort / LoadBalancer services & ingress-nginx | SBOM + sign every image; verify at admission | SLSA build L2–L3 with provenance |
| Pod Security `restricted` in warn mode everywhere | Falco / Tetragon → SIEM with on-call routing | AIBOM + model signing (OMS) with admission checks |
| Run kube-bench + Checkov; pin CI actions & scanners by SHA | Scan every model before load; move to safetensors | Agent identity & least-privilege tool access (MCP) |
| Patch NVIDIA Container Toolkit ≥ 1.17.8 on GPU nodes | AI gateway + guardrails in front of every LLM | Immutable backups + quarterly DR drills; CRA-ready reporting |

---

## References

- Frameworks: [OWASP Top 10 for LLM Apps](https://genai.owasp.org/llm-top-10/) · [OWASP Agentic Top 10](https://genai.owasp.org/) · [MITRE ATLAS](https://atlas.mitre.org/) · [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework) · [SLSA](https://slsa.dev)
- Platform: [kube-bench](https://github.com/aquasecurity/kube-bench) · [Checkov](https://www.checkov.io) · [Syft](https://github.com/anchore/syft) · [Grype](https://github.com/anchore/grype) · [cosign](https://github.com/sigstore/cosign) · [Kyverno](https://kyverno.io) · [Falco](https://falco.org)
- AI: [ModelScan](https://github.com/protectai/modelscan) · [garak](https://github.com/NVIDIA/garak) · [FuzzyAI](https://github.com/cyberark/FuzzyAI) · [Portkey gateway](https://github.com/Portkey-AI/gateway) · [Unsloth](https://unsloth.ai/docs) · [OpenSSF Model Signing](https://github.com/sigstore/model-transparency) · [model-validation-operator](https://github.com/sigstore/model-validation-operator) · [Presidio](https://github.com/microsoft/presidio) · [TruffleHog](https://github.com/trufflesecurity/trufflehog)
- Landscapes: [OWASP GenAI Security Solutions](https://genai.owasp.org/ai-security-solutions-landscape/) · [CNCF Security & Compliance](https://landscape.cncf.io/card-mode?category=security-compliance)
- Data protection: [Veeam Kasten](https://www.veeam.com/kubernetes-data-protection.html)
