#!/usr/bin/env python3
"""Fuzzy dataset scan (Lab 3 · step 11).

Two checks that catch small poisoning campaigns and injected samples:

1. Near-duplicate clusters with MinHash (Jaccard on word shingles). Poisoned
   samples are often the same payload repeated with small edits.
2. Fuzzy match of every sample against a denylist of known trigger /
   prompt-injection phrases, so obfuscated variants ("ign0re previous
   instructions") are caught too.

Flagged samples go to a quarantine file for human review. Clean samples
go to the output file. Exit code 1 if anything was quarantined, so the
script works as a CI gate.

Dependencies: none required. Uses `rapidfuzz` if installed (faster, better
partial matching), otherwise falls back to difflib.

Usage:
  python fuzzy_scan.py data/train.jsonl --denylist triggers.txt \
      --minhash-threshold 0.85 --ratio 90 \
      --out data/clean.jsonl --quarantine data/quarantine.jsonl
"""
import argparse, hashlib, json, re, sys
from collections import defaultdict

try:
    from rapidfuzz import fuzz
    def partial_ratio(a, b): return fuzz.partial_ratio(a, b)
except ImportError:  # pragma: no cover - fallback path
    from difflib import SequenceMatcher
    def partial_ratio(needle, hay):
        """Best ratio of `needle` against any same-length window of `hay`."""
        if not needle or not hay:
            return 0
        if len(needle) > len(hay):
            needle, hay = hay, needle
        n, best = len(needle), 0
        step = 1 if len(hay) < 4000 else max(1, n // 4)
        for i in range(0, max(1, len(hay) - n + 1), step):
            best = max(best, SequenceMatcher(None, needle, hay[i:i + n]).ratio())
        return round(best * 100)

LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})

def normalise(t: str) -> str:
    t = t.lower().translate(LEET)
    t = re.sub(r"[^a-z0-9\s]", " ", t)
    return re.sub(r"\s+", " ", t).strip()

def text_of(rec: dict) -> str:
    parts = [str(v) for k, v in rec.items() if isinstance(v, str)]
    return " \n".join(parts)

# ---------- MinHash (pure Python) ----------
NUM_PERM = 128
MERSENNE = (1 << 61) - 1
_rng = [(int(hashlib.sha256(f"a{i}".encode()).hexdigest(), 16) % MERSENNE or 1,
         int(hashlib.sha256(f"b{i}".encode()).hexdigest(), 16) % MERSENNE) for i in range(NUM_PERM)]

def shingles(t: str, k: int = 3):
    w = t.split()
    return {" ".join(w[i:i + k]) for i in range(max(1, len(w) - k + 1))}

def minhash(sh):
    hs = [int(hashlib.md5(s.encode()).hexdigest(), 16) & 0xFFFFFFFFFFFF for s in sh] or [0]
    return [min((a * h + b) % MERSENNE for h in hs) for a, b in _rng]

def est_jaccard(m1, m2):
    return sum(x == y for x, y in zip(m1, m2)) / NUM_PERM

def lsh_candidates(sigs, bands=32):
    rows = NUM_PERM // bands
    buckets = defaultdict(list)
    for idx, sig in enumerate(sigs):
        for b in range(bands):
            buckets[(b, tuple(sig[b * rows:(b + 1) * rows]))].append(idx)
    pairs = set()
    for ids in buckets.values():
        for i in range(len(ids)):
            for j in range(i + 1, len(ids)):
                pairs.add((ids[i], ids[j]))
    return pairs

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset")
    ap.add_argument("--denylist", default="triggers.txt")
    ap.add_argument("--minhash-threshold", type=float, default=0.85)
    ap.add_argument("--min-cluster", type=int, default=3,
                    help="near-dup clusters this size or larger are quarantined (default 3)")
    ap.add_argument("--ratio", type=int, default=90, help="fuzzy match threshold 0-100")
    ap.add_argument("--out", default="data/clean.jsonl")
    ap.add_argument("--quarantine", default="data/quarantine.jsonl")
    a = ap.parse_args()

    recs = [json.loads(l) for l in open(a.dataset, encoding="utf-8") if l.strip()]
    texts = [normalise(text_of(r)) for r in recs]
    deny = [normalise(l) for l in open(a.denylist, encoding="utf-8")
            if l.strip() and not l.lstrip().startswith("#")]

    reasons = defaultdict(list)

    # 1. trigger / injection phrases
    for i, t in enumerate(texts):
        for d in deny:
            score = partial_ratio(d, t)
            if score >= a.ratio:
                reasons[i].append(f"trigger~'{d}' ({score})")
                break

    # 2. near-duplicate clusters
    sigs = [minhash(shingles(t)) for t in texts]
    parent = list(range(len(texts)))
    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]; x = parent[x]
        return x
    for i, j in lsh_candidates(sigs):
        if est_jaccard(sigs[i], sigs[j]) >= a.minhash_threshold:
            parent[find(i)] = find(j)
    clusters = defaultdict(list)
    for i in range(len(texts)):
        clusters[find(i)].append(i)
    for c in clusters.values():
        if len(c) >= a.min_cluster:
            for i in c:
                reasons[i].append(f"near-dup cluster of {len(c)}")

    with open(a.out, "w", encoding="utf-8") as fo, open(a.quarantine, "w", encoding="utf-8") as fq:
        for i, r in enumerate(recs):
            if i in reasons:
                fq.write(json.dumps({"line": i + 1, "reasons": reasons[i], "record": r}, ensure_ascii=False) + "\n")
            else:
                fo.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(f"scanned {len(recs)} samples · clean {len(recs) - len(reasons)} · quarantined {len(reasons)}")
    for i in sorted(reasons)[:20]:
        print(f"  line {i + 1}: {'; '.join(reasons[i])}")
    sys.exit(1 if reasons else 0)

if __name__ == "__main__":
    main()
