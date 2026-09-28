#!/usr/bin/env python3
"""PII scan + redaction for a JSONL dataset (Lab 3 · step 11).

Uses Microsoft Presidio when installed (recommended):
    pip install presidio-analyzer presidio-anonymizer
    python -m spacy download en_core_web_lg
Falls back to a small regex set (email, phone, card, IPv4, US SSN) so the
lab still runs offline.

Writes a redacted copy of the dataset and exits 1 if any PII was found
(use --no-fail to only redact).

Usage:
  python scan_pii.py data/train.jsonl --out data/redacted.jsonl
"""
import argparse, json, re, sys

def luhn(num: str) -> bool:
    d = [int(c) for c in num if c.isdigit()]
    if len(d) < 13: return False
    s = 0
    for i, x in enumerate(reversed(d)):
        if i % 2: x = x * 2 - 9 if x * 2 > 9 else x * 2
        s += x
    return s % 10 == 0

REGEX = {
    "EMAIL_ADDRESS": re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"),
    "PHONE_NUMBER": re.compile(r"(?<!\d)(?:\+?\d{1,3}[ -]?)?(?:\(?\d{2,4}\)?[ -]?)\d{3,4}[ -]?\d{4}(?!\d)"),
    "CREDIT_CARD": re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"),
    "IP_ADDRESS": re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)"),
    "US_SSN": re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"),
    # secrets are not PII, but never let them reach a training set: redact as a second line of defence
    "AWS_ACCESS_KEY": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "SECRET_40": re.compile(r"(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])"),
}

def regex_findings(text):
    out = []
    for ent, rx in REGEX.items():
        for m in rx.finditer(text):
            if ent == "CREDIT_CARD" and not luhn(m.group()): continue
            out.append((m.start(), m.end(), ent))
    # drop overlaps, keep longest
    out.sort(key=lambda x: (x[0], -(x[1] - x[0])))
    res, last = [], -1
    for s, e, t in out:
        if s >= last: res.append((s, e, t)); last = e
    return res

def make_engine():
    try:
        from presidio_analyzer import AnalyzerEngine
        eng = AnalyzerEngine()
        ents = ["EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "IP_ADDRESS", "US_SSN", "PERSON", "IBAN_CODE"]
        def find(text):
            spans = [(r.start, r.end, r.entity_type) for r in eng.analyze(text=text, entities=ents, language="en") if r.score >= 0.6]
            return spans + [x for x in regex_findings(text) if x[2] in ("AWS_ACCESS_KEY", "SECRET_40")]
        return find, "presidio"
    except Exception:
        return regex_findings, "regex-fallback"

def redact(text, spans):
    for s, e, t in sorted(spans, reverse=True):
        text = text[:s] + f"<{t}>" + text[e:]
    return text

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset")
    ap.add_argument("--out", default="data/redacted.jsonl")
    ap.add_argument("--no-fail", action="store_true")
    a = ap.parse_args()
    find, engine = make_engine()
    hits, n = 0, 0
    with open(a.dataset, encoding="utf-8") as fi, open(a.out, "w", encoding="utf-8") as fo:
        for ln, line in enumerate(fi, 1):
            if not line.strip(): continue
            n += 1
            rec = json.loads(line)
            for k, v in rec.items():
                if isinstance(v, str):
                    spans = find(v)
                    if spans:
                        hits += len(spans)
                        print(f"  line {ln} [{k}]: " + ", ".join(sorted({t for _, _, t in spans})))
                        rec[k] = redact(v, spans)
            fo.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(f"engine={engine} · scanned {n} samples · {hits} PII entities redacted → {a.out}")
    sys.exit(1 if hits and not a.no_fail else 0)

if __name__ == "__main__":
    main()
