#!/usr/bin/env python3
"""Provenance evaluation on the distribution-matched paired dataset.

Human phishing (de-tokenized, defanged, length-capped) vs AI rewrites of the same
lures. Reports in-distribution provenance per generator AND leave-one-generator-out
(cross-generator) when >=2 generators are present, plus a feature inspection so the
separation can be sanity-checked for residual artifacts.

    python scripts/eval_paired_provenance.py
"""

from __future__ import annotations

import glob
import statistics

from lurebench.corpus import assign_test
from lurebench.detectors.tfidf import TfidfLogisticDetector
from lurebench.ingest.base import defang, detokenize
from lurebench.schema import Lure, load_jsonl


def prep_human(n: int):
    corpus = load_jsonl("data/full/core/train.jsonl")
    human = [r for r in corpus if r.source == "human" and r.typology == "phishing"]
    seeds = []
    for r in human:
        text = " ".join(defang(detokenize(r.text)).split()[:120])
        if len(text.split()) >= 25:
            seeds.append(Lure(id=r.id, text=text, label=1, source="human",
                              typology="phishing", channel="email"))
        if len(seeds) >= n:
            break
    return seeds


def main() -> None:
    ai = []
    for f in sorted(glob.glob("data/full/paired/*.jsonl")):
        ai.extend(r for r in load_jsonl(f) if r.source == "ai")
    if not ai:
        print("no AI rewrites yet in data/full/paired/")
        return
    gens = sorted({r.generator for r in ai})
    human = prep_human(max(300, max(sum(1 for r in ai if r.generator == g) for g in gens)))
    print(f"paired eval: {len(human)} human + {len(ai)} AI  |  generators: {gens}")
    print(f"mean words: human {round(statistics.mean(len(r.text.split()) for r in human))}"
          f"  ai {round(statistics.mean(len(r.text.split()) for r in ai))}\n")

    human_tr = [r for r in human if not assign_test(r.id)]
    human_te = [r for r in human if assign_test(r.id)]

    print("=== in-distribution provenance (random split per generator) ===")
    for g in gens:
        g_ai = [r for r in ai if r.generator == g]
        ai_tr = [r for r in g_ai if not assign_test(r.id.replace("rw-phishing-", ""))]
        ai_te = [r for r in g_ai if assign_test(r.id.replace("rw-phishing-", ""))]
        if not ai_te:
            ai_tr, ai_te = g_ai[:-max(1, len(g_ai)//10)], g_ai[-max(1, len(g_ai)//10):]
        det = TfidfLogisticDetector.train(human_tr + ai_tr, task="provenance")
        rec = sum(1 for r in ai_te if det.predict(r) == 1) / len(ai_te)
        fpr = sum(1 for r in human_te if det.predict(r) == 1) / len(human_te)
        print(f"  {g:22} AI-recall={rec:.3f}  human-FPR={fpr:.3f}  (test AI={len(ai_te)})")

    if len(gens) >= 2:
        print("\n=== LOGO cross-generator provenance (train excludes held-out generator) ===")
        for g in gens:
            ai_tr = [r for r in ai if r.generator != g]
            ai_te = [r for r in ai if r.generator == g]
            det = TfidfLogisticDetector.train(human_tr + ai_tr, task="provenance")
            rec = sum(1 for r in ai_te if det.predict(r) == 1) / len(ai_te)
            fpr = sum(1 for r in human_te if det.predict(r) == 1) / len(human_te)
            print(f"  held-out {g:22} AI-recall={rec:.3f}  human-FPR={fpr:.3f}"
                  f"  (test AI={len(ai_te)}, FPR-n={len(human_te)})")

    det = TfidfLogisticDetector.train(human_tr + ai, task="provenance")
    names = det._pipe.named_steps["tfidf"].get_feature_names_out()
    coefs = det._pipe.named_steps["clf"].coef_[0]
    order = coefs.argsort()
    print("\ntop AI features:", [names[i] for i in order[::-1][:10]])
    print("top human features:", [names[i] for i in order[:10]])


if __name__ == "__main__":
    main()
