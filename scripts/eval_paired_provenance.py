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

    # Index-based holdout (every 5th) — self-contained; these records are all from
    # the corpus train split, so the corpus id-hash can't provide a holdout here.
    def split(records, k=5):
        test = records[::k]
        train = [r for i, r in enumerate(records) if i % k != 0]
        return train, test

    human_tr, human_te = split(human)

    print("=== in-distribution provenance (random split per generator) ===")
    for g in gens:
        g_ai = [r for r in ai if r.generator == g]
        ai_tr, ai_te = split(g_ai)
        det = TfidfLogisticDetector.train(human_tr + ai_tr, task="provenance")
        rec = sum(1 for r in ai_te if det.predict(r) == 1) / len(ai_te)
        fpr = sum(1 for r in human_te if det.predict(r) == 1) / len(human_te)
        print(f"  {g:22} AI-recall={rec:.3f}  human-FPR={fpr:.3f}  (test AI={len(ai_te)})")

    if len(gens) >= 2:
        from lurebench.metrics import roc_auc
        print("\n=== LOGO cross-generator provenance (train excludes held-out generator) ===")
        print("  bal-acc = balanced accuracy (0.5 = chance); AUC = threshold-independent discrimination")
        for g in gens:
            ai_tr = [r for r in ai if r.generator != g]
            ai_te = [r for r in ai if r.generator == g]
            det = TfidfLogisticDetector.train(human_tr + ai_tr, task="provenance")
            rec = sum(1 for r in ai_te if det.predict(r) == 1) / len(ai_te)
            fpr = sum(1 for r in human_te if det.predict(r) == 1) / len(human_te)
            bal = (rec + (1 - fpr)) / 2
            y = [0] * len(human_te) + [1] * len(ai_te)
            scores = [det.score(r) for r in human_te + ai_te]
            auc = roc_auc(y, scores)
            print(f"  held-out {g:22} bal-acc={bal:.3f}  AUC={auc:.3f}  "
                  f"(recall={rec:.2f}, FPR={fpr:.2f}, test AI={len(ai_te)})")

    det = TfidfLogisticDetector.train(human_tr + ai, task="provenance")
    names = det._pipe.named_steps["tfidf"].get_feature_names_out()
    coefs = det._pipe.named_steps["clf"].coef_[0]
    order = coefs.argsort()
    print("\ntop AI features:", [names[i] for i in order[::-1][:10]])
    print("top human features:", [names[i] for i in order[:10]])


if __name__ == "__main__":
    main()
