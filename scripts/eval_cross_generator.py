#!/usr/bin/env python3
"""Cross-generator (leave-one-generator-out) evaluation for lurebench-core.

Answers the question a random-split leaderboard cannot: does a trained detector
GENERALIZE across generation styles, or did it just memorize one generator's
fingerprint? For each held-out generator, the detector is trained with NONE of
that generator's lures, then evaluated only on them.

Run from the repo root after assembling the core:
    python scripts/eval_cross_generator.py
"""

from __future__ import annotations

from lurebench.corpus import assign_test
from lurebench.detectors.tfidf import TfidfLogisticDetector
from lurebench.schema import load_jsonl
from lurebench.splits import ai_generators, leave_one_generator_out


def load_corpus():
    return load_jsonl("data/full/core/train.jsonl") + load_jsonl("data/full/core/test.jsonl")


def main() -> None:
    corpus = load_corpus()
    gens = ai_generators(corpus)
    n_ai = sum(1 for r in corpus if r.source == "ai")
    print(f"corpus: {len(corpus)} records ({n_ai} AI) | generators: {gens}\n")

    # Reference: random-split recall on AI lures (from the leaderboard) is ~1.0 —
    # a detector that saw each generator's style in training catches everything.

    print("=== LOGO — fraud detection: recall on held-out generator's AI lures ===")
    print("(the detector never saw the held-out generator in training)")
    for g in gens:
        train, test = leave_one_generator_out(corpus, g)
        det = TfidfLogisticDetector.train(train, task="fraud")
        caught = sum(1 for r in test if det.predict(r) == 1)
        rate = caught / len(test) if test else 0.0
        print(f"  held-out {g:22} recall {caught}/{len(test)} = {rate:.3f}")

    print("\n=== LOGO — provenance: flag AI-authored among FRAUD lures (human phishing vs AI) ===")
    print("(AI-recall = held-out AI lures flagged as AI; human-FPR = human phishing wrongly flagged)")
    fraud = [r for r in corpus if r.label == 1]
    human_fraud = [r for r in fraud if r.source == "human"]
    human_train = [r for r in human_fraud if not assign_test(r.id)]
    human_fpr = [r for r in human_fraud if assign_test(r.id)]
    for g in gens:
        ai_train = [r for r in fraud if r.source == "ai" and r.generator != g]
        ai_test = [r for r in fraud if r.source == "ai" and r.generator == g]
        det = TfidfLogisticDetector.train(human_train + ai_train, task="provenance")
        recall = sum(1 for r in ai_test if det.predict(r) == 1) / len(ai_test) if ai_test else 0.0
        fpr = sum(1 for r in human_fpr if det.predict(r) == 1) / len(human_fpr) if human_fpr else 0.0
        print(f"  held-out {g:22} AI-recall={recall:.3f}  human-FPR={fpr:.3f}  (test AI={len(ai_test)})")


if __name__ == "__main__":
    main()
