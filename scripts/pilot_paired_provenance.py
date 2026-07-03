#!/usr/bin/env python3
"""PILOT: distribution-matched provenance via paired rewriting.

Takes real human phishing lures, has each LLM rewrite the SAME lure (matched
scenario / typology / length / defang), then tests whether a detector can still
tell human-authored from AI-authored. If the confound was doing the work, the
near-perfect separation from the confounded corpus (recall ~1.0, FPR ~0.001)
should DEGRADE here — higher FPR, lower recall, and top features that are about
authorship rather than corpus artifacts (defang/length/era).

Small by design (validate before a full batch). Uses deepseek + mistral to avoid
GLM rate contention. Run from repo root with provider keys sourced.
"""

from __future__ import annotations

from lurebench.corpus import assign_test
from lurebench.detectors.tfidf import TfidfLogisticDetector
from lurebench.generate import get_generator, rewrite_records
from lurebench.ingest.base import defang
from lurebench.schema import Lure, load_jsonl, save_jsonl

N_SEEDS = 40
SEED_WORDS = 120  # truncate seeds so human/AI lengths are comparable
GENERATORS = [("deepseek", "deepseek-v4-pro"), ("mistral", "mistral-large-latest")]


def prep_seeds():
    corpus = load_jsonl("data/full/core/train.jsonl")
    human = [r for r in corpus if r.source == "human" and r.typology == "phishing"]
    seeds = []
    for r in human[:N_SEEDS]:
        text = defang(" ".join(r.text.split()[:SEED_WORDS]))  # clean + length-cap
        if len(text.split()) >= 20:
            seeds.append(Lure(id=r.id, text=text, label=1, source="human",
                              typology="phishing", channel="email"))
    return seeds


def main() -> None:
    seeds = prep_seeds()
    print(f"prepared {len(seeds)} human phishing seeds (<= {SEED_WORDS} words, re-defanged)\n")

    paired = list(seeds)  # human originals
    for engine, label in GENERATORS:
        gen = get_generator(engine, max_tokens=2048)
        rewrites = rewrite_records(gen, seeds, generator_label=label, typology="phishing")
        stats = getattr(gen, "stats", {})
        print(f"{label}: {len(rewrites)} rewrites (stats: {stats})")
        paired.extend(rewrites)

    save_jsonl(paired, "staging/paired_provenance.jsonl")
    ai = [r for r in paired if r.source == "ai"]
    human = [r for r in paired if r.source == "human"]
    import statistics
    print(f"\npaired set: {len(human)} human + {len(ai)} AI")
    print(f"mean words: human {round(statistics.mean(len(r.text.split()) for r in human))}"
          f"  ai {round(statistics.mean(len(r.text.split()) for r in ai))}")

    # LOGO provenance on the matched set
    print("\n=== LOGO provenance on DISTRIBUTION-MATCHED pairs (was recall~1.0 / FPR~0.001) ===")
    gens = sorted({r.generator for r in ai})
    human_train = [r for r in human if not assign_test(r.id)]
    human_fpr = [r for r in human if assign_test(r.id)]
    for g in gens:
        ai_tr = [r for r in ai if r.generator != g]
        ai_te = [r for r in ai if r.generator == g]
        det = TfidfLogisticDetector.train(human_train + ai_tr, task="provenance")
        recall = sum(1 for r in ai_te if det.predict(r) == 1) / len(ai_te) if ai_te else 0.0
        fpr = sum(1 for r in human_fpr if det.predict(r) == 1) / len(human_fpr) if human_fpr else 0.0
        print(f"  held-out {g:22} AI-recall={recall:.3f}  human-FPR={fpr:.3f}")

    # what does it key on now?
    det = TfidfLogisticDetector.train(human_train + ai, task="provenance")
    names = det._pipe.named_steps["tfidf"].get_feature_names_out()
    coefs = det._pipe.named_steps["clf"].coef_[0]
    order = coefs.argsort()
    print("\ntop AI-indicative features:", [names[i] for i in order[::-1][:10]])
    print("top human-indicative features:", [names[i] for i in order[:10]])


if __name__ == "__main__":
    main()
