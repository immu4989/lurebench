"""Adaptive robustness: how many rewrites does a detector cost an attacker?

The one-shot paraphrase attack answers "does a single rewrite evade?". That
understates a real adversary, who rewrites, checks the result, and rewrites
again. This script closes that loop against each detector and reports the
distribution of *attempts to evade*, which is the more useful robustness number:
a detector that survives one rewrite but folds on the third is not robust, it is
slow to fail.

Only lures the detector catches on clean text are attacked — there is nothing to
evade otherwise — so the denominator differs per detector and is reported.

    export OPENROUTER_API_KEY=...
    python scripts/adaptive_robustness.py --limit 60 --rounds 5 \
        --out docs/adaptive_robustness.md
"""

from __future__ import annotations

import argparse
import collections
import concurrent.futures
import json
import os
import re
import statistics
from typing import List

from lurebench.attacks.llm import AdaptiveParaphraseAttack, provider_complete_fn
from lurebench.detectors import get_detector
from lurebench.detectors.cache import CachedDetector
from lurebench.schema import Lure, load_jsonl

CACHE_ROOT = os.path.join(".cache", "llm-experiments", "adaptive")
MINIMAL_REASONING = {"reasoning": {"effort": "minimal"}}

# Kept deliberately small: this is the most expensive experiment (a generation and
# a re-score per round per lure), so it runs on a stratified subsample.
DEFENDERS = [
    ("tfidf-logreg", {}),
    ("llm-judge", {"engine": "openrouter", "model": "openai/gpt-5-nano",
                   "extra_params": MINIMAL_REASONING}),
    ("llm-judge", {"engine": "openrouter", "model": "deepseek/deepseek-v4-flash",
                   "extra_params": MINIMAL_REASONING}),
]
DEFAULT_ATTACKER = "deepseek/deepseek-v4-flash"


def stratified_fraud(path: str, limit: int, phishing_cap: int) -> List[Lure]:
    """Keep the rare typologies, cap phishing so it cannot swamp the sample."""
    by_typ = collections.defaultdict(list)
    for rec in load_jsonl(path):
        if rec.label == 1:
            by_typ[rec.typology].append(rec)
    out = []
    for typ, recs in sorted(by_typ.items()):
        out.extend(recs[:phishing_cap] if typ == "phishing" else recs)
    out.sort(key=lambda r: r.id)
    return out[:limit] if limit else out


def _label(name: str, kwargs: dict) -> str:
    model = kwargs.get("model")
    return f"{name} ({model})" if model else name


def run_defender(name, kwargs, lures, attacker_model, rounds, threshold, workers):
    label = _label(name, kwargs)
    det = get_detector(name, **kwargs)
    det.name = label
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", label)
    det = CachedDetector(det, os.path.join(CACHE_ROOT, f"{safe}.json"))

    def score_text(text: str):
        return det.score(Lure(id="adaptive", text=text, label=1,
                              source="human", typology="phishing"))

    complete = provider_complete_fn("openrouter", attacker_model, max_tokens=700)
    results = []

    def one(lure: Lure):
        atk = AdaptiveParaphraseAttack(complete, score_text,
                                       threshold=threshold, max_rounds=rounds)
        return atk.run(lure.text)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(one, lures))
    det.flush()

    caught = [r for r in results if r.scores and r.scores[0] >= threshold]
    evaded = [r for r in caught if r.evaded]
    attempts = [r.attempts_to_evade for r in evaded]
    return {
        "detector": label,
        "n_lures": len(lures),
        "n_caught_clean": len(caught),
        "n_evaded": len(evaded),
        "evasion_rate": (len(evaded) / len(caught)) if caught else None,
        "median_attempts": statistics.median(attempts) if attempts else None,
        "evaded_by_round": {
            r: sum(1 for a in attempts if a <= r) / len(caught) if caught else None
            for r in range(1, rounds + 1)
        },
    }


def to_markdown(rows, rounds, attacker, label, threshold) -> str:
    out = ["# Adaptive robustness: attempts to evade\n",
           "A real attacker does not stop after one rewrite. Each row attacks only the "
           "lures that detector caught on clean text (there is nothing to evade "
           "otherwise), paraphrasing repeatedly until the score falls below the "
           f"threshold or the {rounds}-round budget runs out. The rewrite is instructed "
           "to preserve the message's intent, so an 'evasion' that simply dropped the "
           "fraudulent ask does not count.\n",
           f"_Attacker `{attacker}` · {label} · threshold {threshold:.2f}._\n",
           "| Detector | caught clean | evaded within budget | median attempts | "
           + " | ".join(f"≤{r}" for r in range(1, rounds + 1)) + " |",
           "|---" * (5 + rounds) + "|"]
    for r in rows:
        cum = " | ".join(
            "  -  " if r["evaded_by_round"][k] is None else f"{r['evaded_by_round'][k]:.0%}"
            for k in range(1, rounds + 1)
        )
        rate = "  -  " if r["evasion_rate"] is None else f"{r['evasion_rate']:.0%}"
        med = "  -  " if r["median_attempts"] is None else f"{r['median_attempts']:.0f}"
        out.append(f"| `{r['detector']}` | {r['n_caught_clean']}/{r['n_lures']} | "
                   f"{rate} | {med} | {cum} |")
    out += ["",
            "The cumulative columns are the point: they show how quickly a detector "
            "gives way as the attacker keeps trying. A detector whose ≤1 column is low "
            "but whose ≤5 column is high is not resisting the attack, only delaying it.",
            "",
            "This table inverts the character-attack result. Against homoglyphs and "
            "zero-width padding the token baselines collapse and the LLM judges are "
            "essentially immune, because those attacks change spelling and the judges "
            "read meaning. Against an attacker that rewrites *meaning* the ordering "
            "reverses: the trained TF-IDF model is the hardest to get past, while the "
            "judges give way — and keep giving way as the budget grows, which is the "
            "signature of delay rather than resistance. The two detector families fail "
            "in complementary directions, which is an argument for running both rather "
            "than picking a winner.",
            "",
            f"Caveat: the attacker (`{attacker}`) is also one of the defenders, and that "
            "row is the most evadable. Some of that gap is likely self-coupling — a model "
            "rewriting text to get past itself — so read the cross-vendor rows as the "
            "cleaner measurement. Each row's denominator is only the lures that detector "
            "caught clean, so rows are not scored on identical sets.",
            "",
            "These numbers are a **lower bound**. The attacker runs at temperature 0 so "
            "the experiment reproduces exactly, but a deterministic rewriter can converge: "
            "once it settles into a phrasing, further rounds rewrite that same phrasing "
            "the same way and stop finding new ground. Where a row's cumulative columns "
            "go flat, that is what happened — the budget was not exhausted, the attacker "
            "was. A sampling attacker (`temperature > 0`) explores more and evades more; "
            "an earlier temperature-1.0 run of this same setup put the judges a few points "
            "higher. Reproducibility was worth that trade here, but do not read these "
            "rates as the ceiling.",
            ""]
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--data", default="data/full/core/test.jsonl")
    ap.add_argument("--limit", type=int, default=60)
    ap.add_argument("--phishing-cap", type=int, default=25)
    ap.add_argument("--rounds", type=int, default=5)
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--workers", type=int, default=10)
    ap.add_argument("--attacker", default=DEFAULT_ATTACKER)
    ap.add_argument("--out", default=None)
    ap.add_argument("--json", default=None)
    args = ap.parse_args(argv)
    if not os.environ.get("OPENROUTER_API_KEY"):
        raise SystemExit("OPENROUTER_API_KEY is not set")

    lures = stratified_fraud(args.data, args.limit, args.phishing_cap)
    print(f"{len(lures)} fraud lures · {len(DEFENDERS)} detectors · {args.rounds} rounds")
    rows = []
    for name, kwargs in DEFENDERS:
        print(f"  attacking {_label(name, kwargs)} ...")
        rows.append(run_defender(name, kwargs, lures, args.attacker,
                                 args.rounds, args.threshold, args.workers))

    md = to_markdown(rows, args.rounds, args.attacker, args.data, args.threshold)
    print("\n" + md)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(md)
        print(f"wrote {args.out}")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(rows, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
