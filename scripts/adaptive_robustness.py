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
from lurebench.generate.completion_cache import CompletionCache
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


def run_defender(name, kwargs, lures, attacker_model, rounds, threshold, workers,
                 replicate: int = 0):
    label = _label(name, kwargs)
    det = get_detector(name, **kwargs)
    det.name = label
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", label)
    det = CachedDetector(det, os.path.join(CACHE_ROOT, f"{safe}.json"), flush_every=1)

    def score_text(text: str):
        return det.score(Lure(id="adaptive", text=text, label=1,
                              source="human", typology="phishing"))

    # Cache the attacker's rewrites so re-analysing a replicate is nearly free.
    # Each replicate gets its own namespace: sharing one would make later replicates
    # replay the first one's chain, collapsing the repeats into a single sample and
    # hiding exactly the run-to-run variance they exist to measure.
    raw_complete = provider_complete_fn("openrouter", attacker_model, max_tokens=700)
    gen_cache = CompletionCache(
        os.path.join(CACHE_ROOT, f"generations_r{replicate}.json"), flush_every=1,
    )
    complete = gen_cache.wrap(raw_complete, model=attacker_model)
    results = []

    def one(lure: Lure):
        atk = AdaptiveParaphraseAttack(complete, score_text,
                                       threshold=threshold, max_rounds=rounds)
        return atk.run(lure.text)

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            results = list(ex.map(one, lures))
    finally:
        # Preserve completed paid work even when another observation is unavailable.
        det.flush()
        gen_cache.flush()
    print(f"    generations: {gen_cache.hits} cached, {gen_cache.misses} new")

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


def aggregate(replicate_rows) -> list:
    """Collapse K replicates of each detector into mean and observed range.

    A single run of this experiment is a noisy sample: hosted providers are not
    bit-deterministic even at temperature 0, so the same setup re-run gives a
    different attack chain and a different evasion rate. Reporting one number as if
    it were exact overstates the precision, so every rate here carries the spread
    across replicates.
    """
    by_detector = {}
    for rows in replicate_rows:
        for r in rows:
            by_detector.setdefault(r["detector"], []).append(r)
    out = []
    for detector, runs in by_detector.items():
        rates = [r["evasion_rate"] for r in runs if r["evasion_rate"] is not None]
        complete = len(rates) == len(runs)
        caught = [r["n_caught_clean"] for r in runs]
        agg = {
            "detector": detector,
            "n_replicates": len(runs),
            "n_replicates_with_rates": len(rates),
            "n_lures": runs[0]["n_lures"],
            "n_caught_clean_mean": statistics.mean(caught),
            "evasion_mean": statistics.mean(rates) if complete else None,
            "evasion_min": min(rates) if complete else None,
            "evasion_max": max(rates) if complete else None,
            "by_round_mean": {},
        }
        # Normalise round keys to str: they are ints in memory but strings once a
        # replicate has been round-tripped through JSON, and the renderer must not
        # care which path the data took.
        rounds = [{str(k): v for k, v in r["evaded_by_round"].items()} for r in runs]
        for k in rounds[0]:
            vals = [r.get(k) for r in rounds]
            agg["by_round_mean"][k] = (
                statistics.mean(vals) if all(v is not None for v in vals) else None
            )
        out.append(agg)
    return out


def to_markdown_agg(rows, rounds, attacker, label, threshold, replicates) -> str:
    out = ["# Adaptive robustness: attempts to evade\n",
           "A real attacker does not stop after one rewrite. Each row attacks only the "
           "lures that detector caught on clean text, paraphrasing repeatedly until the "
           f"score falls below the threshold or the {rounds}-round budget runs out. The "
           "rewrite is instructed to preserve intent, but this script does not verify "
           "that condition. Reported evasions are score drops pending intent review.\n",
           f"**Every rate is the mean of {replicates} configured replicates, with the "
           "observed range in brackets.** One run is not enough: hosted providers are not "
           "bit-deterministic even at temperature 0, so re-running the same setup "
           "produces a different attack chain and a materially different rate. An earlier "
           "single-run version of this table reported numbers that moved by up to 20 "
           "points on re-run.\n",
           f"_Attacker `{attacker}` · {label} · threshold {threshold:.2f}._\n",
           "| Detector | caught clean | evaded (mean [min-max]) | "
           + " | ".join(f"≤{r}" for r in range(1, rounds + 1)) + " |",
           "|---" * (3 + rounds) + "|"]
    for r in rows:
        cum = " | ".join(
            "  -  " if r["by_round_mean"].get(str(k)) is None
            else f"{r['by_round_mean'][str(k)]:.0%}"
            for k in range(1, rounds + 1)
        )
        if r["evasion_mean"] is None:
            rate = "  -  "
        else:
            rate = (f"{r['evasion_mean']:.0%} "
                    f"[{r['evasion_min']:.0%}-{r['evasion_max']:.0%}]")
        out.append(f"| `{r['detector']}` | {r['n_caught_clean_mean']:.0f}/{r['n_lures']} | "
                   f"{rate} | {cum} |")
    out += [
        "",
        "The cumulative columns show how quickly a detector gives way as the attacker "
        "keeps trying. A detector whose ≤1 column is low but whose ≤5 column is high is "
        "not resisting the attack, only delaying it.",
        "",
        "Observed replicate ranges are descriptive, not confidence intervals. Separate "
        "cache namespaces prevent replay across replicates but do not establish their "
        "statistical independence. Missing replicate rates make the aggregate unavailable; "
        "they are not dropped from the mean.",
        "",
        f"Check whether attacker `{attacker}` is also a defender before interpreting "
        "cross-model differences. Each row includes only the lures its detector caught "
        "clean; rows may have different populations. No universal ranking or deployment "
        "guarantee follows from this experiment.",
        "",
    ]
    return "\n".join(out)


def to_markdown(rows, rounds, attacker, label, threshold) -> str:
    out = ["# Adaptive robustness: attempts to evade\n",
           "A real attacker does not stop after one rewrite. Each row attacks only the "
           "lures that detector caught on clean text (there is nothing to evade "
           "otherwise), paraphrasing repeatedly until the score falls below the "
           f"threshold or the {rounds}-round budget runs out. The rewrite is instructed "
           "to preserve the message's intent, but intent preservation is not verified "
           "by this script. Reported evasions are score drops pending that review.\n",
           f"_Attacker `{attacker}` · {label} · threshold {threshold:.2f}._\n",
           "| Detector | caught clean | evaded within budget | median attempts | "
           + " | ".join(f"≤{r}" for r in range(1, rounds + 1)) + " |",
           "|---" * (4 + rounds) + "|"]
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
            "Interpret score drops only after reviewing whether the rewritten message "
            "retained the original fraudulent intent. This script has no independent "
            "intent validator and does not establish a universal detector ranking.",
            "",
            f"Check whether attacker `{attacker}` is also a defender. Each row includes "
            "only the lures that detector caught clean, so rows may describe different "
            "populations rather than a paired comparison.",
            "",
            "Temperature zero does not guarantee provider determinism; only cached "
            "responses replay exactly. A flat cumulative curve does not identify its "
            "cause, and a different sampling configuration may change results in either "
            "direction. These rates are not a certified lower bound on effective attacks.",
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
    ap.add_argument("--replicates", type=int, default=3,
                    help="separate cache namespaces; one run is a noisy sample, so rates "
                         "are reported as a mean with the observed range")
    ap.add_argument("--attacker", default=DEFAULT_ATTACKER)
    ap.add_argument("--out", default=None)
    ap.add_argument("--json", default=None)
    args = ap.parse_args(argv)
    if not os.environ.get("OPENROUTER_API_KEY"):
        raise SystemExit("OPENROUTER_API_KEY is not set")

    lures = stratified_fraud(args.data, args.limit, args.phishing_cap)
    print(f"{len(lures)} fraud lures · {len(DEFENDERS)} detectors · {args.rounds} rounds "
          f"· {args.replicates} replicates")
    replicate_rows = []
    for rep in range(args.replicates):
        print(f"  replicate {rep + 1}/{args.replicates}")
        rows = []
        for name, kwargs in DEFENDERS:
            print(f"    attacking {_label(name, kwargs)} ...")
            rows.append(run_defender(name, kwargs, lures, args.attacker, args.rounds,
                                     args.threshold, args.workers, replicate=rep))
        replicate_rows.append(rows)

    rows = aggregate(replicate_rows)
    md = to_markdown_agg(rows, args.rounds, args.attacker, args.data, args.threshold,
                         args.replicates)
    print("\n" + md)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(md)
        print(f"wrote {args.out}")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"aggregate": rows, "replicates": replicate_rows}, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
