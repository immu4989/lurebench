#!/usr/bin/env python3
"""Build the distribution-matched paired provenance dataset.

Human phishing lures (de-tokenized to natural prose, defanged, length-capped) and
an AI rewrite of each — same scenario, typology, and length. This is the
confound-controlled basis for "can you tell AI-authored fraud from human-authored?"

500 seeds x {DeepSeek, Mistral}, run concurrently. Run from repo root with keys:
    set -a; source .env; set +a
    python scripts/build_paired_provenance.py
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from lurebench.generate import get_generator, rewrite_records
from lurebench.ingest.base import defang, detokenize
from lurebench.schema import Lure, load_jsonl, save_jsonl

N_SEEDS = 500
SEED_WORDS = 120
MIN_WORDS = 25
# (engine, provenance-label, max_tokens) — DeepSeek reasons, so give it more room.
GENERATORS = [
    ("deepseek", "deepseek-v4-pro", 3072),
    ("mistral", "mistral-large-latest", 2048),
]
OUT = "data/full/paired/phishing_provenance.jsonl"


def prep_seeds():
    corpus = load_jsonl("data/full/core/train.jsonl")
    human = [r for r in corpus if r.source == "human" and r.typology == "phishing"]
    seeds = []
    for r in human:
        text = " ".join(defang(detokenize(r.text)).split()[:SEED_WORDS])
        if len(text.split()) >= MIN_WORDS:
            seeds.append(Lure(id=r.id, text=text, label=1, source="human",
                              typology="phishing", channel="email"))
        if len(seeds) >= N_SEEDS:
            break
    return seeds


def main() -> None:
    seeds = prep_seeds()
    print(f"prepared {len(seeds)} human phishing seeds", flush=True)

    def do(engine, label, max_tokens):
        gen = get_generator(engine, max_tokens=max_tokens)
        recs = rewrite_records(gen, seeds, generator_label=label, typology="phishing")
        print(f"{label}: {len(recs)}/{len(seeds)} rewrites", flush=True)
        return recs

    ai = []
    with ThreadPoolExecutor(max_workers=len(GENERATORS)) as ex:
        futs = [ex.submit(do, e, lbl, mt) for e, lbl, mt in GENERATORS]
        for f in futs:
            ai.extend(f.result())

    paired = list(seeds) + ai
    Path("data/full/paired").mkdir(parents=True, exist_ok=True)
    save_jsonl(paired, OUT)
    print(f"saved {len(seeds)} human + {len(ai)} AI -> {OUT}", flush=True)


if __name__ == "__main__":
    main()
