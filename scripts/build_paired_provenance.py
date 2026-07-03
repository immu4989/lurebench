#!/usr/bin/env python3
"""Build paired-provenance rewrites for ONE generator (independent + robust).

Each generator runs as its own process writing its own file, so a hang or slow
model never traps another's completed work. A socket-level timeout backstops the
per-request timeout so a stuck connection can't hang the batch indefinitely.

    python scripts/build_paired_provenance.py --engine mistral \
        --label mistral-large-latest --count 300 --max-tokens 2048

Writes data/full/paired/<label>.jsonl. Human seeds are re-derived deterministically
by the eval, so no shared human file is needed here.
"""

from __future__ import annotations

import argparse
import socket
from pathlib import Path

from lurebench.generate import get_generator, rewrite_records
from lurebench.ingest.base import defang, detokenize
from lurebench.schema import Lure, load_jsonl, save_jsonl

socket.setdefaulttimeout(120)  # backstop: no socket op (connect/handshake/read) hangs forever

SEED_WORDS = 120
MIN_WORDS = 25
OUTDIR = Path("data/full/paired")


def prep_seeds(n: int):
    corpus = load_jsonl("data/full/core/train.jsonl")
    human = [r for r in corpus if r.source == "human" and r.typology == "phishing"]
    seeds = []
    for r in human:
        text = " ".join(defang(detokenize(r.text)).split()[:SEED_WORDS])
        if len(text.split()) >= MIN_WORDS:
            seeds.append(Lure(id=r.id, text=text, label=1, source="human",
                              typology="phishing", channel="email"))
        if len(seeds) >= n:
            break
    return seeds


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", required=True)
    ap.add_argument("--label", required=True)
    ap.add_argument("--count", type=int, required=True)
    ap.add_argument("--max-tokens", type=int, default=2048)
    args = ap.parse_args()

    OUTDIR.mkdir(parents=True, exist_ok=True)
    seeds = prep_seeds(args.count)
    print(f"{args.label}: prepared {len(seeds)} seeds", flush=True)

    gen = get_generator(args.engine, max_tokens=args.max_tokens)
    recs = rewrite_records(gen, seeds, generator_label=args.label, typology="phishing")
    save_jsonl(recs, OUTDIR / f"{args.label}.jsonl")
    print(f"{args.label}: {len(recs)}/{len(seeds)} rewrites -> {OUTDIR}/{args.label}.jsonl", flush=True)


if __name__ == "__main__":
    main()
