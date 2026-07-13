#!/usr/bin/env python3
"""Generate the multilingual fraud-lure pilot — resiliently and rate-limit-aware.

Produces hard-mode AI lures across several languages using the providers that handle
them well (Mistral for European languages, DeepSeek for Chinese), so LureBench can
measure how English-trained detectors hold up under a language shift.

Two lessons baked in:
- **Save after every cell** so a slow provider can never trap already-generated work.
- **Pace requests** (a deliberate delay between calls) so they clear the provider's
  rate limit on the first try instead of burning time on 429 retries. Proactive spacing
  yields far more lures per minute than reactive backoff when a provider is rps-capped.

    python scripts/build_multilingual_pilot.py --n 15 --delay 2.5
    python scripts/build_multilingual_pilot.py --engines mistral            # skip slow zh

Reads provider keys from the environment (or a local .env). Resume-friendly: re-running
tops up cells that don't yet have their full target count.
"""

from __future__ import annotations

import argparse
import os
import time

from lurebench.generate import get_generator
from lurebench.generate.base import GenerationSpec, language_name
from lurebench.generate.pipeline import generate_records
from lurebench.schema import load_jsonl, save_jsonl

CELLS = [
    ("mistral", "es"), ("mistral", "fr"), ("mistral", "de"),
    ("mistral", "it"), ("mistral", "pt"),
    ("deepseek", "zh"),
]
TYPOLOGIES = ["phishing", "bec"]
OUT = "data/full/multilingual/pilot.jsonl"


def _load_env() -> None:
    if os.path.exists(".env"):
        for line in open(".env"):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k, v.strip())


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=15, help="target lures per (language, typology) cell")
    ap.add_argument("--engines", default="mistral,deepseek")
    ap.add_argument("--delay", type=float, default=2.5, help="seconds between calls (rate-limit spacing)")
    ap.add_argument("--timeout", type=float, default=45.0)
    ap.add_argument("--retries", type=int, default=3)
    args = ap.parse_args()
    _load_env()
    engines = set(args.engines.split(","))

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    records = list(load_jsonl(OUT)) if os.path.exists(OUT) else []
    have: dict = {}
    for r in records:
        have[r.id.rsplit("-", 1)[0]] = have.get(r.id.rsplit("-", 1)[0], 0) + 1

    for engine, lang in CELLS:
        if engine not in engines:
            continue
        try:
            gen = get_generator(engine, max_tokens=3072 if engine == "deepseek" else 1024,
                                timeout=args.timeout, max_retries=args.retries)
        except Exception as exc:  # noqa: BLE001
            print(f"! skip {engine}/{lang}: {exc}", flush=True)
            continue
        for typ in TYPOLOGIES:
            cell = f"ml-{lang}-{typ}"
            need = args.n - have.get(cell, 0)
            if need <= 0:
                print(f"skip {cell} (have {have.get(cell, 0)})", flush=True)
                continue
            spec = GenerationSpec(typology=typ, channel="email", language=lang,
                                  hard=True, generator=engine)
            t0 = time.time()
            got = 0
            idx = have.get(cell, 0)
            # One lure per call, spaced, so rate limits don't shred the batch.
            for _ in range(need):
                recs = generate_records(gen, spec, 1)
                for r in recs:
                    r.id = f"{cell}-{idx:04d}"
                    idx += 1
                    got += 1
                    records.append(r)
                save_jsonl(records, OUT)  # persist after every lure
                time.sleep(args.delay)
            print(f"{engine}/{lang}/{typ} ({language_name(lang)}): +{got}/{need} "
                  f"in {time.time() - t0:.0f}s  [total {len(records)}]", flush=True)

    print(f"\nwrote {len(records)} records -> {OUT}", flush=True)


if __name__ == "__main__":
    main()
