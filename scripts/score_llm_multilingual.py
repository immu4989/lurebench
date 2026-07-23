#!/usr/bin/env python3
"""Score the multilingual eval set with llm-judge, raw and artifact-controlled.

Answers the experiment: tfidf-logreg's cross-lingual recall was an artifact (it
collapsed on non-Latin scripts once the <<link>> placeholder was stripped). Does an
LLM detector actually read the fraud, or does it lean on the same artifact?

Scores every fraud lure twice (raw text + placeholder-stripped) with llm-judge, using
a thread pool for throughput and an incremental JSON cache so a slow/interrupted run is
never lost and re-runs resume. Then prints per-language recall raw vs controlled.

    python scripts/score_llm_multilingual.py --engine deepseek --workers 6
"""

from __future__ import annotations

import argparse
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor

from lurebench.detectors import get_detector
from lurebench.multilingual import strip_artifacts
from lurebench.generate.base import language_name
from lurebench.schema import Lure, load_jsonl

EVAL = "data/full/multilingual/eval.jsonl"


def _load_env():
    if os.path.exists(".env"):
        for line in open(".env"):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k, v.strip())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", default="deepseek")
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--cache", default=None)
    args = ap.parse_args()
    _load_env()
    cache_path = args.cache or f"data/full/multilingual/llm_scores_{args.engine}.json"

    records = [r for r in load_jsonl(EVAL) if r.label == 1]
    cache = json.load(open(cache_path)) if os.path.exists(cache_path) else {}
    lock = threading.Lock()
    det = get_detector("llm-judge", engine=args.engine)

    jobs = []
    for r in records:
        jobs.append((f"{r.id}|raw", r.text))
        jobs.append((f"{r.id}|ctrl", strip_artifacts(r.text)))
    todo = [(k, t) for k, t in jobs if k not in cache]
    print(f"{len(records)} lures, {len(jobs)} scores needed, {len(todo)} to do "
          f"({len(cache)} cached)", flush=True)

    done = [0]

    def work(item):
        key, text = item
        s = det.score(Lure(id="x", text=text, label=1, source="ai", typology="phishing"))
        with lock:
            cache[key] = s
            done[0] += 1
            if done[0] % 20 == 0:
                json.dump(cache, open(cache_path, "w"))
                print(f"  {done[0]}/{len(todo)}", flush=True)

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        list(ex.map(work, todo))
    json.dump(cache, open(cache_path, "w"))

    # per-language recall
    by_lang = {}
    for r in records:
        by_lang.setdefault(r.language, []).append(r)

    def recall(recs, variant):
        vals = [cache.get(f"{r.id}|{variant}") for r in recs]
        vals = [v for v in vals if v is not None]
        if not vals:
            return None, 0
        return sum(1 for v in vals if v >= 0.5) / len(vals), len(vals)

    order = sorted(by_lang, key=lambda x: (x != "en", -len(by_lang[x])))
    print(f"\n# llm-judge ({args.engine}) cross-lingual recall\n")
    print("| Language | Lures | Recall (raw) | Recall (artifact-controlled) |")
    print("|---|---|---|---|")
    for lang in order:
        rr, n = recall(by_lang[lang], "raw")
        cr, _ = recall(by_lang[lang], "ctrl")
        print(f"| {language_name(lang)} | {n} | "
              f"{rr:.2f} | {cr:.2f} |")


if __name__ == "__main__":
    main()
