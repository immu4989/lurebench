#!/usr/bin/env python3
"""Robustness of llm-judge vs the baselines, on a fraud-lure sample.

The character attacks (one homoglyph, leet, ...) drove the keyword detector's attack
success rate to ~0.99 and dented tfidf. Does an LLM that reads meaning survive them, and
does it survive an LLM paraphrase designed to beat semantic detectors?

Scores a sample of caught fraud lures clean + attacked with llm-judge (concurrent, cached),
computes attack-success-rate, and prints it next to tfidf-logreg / heuristic-v0 (scored
locally). ASR = of lures caught clean, the fraction that evade after the attack.

    python scripts/score_llm_robustness.py --engine deepseek --n 50 --workers 6
"""

from __future__ import annotations

import argparse
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

from lurebench.attacks import get_attack
from lurebench.detectors import get_detector
from lurebench.robustness import run_robustness
from lurebench.schema import Lure, load_jsonl

CHAR_ATTACKS = ["homoglyph", "leet", "zero-width", "whitespace"]


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
    ap.add_argument("--n", type=int, default=50)
    ap.add_argument("--workers", type=int, default=6)
    args = ap.parse_args()
    _load_env()
    cache_path = f"data/full/multilingual/llm_robust_{args.engine}.json"

    core = load_jsonl("data/full/core/test.jsonl")
    # Dedup by id (the generated shards can carry colliding ids across typologies).
    seen, sample = set(), []
    for r in core:
        if r.label == 1 and r.source == "ai" and r.id not in seen:
            seen.add(r.id)
            sample.append(r)
        if len(sample) >= args.n:
            break
    det = get_detector("llm-judge", engine=args.engine)
    cache = json.load(open(cache_path)) if os.path.exists(cache_path) else {}
    lock = threading.Lock()

    # Precompute attacked text per lure (deterministic char attacks).
    attackers = {a: get_attack(a) for a in CHAR_ATTACKS}
    variants = {}  # key -> text
    for r in sample:
        variants[f"{r.id}|clean"] = r.text
        for a in CHAR_ATTACKS:
            variants[f"{r.id}|{a}"] = attackers[a].apply(r.text)
    # llm-paraphrase: rewrite each lure with the same provider (an LLM attack).
    from lurebench.attacks.llm import LLMParaphraseAttack, provider_complete_fn
    para = LLMParaphraseAttack(provider_complete_fn(args.engine, max_tokens=1024))

    todo = [(k, t) for k, t in variants.items() if k not in cache]
    print(f"{len(sample)} lures; {len(variants)} char-variant scores, {len(todo)} to do",
          flush=True)
    done = [0]

    def score_key(item):
        key, text = item
        s = det.score(Lure(id="x", text=text, label=1, source="ai", typology="phishing"))
        with lock:
            cache[key] = s
            done[0] += 1
            if done[0] % 25 == 0:
                json.dump(cache, open(cache_path, "w"))
                print(f"  {done[0]}/{len(todo)}", flush=True)

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        list(ex.map(score_key, todo))

    # paraphrase (generate + score), also cached/concurrent
    para_todo = [r for r in sample if f"{r.id}|paraphrase" not in cache]
    print(f"paraphrase: {len(para_todo)} to generate+score", flush=True)

    def para_key(r):
        try:
            rewritten = para.apply(r.text)
        except Exception:  # noqa: BLE001
            rewritten = r.text
        s = det.score(replace(r, text=rewritten))
        with lock:
            cache[f"{r.id}|paraphrase"] = s

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        list(ex.map(para_key, para_todo))
    json.dump(cache, open(cache_path, "w"))

    # llm-judge ASR per attack (threshold 0.5)
    def llm_asr(attack):
        caught = [r for r in sample if (cache.get(f"{r.id}|clean") or 0) >= 0.5]
        if not caught:
            return None, 0
        still = sum(1 for r in caught if (cache.get(f"{r.id}|{attack}") or 0) >= 0.5)
        return 1 - still / len(caught), len(caught)

    # baseline ASR (local, no API)
    def base_asr(name, attack):
        d = get_detector(name)
        rep = run_robustness(d, sample, get_attack(attack))
        return rep.attack_success_rate, rep.n_detected_clean

    attacks = CHAR_ATTACKS + ["paraphrase"]
    print("\n# Attack success rate (higher = more brittle). ASR of caught fraud lures.\n")
    print("| Attack | heuristic-v0 | tfidf-logreg | llm-judge |")
    print("|---|---|---|---|")
    for a in attacks:
        la, ln = llm_asr(a)
        if a == "paraphrase":
            print(f"| {a} | (n/a) | (n/a) | {la:.2f} (of {ln}) |")
        else:
            ha, _ = base_asr("heuristic-v0", a)
            ta, _ = base_asr("tfidf-logreg", a)
            print(f"| {a} | {ha:.2f} | {ta:.2f} | {la:.2f} |")


if __name__ == "__main__":
    main()
