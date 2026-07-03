"""Assemble the multi-class ``lurebench-core`` corpus from sourced + generated shards.

Takes any number of JSONL inputs — human-sourced shards (e.g. the phishtext
shard) and approved generated staging files — and:

  1. **gates** each record: sourced records (no ``meta.review``) pass through;
     generated records must be human-``approved``. ``pending`` / ``flagged`` are
     dropped and **counted** (never silently), per the review protocol.
  2. **dedups** across all sources by normalized-text hash.
  3. **splits** into train/test by a stable hash of the record ``id`` — the test
     split is frozen because it keys on the id, so adding a new generator never
     shuffles what was already in test.

This is the last step before ``lurebench publish`` uploads the shards to the Hub.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

from .ingest.base import dedupe
from .schema import Lure, load_jsonl, save_jsonl

TEST_MODULUS = 10  # ~10% held out; frozen because it keys on the stable record id


def assign_test(record_id: str, modulus: int = TEST_MODULUS) -> bool:
    """Deterministic train/test assignment. ``True`` -> test split."""
    digest = int(hashlib.sha1(record_id.encode("utf-8")).hexdigest(), 16)
    return digest % modulus == 0


@dataclass
class CoreBuild:
    train: List[Lure]
    test: List[Lure]
    dropped_pending: int = 0
    dropped_flagged: int = 0
    per_source: Dict[str, int] = field(default_factory=dict)
    n_before_dedup: int = 0
    n_after_dedup: int = 0

    @property
    def n(self) -> int:
        return len(self.train) + len(self.test)


def gate(records: Sequence[Lure]) -> Tuple[List[Lure], int, int]:
    """Keep sourced + approved records; drop (and count) pending/flagged generated ones."""
    kept: List[Lure] = []
    pending = 0
    flagged = 0
    for rec in records:
        review = rec.meta.get("review")
        if review is None or review == "approved":
            kept.append(rec)
        elif review == "flagged":
            flagged += 1
        else:  # "pending" or any non-approved state
            pending += 1
    return kept, pending, flagged


def build_core(source_paths: Sequence[str], test_modulus: int = TEST_MODULUS) -> CoreBuild:
    """Gate, dedup, and split all sources into a :class:`CoreBuild`."""
    kept_all: List[Lure] = []
    per_source: Counter = Counter()
    dropped_pending = 0
    dropped_flagged = 0

    for path in source_paths:
        records = load_jsonl(path)
        kept, pending, flagged = gate(records)
        dropped_pending += pending
        dropped_flagged += flagged
        for rec in kept:
            label = rec.meta.get("source_id") or Path(path).stem
            per_source[label] += 1
        kept_all.extend(kept)

    n_before = len(kept_all)
    deduped = dedupe(kept_all)

    train = [r for r in deduped if not assign_test(r.id, test_modulus)]
    test = [r for r in deduped if assign_test(r.id, test_modulus)]

    return CoreBuild(
        train=train,
        test=test,
        dropped_pending=dropped_pending,
        dropped_flagged=dropped_flagged,
        per_source=dict(per_source),
        n_before_dedup=n_before,
        n_after_dedup=len(deduped),
    )


def write_core(build: CoreBuild, out_dir: str) -> Dict[str, str]:
    """Write ``train.jsonl`` / ``test.jsonl`` under ``out_dir``. Returns split->path."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths = {"train": str(out / "train.jsonl"), "test": str(out / "test.jsonl")}
    save_jsonl(build.train, paths["train"])
    save_jsonl(build.test, paths["test"])
    return paths
