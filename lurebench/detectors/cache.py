"""On-disk score caching for expensive detectors.

The cheap detectors score a 2,000-record corpus in under a second. An LLM-backed
detector needs one API call per record, so the same sweep is thousands of calls:
slow enough that a crash halfway through is painful, and metered enough that
re-running an evaluation to regenerate a table should not cost money twice.

:class:`CachedDetector` wraps any detector and memoises ``score`` to a JSON file
keyed by detector name plus a hash of the record text, so a rerun is free and a
half-finished sweep resumes where it stopped.

:func:`prewarm` fills that cache concurrently. The evaluation harness scores
records one at a time by design (it is simple, ordered, and easy to reason
about), which is fine at cache speed but far too slow against a live API. So the
pattern for an expensive detector is: pre-warm concurrently, then run the normal
sequential harness, which now hits the cache on every record.

    det = CachedDetector(get_detector("llm-judge", engine="openrouter",
                                      model="openai/gpt-5-nano"), "cache.json")
    prewarm(det, dataset, workers=12)   # concurrent, the slow part
    report = run(det, dataset)          # sequential, instant

A cached ``None`` (the detector abstained) is a real result and is replayed as an
abstention rather than retried.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import threading
from typing import Iterable, List, Optional

from ..schema import Lure
from .base import Detector

_MISS = object()


def _key(name: str, text: str) -> str:
    return f"{name}\n{hashlib.sha1(text.encode('utf-8')).hexdigest()}"


class CachedDetector(Detector):
    """Memoise a detector's scores to a JSON file on disk.

    Args:
        inner: the detector to wrap; its ``name`` and ``task`` are adopted so the
            wrapper is transparent to the harness and the leaderboard.
        path: cache file. Created on first :meth:`flush`; missing or corrupt files
            start an empty cache rather than raising.
        flush_every: write to disk after this many new scores (0 disables
            autoflush, in which case call :meth:`flush` yourself).
    """

    def __init__(self, inner: Detector, path: Optional[str] = None,
                 flush_every: int = 100) -> None:
        self.inner = inner
        self.path = path
        self.flush_every = flush_every
        self.name = getattr(inner, "name", "detector")
        self.task = getattr(inner, "task", "fraud")
        self._lock = threading.Lock()
        self._pending = 0
        self.hits = 0
        self.misses = 0
        self._cache = self._load()

    def _load(self) -> dict:
        if not self.path or not os.path.exists(self.path):
            return {}
        try:
            with open(self.path, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError):
            # A truncated cache from an interrupted run is not fatal; start clean.
            return {}

    def flush(self) -> None:
        """Persist the cache. No-op when constructed without a path."""
        if not self.path:
            return
        with self._lock:
            snapshot = dict(self._cache)
            self._pending = 0
        parent = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(parent, exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(snapshot, fh)
        os.replace(tmp, self.path)  # atomic, so a crash can't corrupt the cache

    def score(self, lure: Lure) -> Optional[float]:
        k = _key(self.name, lure.text)
        with self._lock:
            cached = self._cache.get(k, _MISS)
        if cached is not _MISS:
            with self._lock:
                self.hits += 1
            return cached  # may legitimately be None (a cached abstention)

        value = self.inner.score(lure)
        value = None if value is None else float(value)
        with self._lock:
            self._cache[k] = value
            self.misses += 1
            self._pending += 1
            due = self.flush_every and self._pending >= self.flush_every
        if due:
            self.flush()
        return value


def prewarm(detector: CachedDetector, dataset: Iterable[Lure], workers: int = 8,
            progress_every: int = 200) -> int:
    """Concurrently fill ``detector``'s cache for every record. Returns new scores.

    Records already in the cache are skipped, so this is resumable. Failures are
    left uncached (the detector itself decides whether to abstain), so a rerun
    retries only what genuinely failed.
    """
    records: List[Lure] = list(dataset)
    todo = [r for r in records if _key(detector.name, r.text) not in detector._cache]
    if not todo:
        return 0

    done = [0]
    lock = threading.Lock()

    def _one(rec: Lure) -> None:
        detector.score(rec)
        with lock:
            done[0] += 1
            if progress_every and done[0] % progress_every == 0:
                print(f"  {detector.name}: {done[0]}/{len(todo)}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(_one, todo))
    detector.flush()
    return len(todo)
