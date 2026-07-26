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
import threading
from typing import Iterable, List, Optional

from ..diskcache import JsonDiskCache
from ..schema import Lure
from .base import Detector


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
        self.name = getattr(inner, "name", "detector")
        self.task = getattr(inner, "task", "fraud")
        self.store = JsonDiskCache(path, flush_every=flush_every)

    # Cache statistics, kept as attributes so callers can read them directly.
    @property
    def hits(self) -> int:
        return self.store.hits

    @property
    def misses(self) -> int:
        return self.store.misses

    @property
    def _cache(self) -> dict:
        """The raw mapping. prewarm() consults it to decide what still needs scoring."""
        return self.store._data

    def flush(self) -> None:
        """Persist the cache. No-op when constructed without a path."""
        self.store.flush()

    def score(self, lure: Lure) -> Optional[float]:
        key = _key(self.name, lure.text)
        hit, cached = self.store.lookup(key)
        if hit:
            return cached  # may legitimately be None (a cached abstention)
        value = self.inner.score(lure)
        value = None if value is None else float(value)
        self.store.set(key, value)
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
