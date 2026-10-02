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
import re
import threading
from typing import Iterable, List, Optional

from ..diskcache import CacheOnlyMissError, CacheReadError, JsonDiskCache
from ..probability import validate_score
from ..schema import Lure
from .base import Detector


def _key(name: str, text: str) -> str:
    return f"{name}\n{hashlib.sha1(text.encode('utf-8')).hexdigest()}"


class CachedDetector(Detector):
    """Memoise a detector's scores to a JSON file on disk.

    Args:
        inner: the detector to wrap; its ``name`` and ``task`` are adopted so the
            wrapper is transparent to the harness and the leaderboard.
        path: cache file. Created on first :meth:`flush`; only a missing file
            starts empty. Invalid existing caches fail before provider work.
        flush_every: write to disk after this many new scores (0 disables
            autoflush, in which case call :meth:`flush` yourself).
        cache_only: prohibit writes and scoring callbacks on misses. Does not
            constrain side effects from constructing ``inner`` beforehand.
        max_new_calls: per-instance callback admission limit, including failed
            calls; not a provider request, token, or monetary limit.
    """

    def __init__(self, inner: Detector, path: Optional[str] = None,
                 flush_every: int = 100, *, cache_only: bool = False,
                 max_new_calls: Optional[int] = None) -> None:
        self.inner = inner
        self.path = path
        self.name = getattr(inner, "name", "detector")
        self.task = getattr(inner, "task", "fraud")
        namespace = getattr(inner, "cache_namespace", None)
        if path and hasattr(inner, "cache_namespace") and namespace is None:
            raise ValueError("persistent custom LLM score caching requires an explicit cache_context")
        self.cache_name = self.name if namespace is None else f"{self.name}\ncontext={namespace}"
        self.store = JsonDiskCache(path, flush_every=flush_every,
                                   read_only=cache_only, max_computations=max_new_calls)
        if namespace is not None and any(
            key.startswith(self.name + "\n") and not key.startswith(self.cache_name + "\n")
            for key in self.store._data
        ):
            raise CacheReadError(
                "score cache contains legacy or different detector context; preserve it "
                "and explicitly choose a new cache path before any paid rerun"
            )

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
        key = _key(self.cache_name, lure.text)
        return validate_score(self.store.get_or_compute(
            key, lambda: validate_score(self.inner.score(lure)),
        ))

    def plan(self, dataset: Iterable[Lure]) -> dict:
        """Aggregate replay coverage without detector calls, writes, or counter changes."""
        snapshot = self.store.snapshot()
        keys = [_key(self.cache_name, record.text) for record in dataset]
        unique = set(keys)
        cached = unique.intersection(snapshot)
        abstained = {key for key in cached if validate_score(snapshot[key]) is None}
        return {
            "records": len(keys), "unique_score_keys": len(unique),
            "cached_records": sum(key in cached for key in keys),
            "cached_unique_keys": len(cached), "missing_unique_keys": len(unique - cached),
            "cached_abstained_records": sum(key in abstained for key in keys),
            "replay_complete": unique == cached,
            "limitations": ["cached_scores_are_not_new_independent_observations",
                            "unique_misses_are_not_a_token_or_provider_billing_estimate"],
        }


class _ReplaySource:
    def __init__(self, name, task, namespace):
        self.name, self.task = name, task
        if namespace is not None:
            self.cache_namespace = namespace

    def score(self, lure):
        raise CacheOnlyMissError("replay has no live detector")


class ReplayDetector(CachedDetector):
    """Replay explicit cache identity without constructing any model/provider.

    Identity parameters must come from trusted experiment configuration; a cache
    does not authenticate its producer or prove that the chosen task is correct.
    """

    def __init__(self, path: str, *, name: str, task: str,
                 cache_namespace: Optional[str] = None):
        if (not isinstance(name, str) or not 1 <= len(name) <= 256
                or any(ord(c) < 32 or ord(c) == 127 for c in name)):
            raise ValueError("replay detector name must be a bounded string without controls")
        if task not in ("fraud", "provenance"):
            raise ValueError("replay task must be fraud or provenance")
        if cache_namespace is not None and (
            not isinstance(cache_namespace, str)
            or re.fullmatch(r"[0-9a-f]{64}", cache_namespace) is None
        ):
            raise ValueError("replay cache namespace must be a lowercase SHA-256 identity")
        super().__init__(_ReplaySource(name, task, cache_namespace), path, cache_only=True)


def prewarm(detector: CachedDetector, dataset: Iterable[Lure], workers: int = 8,
            progress_every: int = 200) -> int:
    """Fill the cache concurrently; return the number of scheduled records.

    Records already in the cache are skipped, so this is resumable. Failures are
    left uncached (the detector itself decides whether to abstain), so a rerun
    retries only what genuinely failed.
    Identical keys in concurrent records share one computation, so scheduled
    records are not necessarily the number of underlying provider requests.
    At most ``workers`` tasks are outstanding. Failures stop further admission;
    already-running callbacks are awaited, not cancelled or refunded.
    """
    if type(workers) is not int or not 1 <= workers <= 128:
        raise ValueError("prewarm workers must be an integer from 1 through 128")
    if type(progress_every) is not int or progress_every < 0:
        raise ValueError("prewarm progress interval must be a nonnegative integer")
    records: List[Lure] = list(dataset)
    # Reject invalid existing values before any new, potentially metered work.
    detector.plan(records)
    snapshot = detector.store.snapshot()
    todo = [r for r in records if _key(detector.cache_name, r.text) not in snapshot]
    if not todo:
        return 0

    done = [0]
    lock = threading.Lock()
    stopped = threading.Event()

    def _one(rec: Lure) -> None:
        if stopped.is_set():
            return
        try:
            detector.score(rec)
        except BaseException:
            stopped.set()
            raise
        with lock:
            done[0] += 1
            if progress_every and done[0] % progress_every == 0:
                print(f"  {detector.name}: {done[0]}/{len(todo)}")

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            pending = set()
            remaining = iter(todo)
            exhausted = False
            try:
                while pending or not exhausted:
                    while not exhausted and not stopped.is_set() and len(pending) < workers:
                        try:
                            record = next(remaining)
                        except StopIteration:
                            exhausted = True
                        else:
                            pending.add(ex.submit(_one, record))
                    if not pending:
                        break
                    completed, pending = concurrent.futures.wait(
                        pending, return_when=concurrent.futures.FIRST_COMPLETED,
                    )
                    # Check all completed tasks before admitting replacements.
                    for future in completed:
                        future.result()
            finally:
                stopped.set()
                for future in pending:
                    future.cancel()
    finally:
        detector.flush()
    return len(todo)
