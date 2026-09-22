"""A small thread-safe JSON cache on disk.

Shared by the two things in LureBench that are slow and metered: detector scores
(:mod:`lurebench.detectors.cache`) and provider completions
(:mod:`lurebench.generate.completion_cache`). Both want the same behaviour —
memoise to a file, survive an interrupted run, never corrupt the file — so the
mechanics live here once rather than being written twice and drifting.

The write path is the fiddly part. Flushes come from several worker threads at
once, so each writer stages to its own temp file before an atomic replace. An
earlier version shared a single ``<path>.tmp`` between writers, and concurrent
flushes raced: the first replace consumed the file and the second died with
``FileNotFoundError``.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from concurrent.futures import Future
from pathlib import Path
from typing import Any, Callable

from .local_io import read_regular_file
from .receipts import loads_strict_json

_MISS = object()
MAX_CACHE_BYTES = 64 * 1024 * 1024


class CacheReadError(ValueError):
    """An existing cache cannot safely be resumed; no fresh paid run is implied."""


class JsonDiskCache:
    """Dict-like cache persisted to a JSON file.

    Args:
        path: file to persist to. ``None`` keeps the cache in memory only.
        flush_every: write after this many new entries (0 disables autoflush).
    """

    def __init__(self, path: str | None = None, flush_every: int = 100) -> None:
        if type(flush_every) is not int or flush_every < 0:
            raise ValueError("cache flush interval must be a nonnegative integer")
        self.path = path
        self.flush_every = flush_every
        self.hits = 0
        self.misses = 0
        self._lock = threading.Lock()
        self._flush_lock = threading.Lock()
        self._inflight: dict[str, Future] = {}
        self._pending = 0
        self._data = self._load()

    def _load(self) -> dict:
        if not self.path:
            return {}
        try:
            Path(self.path).lstat()
        except FileNotFoundError:
            return {}
        try:
            value = loads_strict_json(read_regular_file(
                Path(self.path), maximum=MAX_CACHE_BYTES, label="cache",
            ))
            if not isinstance(value, dict):
                raise ValueError("cache root must be an object")
            return value
        except (OSError, ValueError) as exc:
            raise CacheReadError(
                "existing cache is invalid or unreadable; preserve it and explicitly "
                "restore a valid backup or choose a new cache path before paid work"
            ) from exc

    def __contains__(self, key: str) -> bool:
        with self._lock:
            return key in self._data

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            value = self._data.get(key, _MISS)
            if value is _MISS:
                self.misses += 1
                return default
            self.hits += 1
            return value

    def lookup(self, key: str):
        """Return ``(hit, value)`` so a cached ``None`` is distinguishable from a miss."""
        with self._lock:
            value = self._data.get(key, _MISS)
            if value is _MISS:
                self.misses += 1
                return False, None
            self.hits += 1
            return True, value

    def set(self, key: str, value: Any) -> None:
        if not isinstance(key, str):
            raise ValueError("cache keys must be strings")
        with self._lock:
            self._data[key] = value
            self._pending += 1
            due = self.flush_every and self._pending >= self.flush_every
        if due:
            self.flush()

    def get_or_compute(
        self, key: str, compute: Callable[[], Any], *,
        cache_if: Callable[[Any], bool] = lambda value: True,
    ) -> Any:
        """Coalesce same-key work in this instance, including cached None.

        A failed computation is shared with waiters but is not cached. Different
        keys remain concurrent. This is not a cross-process lock or spend cap.
        """
        if not isinstance(key, str):
            raise ValueError("cache keys must be strings")
        with self._lock:
            value = self._data.get(key, _MISS)
            if value is not _MISS:
                self.hits += 1
                return value
            future = self._inflight.get(key)
            leader = future is None
            if leader:
                future = Future()
                self._inflight[key] = future
                self.misses += 1
            else:
                self.hits += 1
        if not leader:
            return future.result()
        try:
            value = compute()
            if cache_if(value):
                self.set(key, value)
            future.set_result(value)
            return value
        except BaseException as exc:
            future.set_exception(exc)
            raise
        finally:
            with self._lock:
                self._inflight.pop(key, None)

    def flush(self) -> None:
        """Persist atomically. No-op without a path."""
        if not self.path:
            return
        # Serialize snapshot capture AND replacement. A unique temp file alone
        # does not stop an older snapshot from replacing a newer one last.
        with self._flush_lock:
            with self._lock:
                snapshot = dict(self._data)
                pending = self._pending
                self._pending = 0
            temporary = None
            try:
                destination = Path(self.path)
                destination.parent.mkdir(parents=True, exist_ok=True)
                if destination.is_symlink() or destination.parent.is_symlink():
                    raise ValueError("cache destination must not be a symlink")
                with tempfile.NamedTemporaryFile(
                    mode="w", encoding="utf-8", dir=destination.parent,
                    prefix=".lurecache-", suffix=".tmp", delete=False,
                ) as stream:
                    temporary = Path(stream.name)
                    size = 0
                    for chunk in json.JSONEncoder(allow_nan=False).iterencode(snapshot):
                        size += len(chunk.encode("utf-8"))
                        if size > MAX_CACHE_BYTES:
                            raise ValueError("cache exceeds its bounded size")
                        stream.write(chunk)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, destination)
                temporary = None
            except BaseException:
                with self._lock:
                    self._pending += pending
                raise
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)
