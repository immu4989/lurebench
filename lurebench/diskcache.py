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
import threading
from typing import Any

_MISS = object()


class JsonDiskCache:
    """Dict-like cache persisted to a JSON file.

    Args:
        path: file to persist to. ``None`` keeps the cache in memory only.
        flush_every: write after this many new entries (0 disables autoflush).
    """

    def __init__(self, path: str | None = None, flush_every: int = 100) -> None:
        self.path = path
        self.flush_every = flush_every
        self.hits = 0
        self.misses = 0
        self._lock = threading.Lock()
        self._pending = 0
        self._data = self._load()

    def _load(self) -> dict:
        if not self.path or not os.path.exists(self.path):
            return {}
        try:
            with open(self.path, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError):
            # A truncated file from an interrupted run is not fatal; start clean.
            return {}

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
        with self._lock:
            self._data[key] = value
            self._pending += 1
            due = self.flush_every and self._pending >= self.flush_every
        if due:
            self.flush()

    def flush(self) -> None:
        """Persist atomically. No-op without a path."""
        if not self.path:
            return
        with self._lock:
            snapshot = dict(self._data)
            self._pending = 0
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        # Per-writer temp name: a shared one races when several threads flush at once.
        tmp = f"{self.path}.{os.getpid()}.{threading.get_ident()}.tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(snapshot, fh)
            os.replace(tmp, self.path)
        except Exception:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
