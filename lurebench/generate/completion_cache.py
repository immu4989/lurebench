"""Memoise provider completions to disk.

Detector scores are cached, which makes re-running an evaluation free. Attacks
were not: an adaptive attack issues a generation per round per lure, so
regenerating its table re-paid for every rewrite even though nothing had changed.

Caching preserves one observed completion, not the provider's determinism.
Even temperature zero does not guarantee identical uncached outputs. Do not
reuse a cache to claim independent stochastic replicates: it replays one draw.
Keep cache paths separate for different provider configurations and experiments.

    complete = cached_complete_fn(
        provider_complete_fn("openrouter", "deepseek/deepseek-v4-flash"),
        "cache/attacker.json", model="deepseek/deepseek-v4-flash",
    )
    complete("rewrite this", "some lure")   # calls the API
    complete("rewrite this", "some lure")   # free, byte-identical
"""

from __future__ import annotations

import hashlib
from typing import Callable, Optional

from ..diskcache import JsonDiskCache


def _key(model: str, system: str, user: str) -> str:
    # The model id is part of the key: the same prompt to a different model is a
    # different completion, and these caches get reused across panels.
    if any(not isinstance(value, str) or "\x00" in value for value in (model, system, user)):
        raise ValueError("completion cache inputs must be strings without NUL separators")
    h = hashlib.sha1("\x00".join((model, system, user)).encode("utf-8"))
    return h.hexdigest()


class CompletionCache:
    """Wrap a ``complete(system, user) -> text`` callable with an on-disk cache."""

    def __init__(self, path: Optional[str] = None, flush_every: int = 25) -> None:
        self.store = JsonDiskCache(path, flush_every=flush_every)

    @property
    def hits(self) -> int:
        return self.store.hits

    @property
    def misses(self) -> int:
        return self.store.misses

    def wrap(self, complete_fn: Callable[[str, str], str], model: str = "") -> Callable:
        def complete(system: str, user: str) -> str:
            key = _key(model, system, user)

            def compute():
                text = complete_fn(system, user)
                if not isinstance(text, str):
                    raise ValueError("completion provider must return a string")
                return text

            value = self.store.get_or_compute(key, compute, cache_if=bool)
            if not isinstance(value, str):
                raise ValueError("cached completion must be a string; provider was not retried")
            return value

        return complete

    def flush(self) -> None:
        self.store.flush()


def cached_complete_fn(complete_fn: Callable[[str, str], str], path: Optional[str],
                       model: str = "") -> Callable[[str, str], str]:
    """Return a callable that persists each successful nonempty completion.

    Use CompletionCache directly for batched flushes, and explicitly flush that
    object before ending a run. A cache remains a local replay, not new evidence.
    """
    return CompletionCache(path, flush_every=1).wrap(complete_fn, model=model)
