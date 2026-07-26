"""Memoise provider completions to disk.

Detector scores are cached, which makes re-running an evaluation free. Attacks
were not: an adaptive attack issues a generation per round per lure, so
regenerating its table re-paid for every rewrite even though nothing had changed.

Caching a completion is only sound if the same input reliably produces the same
output, so this is meant for the attack path, which pins ``temperature=0`` for
exactly that reason. Do not wrap a sampling generator with it: you would cache one
draw and then replay it forever, quietly turning a distribution into a constant.

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
            hit, value = self.store.lookup(key)
            if hit:
                return value
            text = complete_fn(system, user)
            # Only cache a real completion. An empty string means the provider failed
            # or filtered the request, and caching that would make one bad call
            # permanent.
            if text:
                self.store.set(key, text)
            return text

        return complete

    def flush(self) -> None:
        self.store.flush()


def cached_complete_fn(complete_fn: Callable[[str, str], str], path: Optional[str],
                       model: str = "") -> Callable[[str, str], str]:
    """Convenience wrapper returning a cached ``complete`` callable."""
    return CompletionCache(path).wrap(complete_fn, model=model)
