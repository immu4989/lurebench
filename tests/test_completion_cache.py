"""Tests for on-disk memoisation of provider completions."""

from __future__ import annotations

import json

from lurebench.generate.completion_cache import CompletionCache, cached_complete_fn


def _counting(returns="rewritten"):
    """Stub provider that counts calls."""
    calls = {"n": 0}

    def complete(system, user):
        calls["n"] += 1
        return returns

    return complete, calls


def test_identical_prompt_is_served_from_cache(tmp_path):
    inner, calls = _counting()
    complete = CompletionCache(str(tmp_path / "g.json")).wrap(inner, model="m1")
    assert complete("sys", "lure") == "rewritten"
    assert complete("sys", "lure") == "rewritten"
    assert calls["n"] == 1


def test_different_prompt_or_model_is_a_different_entry(tmp_path):
    inner, calls = _counting()
    cache = CompletionCache(str(tmp_path / "g.json"))
    c1 = cache.wrap(inner, model="m1")
    c2 = cache.wrap(inner, model="m2")
    c1("sys", "lure")
    c1("sys", "other lure")     # different user text
    c1("other sys", "lure")     # different system prompt
    c2("sys", "lure")           # same prompt, different model
    assert calls["n"] == 4


def test_empty_completion_is_not_cached(tmp_path):
    # An empty string means the provider failed or filtered the request. Caching it
    # would make one bad call permanent.
    inner, calls = _counting(returns="")
    complete = cached_complete_fn(inner, str(tmp_path / "g.json"), model="m")
    assert complete("sys", "lure") == ""
    assert complete("sys", "lure") == ""
    assert calls["n"] == 2      # retried rather than replaying the failure


def test_cache_persists_across_instances(tmp_path):
    path = str(tmp_path / "g.json")
    inner1, calls1 = _counting()
    CompletionCache(path, flush_every=1).wrap(inner1, model="m")("sys", "lure")

    inner2, calls2 = _counting()
    out = CompletionCache(path).wrap(inner2, model="m")("sys", "lure")
    assert out == "rewritten"
    assert calls2["n"] == 0     # replayed from disk; the API was not called again
    assert len(json.loads(open(path, encoding="utf-8").read())) == 1


def test_in_memory_only_when_no_path_given():
    inner, calls = _counting()
    complete = CompletionCache(None).wrap(inner, model="m")
    complete("sys", "lure")
    complete("sys", "lure")
    assert calls["n"] == 1      # still memoises, just never touches disk
