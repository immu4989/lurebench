"""Tests for on-disk memoisation of provider completions."""

from __future__ import annotations

import json

import pytest

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


@pytest.mark.parametrize("value", [None, 3, {}, [], b"bytes"])
def test_nonstring_provider_output_is_not_cached(value):
    inner, calls = _counting(returns=value)
    cache = CompletionCache()
    complete = cache.wrap(inner, model="m")
    with pytest.raises(ValueError, match="string"):
        complete("s", "u")
    assert len(cache.store) == 0


def test_invalid_cached_completion_does_not_trigger_a_paid_retry():
    from lurebench.generate.completion_cache import _key

    inner, calls = _counting()
    cache = CompletionCache()
    cache.store.set(_key("m", "s", "u"), {"invalid": "cached output"})
    with pytest.raises(ValueError, match="provider was not retried"):
        cache.wrap(inner, model="m")("s", "u")
    assert calls["n"] == 0


def test_convenience_wrapper_persists_even_a_single_completion(tmp_path):
    path = str(tmp_path / "one-completion.json")
    first, first_calls = _counting()
    assert cached_complete_fn(first, path, model="m")("s", "u") == "rewritten"
    assert first_calls["n"] == 1
    second, second_calls = _counting()
    assert cached_complete_fn(second, path, model="m")("s", "u") == "rewritten"
    assert second_calls["n"] == 0


@pytest.mark.parametrize("model,system,user", [
    ("m", "a\x00b", "c"), ("m", "a", "b\x00c"), ("m\x00a", "b", "c"),
])
def test_ambiguous_separator_inputs_rejected_before_provider_call(model, system, user):
    inner, calls = _counting()
    complete = CompletionCache().wrap(inner, model=model)
    with pytest.raises(ValueError, match="NUL"):
        complete(system, user)
    assert calls["n"] == 0
