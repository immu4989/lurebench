"""Optional provenance adapter safety without importing or loading a real model."""

import math
import sys
from types import SimpleNamespace

import pytest

from lurebench.detectors.binoculars import BinocularsDetector
from lurebench.detectors.cache import CachedDetector
from lurebench.schema import Lure


def lure(text="synthetic provenance sample"):
    return Lure("synthetic", text, 1, "ai", "phishing")


def backend(raw=.9, tokens=4, limit=512):
    calls = []

    def tokenize(text, **kwargs):
        calls.append(("tokenize", kwargs))
        return {"input_ids": list(range(tokens))}

    def compute(text):
        calls.append(("compute", text))
        return raw

    return SimpleNamespace(tokenizer=tokenize, compute_score=compute, max_token_observed=limit), calls


def test_default_constructor_does_not_import_or_construct_upstream(monkeypatch):
    calls = []
    monkeypatch.setitem(sys.modules, "binoculars", SimpleNamespace(Binoculars=lambda: calls.append(True)))
    with pytest.raises(ValueError, match="allow_unsafe_upstream"):
        BinocularsDetector()
    assert calls == []


def test_explicit_upstream_opt_in_is_required_and_supported(monkeypatch):
    model, _ = backend()
    called = []
    monkeypatch.setitem(sys.modules, "binoculars", SimpleNamespace(
        Binoculars=lambda: called.append(True) or model))
    detector = BinocularsDetector(allow_unsafe_upstream=True)
    assert called == [True]
    assert detector.score(lure()) == pytest.approx((.95 - .9) / .30 + .5)


@pytest.mark.parametrize("raw", [math.nan, math.inf, -math.inf, None, True, False,
                              "0.9", [], [.9], 0., -1.])
def test_invalid_raw_scores_never_become_a_probability(raw):
    model, _ = backend(raw=raw)
    detector = BinocularsDetector(backend=model)
    with pytest.raises(ValueError):
        detector.score(lure())


@pytest.mark.parametrize("raw", [.01, .8, .85, .9, .95, 1., 1.1, 10., 1e308])
def test_valid_legacy_proxy_values_are_preserved(raw):
    model, _ = backend(raw=raw)
    result = BinocularsDetector(backend=model).score(lure())
    assert result == max(0., min(1., (.95 - raw) / .30 + .5))


def test_overlong_tokens_abstain_without_backend_inference():
    model, calls = backend(tokens=513)
    assert BinocularsDetector(backend=model).score(lure()) is None
    assert calls == [("tokenize", {"truncation": False, "return_token_type_ids": False,
                                 "return_attention_mask": False})]


def test_exact_token_limit_is_scored():
    model, calls = backend(tokens=512)
    assert BinocularsDetector(backend=model).score(lure()) is not None
    assert [item[0] for item in calls] == ["tokenize", "compute"]


@pytest.mark.parametrize("text", ["", "x" * 100_001], ids=["empty", "too_long"])
def test_text_bounds_abstain_before_tokenization(text):
    model, calls = backend()
    assert BinocularsDetector(backend=model).score(lure(text)) is None
    assert calls == []


def test_persistent_cache_requires_reviewed_context_and_rejects_old_entries(tmp_path):
    model, calls = backend()
    with pytest.raises(ValueError, match="cache_context"):
        CachedDetector(BinocularsDetector(backend=model), str(tmp_path / "cache.json"))
    old = CachedDetector(SimpleNamespace(name="binoculars", score=lambda r: .5),
                         str(tmp_path / "legacy.json"), flush_every=1)
    old.score(lure())
    with pytest.raises(ValueError, match="legacy"):
        CachedDetector(BinocularsDetector(backend=model, cache_context="a" * 64),
                       str(tmp_path / "legacy.json"))
    assert calls == []


def test_cache_context_and_token_budget_separate_results():
    first, _ = backend()
    second, _ = backend(limit=256)
    detectors = [BinocularsDetector(backend=first, cache_context="a" * 64),
                 BinocularsDetector(backend=first, cache_context="b" * 64),
                 BinocularsDetector(backend=second, cache_context="a" * 64)]
    assert len({detector.cache_namespace for detector in detectors}) == 3


def test_backend_limit_mutation_cannot_silently_reuse_the_bound_contract():
    model, calls = backend()
    detector = BinocularsDetector(backend=model)
    model.max_token_observed = 2
    with pytest.raises(ValueError, match="changed"):
        detector.score(lure())
    assert calls == []


@pytest.mark.parametrize("options", [
    {"allow_unsafe_upstream": 1}, {"allow_unsafe_upstream": "true"},
    {"cache_context": "not-a-pin"}, {"cache_context": "A" * 64},
    {"cache_context": True},
])
def test_invalid_configuration_fails_before_import(monkeypatch, options):
    import builtins

    original = builtins.__import__

    def guarded(name, *args, **kwargs):
        if name.split(".")[0] in {"binoculars", "torch", "transformers"}:
            pytest.fail("optional model import happened before validation")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded)
    with pytest.raises(ValueError):
        BinocularsDetector(**options)


def test_injected_backend_does_not_import_optional_stack(monkeypatch):
    import builtins

    original = builtins.__import__

    def guarded(name, *args, **kwargs):
        if name.split(".")[0] in {"binoculars", "torch", "transformers"}:
            pytest.fail("injected backend should not import upstream")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded)
    model, _ = backend()
    assert BinocularsDetector(backend=model).score(lure()) is not None
    with pytest.raises(ValueError, match="allow_unsafe_upstream"):
        BinocularsDetector()


@pytest.mark.parametrize("limit", [True, None, 0, -1, 128_001, 512.0, "512"])
def test_bad_backend_limits_reject_before_scoring(limit):
    model, calls = backend(limit=limit)
    with pytest.raises(ValueError):
        BinocularsDetector(backend=model)
    assert calls == []


@pytest.mark.parametrize("tokens", [0, 1])
def test_too_few_tokens_abstain_without_inference(tokens):
    model, calls = backend(tokens=tokens)
    assert BinocularsDetector(backend=model).score(lure()) is None
    assert len(calls) == 1


@pytest.mark.parametrize("encoded", [None, {}, {"input_ids": [[1, 2]]}, {"input_ids": "12"},
    {"input_ids": [True, 2]}, {"input_ids": [-1, 2]}, {"input_ids": [1., 2.]}])
def test_bad_tokenizer_outputs_fail_before_inference(encoded):
    model, calls = backend()
    model.tokenizer = lambda *a, **kw: encoded
    with pytest.raises(ValueError, match="token IDs"):
        BinocularsDetector(backend=model).score(lure())
    assert calls == []


def test_method_tokenizer_is_stable_across_attribute_access():
    class Reviewed:
        max_token_observed = 512

        def tokenizer(self, *args, **kwargs):
            return {"input_ids": [1, 2, 3]}

        def compute_score(self, text):
            return .9

    assert BinocularsDetector(backend=Reviewed()).score(lure()) is not None


def test_tokenizer_replacement_is_detected_before_inference():
    model, calls = backend()
    detector = BinocularsDetector(backend=model)
    model.tokenizer = lambda *a, **kw: {"input_ids": [1, 2]}
    with pytest.raises(ValueError, match="changed"):
        detector.score(lure())
    assert calls == []


def test_explicit_loading_and_injected_backend_are_mutually_exclusive():
    model, calls = backend()
    with pytest.raises(ValueError):
        BinocularsDetector(backend=model, allow_unsafe_upstream=True)
    assert calls == []


def test_new_cache_replays_without_inference_and_records_abstention(tmp_path):
    model, calls = backend(tokens=513)
    detector = BinocularsDetector(backend=model, cache_context="a" * 64)
    cached = CachedDetector(detector, str(tmp_path / "v2.json"), flush_every=1)
    assert cached.score(lure()) is None
    assert len(calls) == 1
    replayed = CachedDetector(detector, str(tmp_path / "v2.json"), cache_only=True)
    assert replayed.score(lure()) is None
    assert len(calls) == 1


def test_model_failures_propagate_without_a_false_score():
    model, _ = backend()

    def fail(text):
        raise RuntimeError("synthetic inference failure")

    model.compute_score = fail
    with pytest.raises(RuntimeError, match="synthetic inference failure"):
        BinocularsDetector(backend=model).score(lure())


def test_invalid_raw_score_is_not_cached(tmp_path):
    model, _ = backend(raw=math.nan)
    cached = CachedDetector(BinocularsDetector(backend=model, cache_context="a" * 64),
                            str(tmp_path / "invalid.json"), flush_every=1)
    with pytest.raises(ValueError):
        cached.score(lure())
    assert cached.store.snapshot() == {}
    assert not (tmp_path / "invalid.json").exists()
