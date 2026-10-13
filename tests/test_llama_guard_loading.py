"""No implicit framework import, download, or loading through the safety baseline."""

import builtins
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from lurebench.detectors.cache import CachedDetector
from lurebench.detectors.llama_guard import LlamaGuardDetector
from lurebench.schema import Lure


@pytest.fixture
def forbid_framework_imports(monkeypatch):
    original = builtins.__import__

    def guarded(name, *args, **kwargs):
        if name.split(".")[0] in {"torch", "transformers", "accelerate"}:
            pytest.fail("unapproved framework import")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded)


def backend():
    class Input:
        shape = (1, 3)

        def to(self, device):
            return self

    return SimpleNamespace(
        tokenizer=SimpleNamespace(chat_template="synthetic reviewed template",
            apply_chat_template=lambda *a, **kw: Input(), decode=lambda *a, **kw: "safe"),
        model=SimpleNamespace(device="cpu", eval=lambda: None,
                              generate=lambda *a, **kw: [[1, 2, 3, 4]]),
        inference_context=nullcontext,
    )


@pytest.mark.parametrize("options", [{}, {"revision": "a" * 40}, {"local_files_only": True}])
def test_loading_disabled_even_for_pin_or_offline_mode(forbid_framework_imports, options):
    with pytest.raises(ValueError, match="allow_unsafe_upstream"):
        LlamaGuardDetector(**options)


@pytest.mark.parametrize("value", [None, 0, 1, "true"])
def test_opt_in_is_strict_boolean(forbid_framework_imports, value):
    with pytest.raises(ValueError, match="boolean"):
        LlamaGuardDetector(allow_unsafe_upstream=value)


def test_backend_and_loading_are_mutually_exclusive(forbid_framework_imports):
    with pytest.raises(ValueError, match="not both"):
        LlamaGuardDetector(backend=backend(), allow_unsafe_upstream=True)


def test_reviewed_backend_scores_without_frameworks(forbid_framework_imports):
    detector = LlamaGuardDetector(backend=backend(), cache_context="a" * 64)
    assert detector.score(Lure("a", "Synthetic notes", 0, "human", "benign")) == 0.


def test_custom_backend_revision_is_not_cache_authority(forbid_framework_imports, tmp_path):
    detector = LlamaGuardDetector(backend=backend(), revision="a" * 40)
    assert detector.cache_namespace is None
    with pytest.raises(ValueError, match="cache_context"):
        CachedDetector(detector, str(tmp_path / "cache.json"))


@pytest.mark.parametrize("part,field", [("model", "generate"), ("model", "eval"),
    ("tokenizer", "apply_chat_template"), ("tokenizer", "decode"), (None, "inference_context")])
def test_invalid_backend_does_not_execute_eval(forbid_framework_imports, part, field):
    value = backend()
    setattr(getattr(value, part) if part else value, field, None)
    if field != "eval":
        value.model.eval = lambda: pytest.fail("eval callback executed")
    with pytest.raises(ValueError, match="backend"):
        LlamaGuardDetector(backend=value)


def test_review_context_changes_cache_identity(forbid_framework_imports, tmp_path):
    a = LlamaGuardDetector(backend=backend(), cache_context="a" * 64)
    b = LlamaGuardDetector(backend=backend(), cache_context="b" * 64)
    assert a.cache_namespace != b.cache_namespace
    source = tmp_path / "cache.json"
    cached = CachedDetector(a, str(source), flush_every=1)
    cached.score(Lure("a", "Synthetic notes", 0, "human", "benign"))
    original = source.read_bytes()
    with pytest.raises(ValueError):
        CachedDetector(b, str(source))
    assert source.read_bytes() == original
