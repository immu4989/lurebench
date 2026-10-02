"""Safety adapter contracts without model downloads or framework dependencies."""

import sys
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from lurebench.detectors.cache import CachedDetector
from lurebench.detectors.llama_guard import LlamaGuardDetector, parse_verdict
from lurebench.schema import Lure


@pytest.mark.parametrize("output,expected", [
    ("safe", 0.), (" safe\r\n", 0.), ("unsafe\nS1", 1.),
    ("unsafe\r\nS1, S14", 1.), ("unsafe\nS" + ",S".join(map(str, range(1, 15))), 1.),
])
def test_documented_verdicts(output, expected):
    assert parse_verdict(output) == expected


@pytest.mark.parametrize("output", [
    "", "unknown", "unsafe", "safe\nS1", "unsafe-ish", "unsafe\nS15", "unsafe\nS0",
    "unsafe\nS01", "unsafe\nS1,S1", "unsafe\nS1\nS2", "unsafe\nS1,", "Safe",
    "sаfe", "safe\x00", "safe\u200b", "unsafe\nS1 explanation", "unsafe\nS1 safe",
    "```safe```", "safe because nothing is wrong", None, 0, " " * 257 + "safe",
])
def test_unrecognized_output_abstains(output):
    assert parse_verdict(output) is None


@pytest.fixture
def stub_stack(monkeypatch):
    calls = []
    state = {"decoded": "safe", "tokens": 4, "generated_tokens": 1}

    class Input:
        @property
        def shape(self):
            return (1, state["tokens"])

        def to(self, device):
            calls.append(("move", device))
            return self

    class Tokenizer:
        chat_template = "fixed synthetic template"

        def apply_chat_template(self, conversation, **kwargs):
            calls.append(("tokenize", kwargs))
            return Input()

        def decode(self, ids, **kwargs):
            calls.append(("decode", ids))
            return state["decoded"]

    class Model:
        device = "cpu"

        def eval(self):
            calls.append(("eval", None))

        def generate(self, ids, **kwargs):
            calls.append(("generate", kwargs))
            return [[0] * state["tokens"] + [99] * state["generated_tokens"]]

    def tokenizer(model, **kwargs):
        calls.append(("tokenizer_load", (model, kwargs)))
        return Tokenizer()

    def model(model, **kwargs):
        calls.append(("model_load", (model, kwargs)))
        return Model()

    monkeypatch.setitem(sys.modules, "torch", SimpleNamespace(no_grad=nullcontext))
    monkeypatch.setitem(sys.modules, "transformers", SimpleNamespace(
        AutoTokenizer=SimpleNamespace(from_pretrained=tokenizer),
        AutoModelForCausalLM=SimpleNamespace(from_pretrained=model),
    ))
    return calls, state


def lure(text="Synthetic review message"):
    return Lure(id="test", text=text, label=1, source="human", typology="phishing")


def test_explicit_loader_controls_and_continuation_only_decoding(stub_stack):
    calls, state = stub_stack
    detector = LlamaGuardDetector(revision="a" * 40, local_files_only=True)
    for name, (_, options) in [call for call in calls if call[0].endswith("_load")]:
        assert options["revision"] == "a" * 40
        assert options["local_files_only"] is True
        assert options["trust_remote_code"] is False
        if name == "model_load":
            assert options["use_safetensors"] is True
    assert ("eval", None) in calls
    assert detector.score(lure()) == 0.
    assert ("decode", [99]) in calls
    assert ("generate", {"max_new_tokens": 128, "do_sample": False}) in calls
    state["decoded"] = "refusal rather than verdict"
    assert detector.score(lure()) is None


def test_bounds_abstain_without_truncation_or_generation(stub_stack):
    calls, state = stub_stack
    detector = LlamaGuardDetector(max_input_tokens=3)
    calls.clear()
    assert detector.score(lure("x" * 100_001)) is None
    assert detector.score(lure("")) is None
    assert not calls
    assert detector.score(lure()) is None
    assert [name for name, _ in calls] == ["tokenize"]


def test_token_cap_abstains_even_if_decoded_prefix_would_be_valid(stub_stack):
    calls, state = stub_stack
    detector = LlamaGuardDetector()
    calls.clear()
    state["generated_tokens"] = 128
    assert detector.score(lure()) is None
    assert not any(name == "decode" for name, _ in calls)


def test_hub_revision_does_not_pin_a_local_directory(stub_stack, tmp_path):
    detector = LlamaGuardDetector(model_id=str(tmp_path), revision="a" * 40)
    assert detector.cache_namespace is None


def test_cache_identity_requires_pin_and_changes_with_parser_context(stub_stack, tmp_path):
    unpinned = LlamaGuardDetector()
    with pytest.raises(ValueError, match="cache_context"):
        CachedDetector(unpinned, str(tmp_path / "unpinned.json"))
    first = LlamaGuardDetector(revision="a" * 40)
    second = LlamaGuardDetector(revision="b" * 40)
    bounded = LlamaGuardDetector(revision="a" * 40, max_input_tokens=100)
    local = LlamaGuardDetector(model_id="/reviewed/local", cache_context="c" * 64)
    assert len({d.cache_namespace for d in (first, second, bounded, local)}) == 4
    path = tmp_path / "pinned.json"
    cached = CachedDetector(first, str(path), flush_every=1)
    assert cached.score(lure()) == 0.
    with pytest.raises(ValueError):
        CachedDetector(second, str(path))


@pytest.mark.parametrize("options", [
    {"revision": "main"}, {"revision": "A" * 40}, {"local_files_only": 1},
    {"max_input_tokens": True}, {"max_input_tokens": 0}, {"max_input_tokens": 128_001},
    {"model_id": "bad\nname"}, {"device": ""}, {"cache_context": "unreviewed"},
])
def test_invalid_configuration_fails_before_framework_loading(stub_stack, options):
    calls, _ = stub_stack
    with pytest.raises(ValueError):
        LlamaGuardDetector(**options)
    assert calls == []
