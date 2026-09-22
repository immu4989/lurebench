import json

import pytest

from lurebench.detectors.cache import CachedDetector, _key
from lurebench.detectors.llm import LLMJudgeDetector, LLMProvenanceJudgeDetector
from lurebench.schema import Lure

RECORD = Lure(id="synthetic", text="synthetic", label=1, source="ai", typology="phishing")


@pytest.mark.parametrize("detector", [LLMJudgeDetector, LLMProvenanceJudgeDetector])
def test_all_canonical_integer_scores_and_ascii_whitespace(detector):
    for value in range(101):
        assert detector._parse(str(value)) == value / 100
        assert detector._parse(f" \t{value}\r\n") == value / 100


@pytest.mark.parametrize("response", [
    "-5", "+5", "101", "999", "1000", "00", "01", "0.9", "90%", "score: 90",
    "1. The answer is 90", "90 or 10", "not fraud", "not AI generated", "legitimate",
    "{\"score\":90}", "```90```", "٨٧", "８７", "\u00a090", "90\x00", "9" * 1000,
    None, 90, [], {},
])
@pytest.mark.parametrize("detector", [LLMJudgeDetector, LLMProvenanceJudgeDetector])
def test_noncontract_answers_abstain_instead_of_becoming_guessed_probabilities(detector, response):
    assert detector._parse(response) is None


def test_legacy_score_cache_stops_before_any_provider_call(tmp_path):
    calls = []
    detector = LLMJudgeDetector(complete_fn=lambda *args: calls.append(1), cache_context="fixture-v1")
    path = tmp_path / "legacy.json"
    original = json.dumps({_key(detector.name, RECORD.text): 0.9})
    path.write_text(original)
    with pytest.raises(ValueError, match="legacy or different detector context"):
        CachedDetector(detector, str(path))
    assert calls == []
    assert path.read_text() == original


def test_custom_callable_requires_context_for_persistent_replay(tmp_path):
    detector = LLMJudgeDetector(complete_fn=lambda *args: "50")
    with pytest.raises(ValueError, match="cache_context"):
        CachedDetector(detector, str(tmp_path / "scores.json"))
    assert CachedDetector(detector).score(RECORD) == 0.5


def test_matching_context_replays_and_different_context_refuses(tmp_path):
    path = str(tmp_path / "scores.json")
    first = LLMJudgeDetector(complete_fn=lambda *args: "50", cache_context="fixture-v1")
    assert CachedDetector(first, path, flush_every=1).score(RECORD) == 0.5

    def forbidden(*args):
        raise AssertionError("matching cache must not call provider again")

    same = LLMJudgeDetector(complete_fn=forbidden, cache_context="fixture-v1")
    assert CachedDetector(same, path).score(RECORD) == 0.5
    other = LLMJudgeDetector(complete_fn=forbidden, cache_context="fixture-v2")
    with pytest.raises(ValueError, match="different detector context"):
        CachedDetector(other, path)


def test_namespace_binds_resolved_model_endpoint_prompt_task_and_generation_settings(monkeypatch):
    from lurebench import generate

    class Stub:
        def __init__(self, engine, kwargs):
            self.model = kwargs.get("model", "resolved-default")
            self.endpoint = f"https://{engine}.invalid/chat/completions"

        def complete(self, *args):
            raise AssertionError("no provider work during configuration fingerprinting")

    monkeypatch.setattr(generate, "get_generator", lambda engine, **kwargs: Stub(engine, kwargs))
    baseline = LLMJudgeDetector().cache_namespace
    variants = [
        LLMJudgeDetector(engine="different").cache_namespace,
        LLMJudgeDetector(model="different").cache_namespace,
        LLMJudgeDetector(max_tokens=1024).cache_namespace,
        LLMJudgeDetector(extra_params={"seed": 42}).cache_namespace,
        LLMProvenanceJudgeDetector().cache_namespace,
    ]
    assert all(value != baseline for value in variants)
    monkeypatch.setattr(LLMJudgeDetector, "system_prompt", "new prompt")
    assert LLMJudgeDetector().cache_namespace != baseline
