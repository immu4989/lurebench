"""Tests for the adaptive (iterate-until-evasion) paraphrase attack and the
provenance LLM judge. All offline: the provider and detector are stubs."""

from __future__ import annotations

import pytest

from lurebench.attacks.llm import AdaptiveParaphraseAttack
from lurebench.detectors.llm import LLMProvenanceJudgeDetector
from lurebench.probability import DetectorAbstainedError

LURE = "Verify your account within 24 hours or it will be suspended."


def _complete_returning(*texts):
    """Stub generator that returns the given rewrites in order."""
    seq = list(texts)

    def complete(system, user):
        return seq.pop(0) if seq else ""

    return complete


def test_stops_at_the_first_evasion_and_reports_attempts():
    # Clean 0.9 (flagged), rewrite 1 still 0.8, rewrite 2 drops to 0.2 -> evades on 2.
    scores = {LURE: 0.9, "rewrite one": 0.8, "rewrite two": 0.2}
    atk = AdaptiveParaphraseAttack(
        _complete_returning("rewrite one", "rewrite two", "rewrite three"),
        lambda t: scores.get(t, 0.9), threshold=0.5, max_rounds=5,
    )
    r = atk.run(LURE)
    assert r.evaded is True
    assert r.attempts_to_evade == 2
    assert r.rounds == 2                 # stopped early, did not spend the budget
    assert r.text == "rewrite two"
    assert r.scores == [0.9, 0.8, 0.2]


def test_budget_exhausted_returns_the_best_attempt():
    scores = {LURE: 0.95, "a": 0.9, "b": 0.7, "c": 0.8}
    atk = AdaptiveParaphraseAttack(
        _complete_returning("a", "b", "c"),
        lambda t: scores.get(t, 0.95), threshold=0.5, max_rounds=3,
    )
    r = atk.run(LURE)
    assert r.evaded is False
    assert r.attempts_to_evade is None
    assert r.rounds == 3
    assert r.text == "b"                 # lowest-scoring attempt, not merely the last


def test_never_flagged_means_nothing_to_evade():
    atk = AdaptiveParaphraseAttack(
        _complete_returning("unused"), lambda t: 0.1, threshold=0.5, max_rounds=5
    )
    r = atk.run(LURE)
    assert r.rounds == 0 and r.evaded is False
    assert r.text == LURE                # untouched; no calls spent


def test_empty_generation_stops_the_loop():
    atk = AdaptiveParaphraseAttack(
        _complete_returning(""), lambda t: 0.9, threshold=0.5, max_rounds=5
    )
    with pytest.raises(ValueError, match="generation unavailable"):
        atk.run(LURE)


def test_clean_abstention_stops_before_any_generation():
    atk = AdaptiveParaphraseAttack(
        lambda *a: pytest.fail("paid generation attempted"), lambda t: None,
        threshold=0.5, max_rounds=2,
    )
    with pytest.raises(DetectorAbstainedError):
        atk.run(LURE)


@pytest.mark.parametrize("bad", [None, True, "0.2", float("nan"), float("inf"), -1, 2])
def test_attacked_invalid_score_never_becomes_resistance_or_evasion(bad):
    calls = []

    def complete(*args):
        calls.append(1)
        return "candidate"

    atk = AdaptiveParaphraseAttack(complete, lambda t: .9 if t == LURE else bad)
    with pytest.raises(ValueError):
        atk.run(LURE)
    assert len(calls) == 1


@pytest.mark.parametrize("budget", [0, -1, True, 2.0, 1001])
def test_invalid_round_budget_rejected_before_work(budget):
    with pytest.raises(ValueError, match="max_rounds"):
        AdaptiveParaphraseAttack(lambda *a: "", lambda t: .9, max_rounds=budget)


def test_apply_returns_the_best_text_for_the_attack_interface():
    scores = {LURE: 0.9, "quiet version": 0.1}
    atk = AdaptiveParaphraseAttack(
        _complete_returning("quiet version"), lambda t: scores.get(t, 0.9), max_rounds=2
    )
    assert atk.apply(LURE) == "quiet version"


def test_provenance_judge_asks_about_authorship_not_fraud():
    det = LLMProvenanceJudgeDetector.__new__(LLMProvenanceJudgeDetector)
    assert det.task == "provenance"
    prompt = LLMProvenanceJudgeDetector.system_prompt
    assert "WRITTEN BY AN AI" in prompt
    # The corpus is all fraud, so scamminess must be explicitly ruled out as a proxy,
    # and the uniform defang placeholders must be ruled out as a provenance signal.
    assert "must not affect" in prompt
    assert "<<link>>" in prompt


def test_provenance_parse_requires_the_requested_integer_contract():
    p = LLMProvenanceJudgeDetector._parse
    assert p("87") == 0.87
    assert p("clearly written by an AI model") is None
    assert p("this reads like a human wrote it") is None
    assert p("") is None


def test_attack_provider_uses_zero_temperature_by_default(monkeypatch):
    # This reduces variability; it does not prove provider determinism.
    from lurebench.attacks.llm import provider_complete_fn

    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test")
    seen = {}

    from lurebench.generate import openai_compat

    real_init = openai_compat.OpenAICompatibleGenerator.__init__

    def spy(self, *a, **kw):
        real_init(self, *a, **kw)
        seen["temperature"] = self.temperature

    monkeypatch.setattr(openai_compat.OpenAICompatibleGenerator, "__init__", spy)
    provider_complete_fn("openrouter", "openai/gpt-5-nano")
    assert seen["temperature"] == 0.0

    provider_complete_fn("openrouter", "openai/gpt-5-nano", temperature=0.9)
    assert seen["temperature"] == 0.9  # still opt-in-able for multi-sample attacks


def test_generation_still_samples_for_variety(monkeypatch):
    # The corpus generator deliberately keeps a non-zero default; pinning the attack
    # path must not have changed it.
    from lurebench.generate import get_generator

    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test")
    assert get_generator("openrouter", model="m").temperature == 1.0
