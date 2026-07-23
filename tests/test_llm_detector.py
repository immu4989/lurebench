"""Tests for the LLM-as-classifier detector (provider stubbed, no network)."""

from __future__ import annotations

from lurebench.detectors.llm import LLMJudgeDetector
from lurebench.schema import Lure


def _lure(text="hi"):
    return Lure(id="x", text=text, label=1, source="ai", typology="phishing")


def test_parses_integer_score():
    det = LLMJudgeDetector(complete_fn=lambda s, u: "87")
    assert det.score(_lure()) == 0.87


def test_clamps_and_maps_range():
    assert LLMJudgeDetector(complete_fn=lambda s, u: "0").score(_lure()) == 0.0
    assert LLMJudgeDetector(complete_fn=lambda s, u: "100").score(_lure()) == 1.0
    # extracts the first integer even with stray text
    assert LLMJudgeDetector(complete_fn=lambda s, u: "score: 42.").score(_lure()) == 0.42


def test_word_fallback_when_no_number():
    assert LLMJudgeDetector(complete_fn=lambda s, u: "this is a phishing scam").score(_lure()) == 0.9
    assert LLMJudgeDetector(complete_fn=lambda s, u: "benign message").score(_lure()) == 0.1


def test_abstains_on_empty_or_unparseable():
    assert LLMJudgeDetector(complete_fn=lambda s, u: "").score(_lure()) is None
    assert LLMJudgeDetector(complete_fn=lambda s, u: "¯\\_(ツ)_/¯").score(_lure()) is None


def test_abstains_on_provider_error():
    def boom(s, u):
        raise RuntimeError("network down")

    assert LLMJudgeDetector(complete_fn=boom).score(_lure()) is None


def test_name_includes_engine_and_registered():
    from lurebench.detectors import available

    det = LLMJudgeDetector(complete_fn=lambda s, u: "50", engine="mistral")
    assert det.name == "llm-judge (mistral)"
    assert det.task == "fraud"
    assert "llm-judge" in available()
