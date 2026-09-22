"""Tests for the adversarial robustness harness."""

from __future__ import annotations

import pytest

from lurebench.attacks.base import Attack
from lurebench.attacks.perturb import HomoglyphAttack
from lurebench.robustness import RobustnessReport, render_markdown, run_robustness
from lurebench.schema import Lure


class _KeywordDetector:
    """A toy detector that fires on the exact token 'verify' — brittle by design."""

    name = "toy-keyword"

    def score(self, lure: Lure):
        return 1.0 if "verify" in lure.text.lower().split() else 0.0


class _NoOpAttack(Attack):
    name = "noop"

    def apply(self, text: str) -> str:
        return text


def _corpus():
    lures = [
        Lure(id=f"f{i}", text="please verify your account", label=1, source="ai",
             typology="phishing") for i in range(6)
    ]
    benign = [
        Lure(id=f"b{i}", text="lunch tomorrow at noon", label=0, source="human",
             typology="benign") for i in range(4)
    ]
    return lures + benign


def test_noop_attack_has_zero_success_rate():
    rep = run_robustness(_KeywordDetector(), _corpus(), _NoOpAttack())
    assert rep.attack_success_rate == 0.0
    assert rep.clean_recall == rep.attacked_recall == 1.0
    assert rep.n_detected_clean == rep.n_detected_after == 6


def test_homoglyph_breaks_the_keyword_detector():
    rep = run_robustness(_KeywordDetector(), _corpus(), HomoglyphAttack())
    # Every caught lure evades once 'verify' is homoglyphed.
    assert rep.attack_success_rate == 1.0
    assert rep.n_detected_clean == 6
    assert rep.n_detected_after == 0
    assert rep.attacked_recall == 0.0


def test_report_fields_and_summary():
    rep = run_robustness(_KeywordDetector(), _corpus(), HomoglyphAttack())
    assert isinstance(rep, RobustnessReport)
    assert rep.detector == "toy-keyword"
    assert rep.attack == "homoglyph"
    assert rep.task == "fraud"
    assert rep.n_positives == 6
    line = rep.summary_line()
    assert "homoglyph" in line and "ASR=" in line
    assert set(rep.as_dict()) >= {"attack_success_rate", "clean_recall", "attacked_recall"}


def test_asr_is_undefined_when_nothing_was_caught():
    class _Blind:
        name = "blind"

        def score(self, lure):
            return 0.0

    rep = run_robustness(_Blind(), _corpus(), HomoglyphAttack())
    assert rep.n_detected_clean == 0
    assert rep.attack_success_rate is None
    assert rep.attack_success_rate_lower is None
    assert rep.attack_success_rate_upper is None
    assert "no eligible" in rep.summary_line()


def test_render_markdown_is_a_table():
    rep = run_robustness(_KeywordDetector(), _corpus(), HomoglyphAttack())
    md = render_markdown([rep], dataset_label="toy")
    assert "| Detector |" in md
    assert "toy-keyword" in md
    assert "homoglyph" in md


def test_abstention_is_unknown_not_successful_evasion():
    class SequenceDetector:
        name = "synthetic-abstaining"

        def __init__(self):
            self.values = iter([None, 0.9, 0.9, 0.9, 0.1, 0.9, None, 0.1, 0.9, 0.1])

        def score(self, lure):
            return next(self.values)

    report = run_robustness(SequenceDetector(), _corpus(), _NoOpAttack())
    assert report.n_abstained_clean == 1
    assert report.n_detected_clean == 4
    assert report.n_abstained_after == 1
    assert report.n_detected_after == 1
    assert report.n_evaded == 2
    assert report.attack_success_rate is None
    assert report.attack_success_rate_lower == 0.5
    assert report.attack_success_rate_upper == 0.75
    assert "inconclusive [0.50, 0.75]" in report.summary_line()
    assert "not confidence intervals" in render_markdown([report], "synthetic")


@pytest.mark.parametrize("value", [float("nan"), True, "0.2", -0.2, 1.2])
def test_invalid_outputs_are_not_counted_as_evasion(value):
    class InvalidAfter:
        def __init__(self):
            self.calls = 0

        def score(self, lure):
            self.calls += 1
            return 0.9 if self.calls <= 6 else value

    with pytest.raises(ValueError):
        run_robustness(InvalidAfter(), _corpus(), _NoOpAttack())


def test_all_attacked_abstentions_produce_full_uncertainty_interval():
    class AbstainsAfter:
        def __init__(self):
            self.calls = 0

        def score(self, lure):
            self.calls += 1
            return 0.9 if self.calls <= 6 else None

    report = run_robustness(AbstainsAfter(), _corpus(), _NoOpAttack())
    assert report.attack_success_rate is None
    assert report.n_evaded == 0
    assert report.n_abstained_after == 6
    assert (report.attack_success_rate_lower, report.attack_success_rate_upper) == (0.0, 1.0)


def test_cached_research_script_preserves_unknown_outcomes_without_provider_calls():
    import runpy
    from pathlib import Path

    script = Path(__file__).parents[1] / "scripts/score_llm_robustness.py"
    summarize = runpy.run_path(str(script))["_cached_asr"]
    sample = _corpus()[:2]
    assert "0 eligible" in summarize(sample, {}, "attack")
    cache = {"f0|clean": 0.9, "f1|clean": 0.9, "f0|attack": 0.1, "f1|attack": None}
    assert "inconclusive [0.50, 1.00]" in summarize(sample, cache, "attack")
    cache["f1|attack"] = 0.9
    assert summarize(sample, cache, "attack").startswith("0.50 ")
    cache["f1|attack"] = True
    with pytest.raises(ValueError):
        summarize(sample, cache, "attack")
