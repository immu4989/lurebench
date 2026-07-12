"""Tests for the adversarial robustness harness."""

from __future__ import annotations

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


def test_asr_is_zero_when_nothing_was_caught():
    class _Blind:
        name = "blind"

        def score(self, lure):
            return 0.0

    rep = run_robustness(_Blind(), _corpus(), HomoglyphAttack())
    assert rep.n_detected_clean == 0
    assert rep.attack_success_rate == 0.0  # no false brittleness signal from an empty base


def test_render_markdown_is_a_table():
    rep = run_robustness(_KeywordDetector(), _corpus(), HomoglyphAttack())
    md = render_markdown([rep], dataset_label="toy")
    assert "| Detector |" in md
    assert "toy-keyword" in md
    assert "homoglyph" in md
