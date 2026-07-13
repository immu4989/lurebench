"""Tests for cross-lingual detection evaluation."""

from __future__ import annotations

from lurebench.multilingual import (
    cross_lingual_detection,
    render_comparison,
    render_markdown,
    strip_artifacts,
)
from lurebench.schema import Lure


class _EnglishOnlyDetector:
    """Flags a lure only if it contains an English trigger word — a stand-in for the
    English-centric detectors the module is meant to expose."""

    name = "english-only"

    def score(self, lure: Lure):
        return 0.9 if "account" in lure.text.lower() else 0.1


def _records():
    return [
        Lure(id="en1", text="verify your account now", label=1, source="ai",
             typology="phishing", language="en"),
        Lure(id="en2", text="update your account details", label=1, source="ai",
             typology="phishing", language="en"),
        Lure(id="es1", text="verifique su cuenta ahora", label=1, source="ai",
             typology="phishing", language="es"),
        Lure(id="es2", text="actualice los datos de su cuenta", label=1, source="ai",
             typology="phishing", language="es"),
        Lure(id="fr1", text="vérifiez votre compte maintenant", label=1, source="ai",
             typology="phishing", language="fr"),
        # a benign record must be ignored
        Lure(id="b1", text="lunch tomorrow", label=0, source="human",
             typology="benign", language="en"),
    ]


def test_recall_breaks_down_by_language():
    results = cross_lingual_detection(_EnglishOnlyDetector(), _records())
    by = {r.language: r for r in results}
    assert by["en"].recall == 1.0        # both English lures caught
    assert by["es"].recall == 0.0        # Spanish "cuenta" not caught
    assert by["fr"].recall == 0.0
    assert by["en"].n == 2 and by["es"].n == 2 and by["fr"].n == 1


def test_english_sorted_first():
    results = cross_lingual_detection(_EnglishOnlyDetector(), _records())
    assert results[0].language == "en"


def test_benign_records_excluded():
    results = cross_lingual_detection(_EnglishOnlyDetector(), _records())
    # only fraud lures counted: en=2 (not 3 with the benign one)
    assert {r.language: r.n for r in results}["en"] == 2


def test_language_names_resolved():
    results = cross_lingual_detection(_EnglishOnlyDetector(), _records())
    names = {r.language: r.language_name for r in results}
    assert names["es"] == "Spanish" and names["fr"] == "French"


def test_skipped_when_detector_returns_none():
    class _Abstains:
        name = "abstains"

        def score(self, lure):
            return None

    results = cross_lingual_detection(_Abstains(), _records())
    for r in results:
        assert r.n == 0 and r.n_skipped > 0 and r.recall == 0.0


def test_render_markdown_table():
    results = cross_lingual_detection(_EnglishOnlyDetector(), _records())
    md = render_markdown(results, "english-only")
    assert "Cross-lingual detection" in md
    assert "Spanish" in md and "French" in md


def test_strip_artifacts_removes_defang_placeholders():
    out = strip_artifacts("click <<link>> now <<contact>>")
    assert "<<link>>" not in out and "<<contact>>" not in out
    assert out.split() == ["click", "now"]


class _PlaceholderDetector:
    """Fires only on the defang placeholder — a stand-in for a detector whose recall is
    really just 'this text had a URL', which the artifact control must expose."""

    name = "placeholder-only"

    def score(self, lure: Lure):
        return 0.9 if "<<link>>" in lure.text else 0.0


def test_artifact_control_exposes_placeholder_only_detection():
    recs = [
        Lure(id="zh1", text="登录一下才能看 <<link>>", label=1, source="ai",
             typology="phishing", language="zh"),
        Lure(id="zh2", text="请点击 <<link>> 确认", label=1, source="ai",
             typology="phishing", language="zh"),
    ]
    raw = cross_lingual_detection(_PlaceholderDetector(), recs)
    controlled = cross_lingual_detection(_PlaceholderDetector(), recs, control_artifacts=True)
    assert raw[0].recall == 1.0          # looks like perfect detection
    assert controlled[0].recall == 0.0   # ...but it was entirely the placeholder


def test_render_comparison_shows_both_columns():
    recs = [
        Lure(id="zh1", text="foo <<link>>", label=1, source="ai",
             typology="phishing", language="zh"),
    ]
    md = render_comparison(_PlaceholderDetector(), recs, "placeholder-only")
    assert "artifact-controlled" in md
    assert "Chinese" in md
