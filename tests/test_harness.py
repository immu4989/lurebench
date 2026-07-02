"""Smoke and correctness tests for the LureBench core."""

from __future__ import annotations

from pathlib import Path

import pytest

from lurebench import Lure, load_jsonl, run
from lurebench.detectors import HeuristicDetector, available, get_detector
from lurebench.metrics import evaluate, mcc_from_confusion, roc_auc

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples" / "lures.jsonl"


def test_samples_load_and_validate():
    data = load_jsonl(SAMPLES)
    assert len(data) == 16
    assert all(isinstance(r, Lure) for r in data)
    # Class balance sanity: both classes present.
    labels = {r.label for r in data}
    assert labels == {0, 1}


def test_schema_rejects_inconsistent_label():
    with pytest.raises(ValueError):
        Lure(id="x", text="t", label=1, source="human", typology="benign")
    with pytest.raises(ValueError):
        Lure(id="x", text="t", label=0, source="human", typology="phishing")


def test_mcc_perfect_and_inverse():
    assert mcc_from_confusion(tp=5, fp=0, tn=5, fn=0) == pytest.approx(1.0)
    assert mcc_from_confusion(tp=0, fp=5, tn=0, fn=5) == pytest.approx(-1.0)


def test_auc_separable():
    y = [0, 0, 1, 1]
    scores = [0.1, 0.2, 0.8, 0.9]
    assert roc_auc(y, scores) == pytest.approx(1.0)


def test_auc_single_class_is_none():
    assert roc_auc([1, 1, 1], [0.2, 0.5, 0.9]) is None


def test_evaluate_shapes_must_match():
    with pytest.raises(ValueError):
        evaluate([1, 0], [1])


def test_heuristic_beats_floor_on_fraud_task():
    data = load_jsonl(SAMPLES)
    report = run(HeuristicDetector(), data, task="fraud")
    # The heuristic should clearly separate fraud from benign on the toy shard.
    assert report.metrics.mcc > 0.5
    assert report.metrics.recall > 0.5
    assert report.task == "fraud"


def test_registry_lists_heuristic():
    assert "heuristic-v0" in available()
    assert isinstance(get_detector("heuristic-v0"), HeuristicDetector)


def test_lazy_detector_missing_dep_raises_cleanly():
    # Without the extras installed, constructing these must raise a helpful error,
    # never an AttributeError / silent success.
    with pytest.raises((ImportError, RuntimeError)):
        get_detector("openai-moderation")
