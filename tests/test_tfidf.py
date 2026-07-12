"""Tests for the TF-IDF + LogisticRegression trained baseline."""

from __future__ import annotations

import pytest

pytest.importorskip("sklearn")  # skip if the 'train' extra isn't installed

from lurebench.detectors.tfidf import TfidfLogisticDetector
from lurebench.schema import Lure


def _toy_corpus():
    fraud = [
        Lure(id=f"f{i}", text="urgent wire transfer confirm the account and pay now",
             label=1, source="ai", typology="bec") for i in range(8)
    ]
    benign = [
        Lure(id=f"b{i}", text="see you at lunch tomorrow, bring the meeting notes",
             label=0, source="human", typology="benign") for i in range(8)
    ]
    return fraud + benign


def test_train_and_score_separates_classes():
    det = TfidfLogisticDetector.train(_toy_corpus(), task="fraud")
    assert det.name == "tfidf-logreg" and det.task == "fraud"
    fraud_score = det.score(Lure(id="x", text="urgent wire transfer pay the account now",
                                 label=1, source="ai", typology="bec"))
    benign_score = det.score(Lure(id="y", text="lunch tomorrow bring the notes",
                                  label=0, source="human", typology="benign"))
    assert 0.0 <= benign_score <= 1.0 and 0.0 <= fraud_score <= 1.0
    assert fraud_score > benign_score  # learned the separation


def test_save_load_roundtrip(tmp_path):
    det = TfidfLogisticDetector.train(_toy_corpus(), task="fraud")
    path = tmp_path / "m.joblib"
    det.save(str(path))
    loaded = TfidfLogisticDetector(model_path=str(path))
    probe = Lure(id="p", text="urgent wire transfer pay now", label=1, source="ai", typology="bec")
    assert loaded.score(probe) == pytest.approx(det.score(probe))


def test_missing_model_raises_helpfully(tmp_path):
    with pytest.raises(RuntimeError, match="Train one first"):
        TfidfLogisticDetector(model_path=str(tmp_path / "nope.joblib"))


def test_registered_in_detector_registry():
    from lurebench.detectors import available
    assert "tfidf-logreg" in available()
