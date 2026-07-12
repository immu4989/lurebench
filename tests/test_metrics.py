"""Tests for evaluation metrics, focused on the operating-point recall@FPR."""

from __future__ import annotations

from lurebench.metrics import evaluate, recall_at_fpr


def test_recall_at_fpr_perfect_separation():
    # All positives score above all negatives -> full recall at any FPR budget.
    y_true = [1, 1, 1, 0, 0, 0]
    scores = [0.9, 0.8, 0.7, 0.3, 0.2, 0.1]
    assert recall_at_fpr(y_true, scores, 0.0) == 1.0


def test_recall_at_fpr_respects_budget():
    # 10 negatives, 10 positives interleaved so catching all positives needs FPs.
    y_true = [1, 0] * 10
    scores = [1.0 - i * 0.01 for i in range(20)]  # strictly descending
    # At FPR 0.1 (1 of 10 negatives allowed), we can only go so deep.
    r = recall_at_fpr(y_true, scores, 0.1)
    assert 0.0 < r < 1.0


def test_recall_at_fpr_none_when_class_absent():
    assert recall_at_fpr([1, 1, 1], [0.9, 0.5, 0.1], 0.05) is None
    assert recall_at_fpr([0, 0, 0], [0.9, 0.5, 0.1], 0.05) is None


def test_balanced_accuracy_averages_recall_and_specificity():
    # 2 pos both caught, 2 neg both correctly rejected -> bal acc 1.0
    y_true = [1, 1, 0, 0]
    y_pred = [1, 1, 0, 0]
    m = evaluate(y_true, y_pred, scores=[0.9, 0.8, 0.2, 0.1])
    assert m.balanced_accuracy == 1.0


def test_balanced_accuracy_penalizes_all_positive_prediction():
    # Predict everything positive: recall 1, specificity 0 -> bal acc 0.5
    y_true = [1, 1, 0, 0]
    y_pred = [1, 1, 1, 1]
    m = evaluate(y_true, y_pred)
    assert m.balanced_accuracy == 0.5
