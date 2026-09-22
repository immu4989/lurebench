"""Fast selection must match exhaustive evaluation, including tied scores."""

import itertools
import math

import pytest

from lurebench.calibration import select_threshold
from lurebench.metrics import evaluate


def _reference(labels, scores, objective, budget):
    candidates = set(scores)
    if max(scores) < 1:
        candidates.add(math.nextafter(max(scores), math.inf))
    feasible = []
    for threshold in candidates:
        metrics = evaluate(labels, [int(s >= threshold) for s in scores], scores)
        if objective == "max_mcc" or metrics.fpr <= budget:
            key = ((metrics.mcc, metrics.recall, threshold) if objective == "max_mcc"
                   else (metrics.recall, metrics.mcc, threshold))
            feasible.append((key, threshold, metrics))
    if not feasible:
        return None
    _, threshold, metrics = max(feasible, key=lambda row: row[0])
    return threshold, metrics


def test_sweep_matches_all_four_record_ternary_score_cases():
    for labels in itertools.product((0, 1), repeat=4):
        for scores in itertools.product((0., .5, 1.), repeat=4):
            for objective, budget in (("max_mcc", None), ("target_fpr", 0.),
                                      ("target_fpr", .5), ("target_fpr", 1.)):
                expected = _reference(labels, scores, objective, budget)
                if expected is None:
                    with pytest.raises(ValueError, match="no threshold"):
                        select_threshold(labels, scores, objective, budget)
                else:
                    assert select_threshold(labels, scores, objective, budget) == expected


def test_full_metric_bundle_computed_once_for_large_validation_set(monkeypatch):
    from lurebench import calibration

    calls = []
    original = calibration.evaluate

    def counted(*args):
        calls.append(len(args[0]))
        return original(*args)

    monkeypatch.setattr(calibration, "evaluate", counted)
    size = 10_000
    labels = [int(index >= size // 2) for index in range(size)]
    scores = [index / size for index in range(size)]
    threshold, metrics = select_threshold(labels, scores)
    assert threshold == .5
    assert metrics.mcc == 1
    assert calls == [size]


def test_real_inputs_use_the_same_float_probability_contract_as_serving():
    from fractions import Fraction

    labels = [0, 0, 1, 1]
    scores = [Fraction(1, 10), Fraction(1, 5), Fraction(4, 5), Fraction(9, 10)]
    assert select_threshold(labels, scores) == select_threshold(labels, list(map(float, scores)))
