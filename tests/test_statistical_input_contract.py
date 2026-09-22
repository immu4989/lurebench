"""Malformed observations must never hang ranking or produce policy evidence."""

import itertools
import math
import random
import subprocess
import sys

import pytest

from lurebench.calibration import (
    binomial_cdf,
    bootstrap_ci,
    calibration_metrics,
    clopper_pearson_upper,
    select_risk_controlled_threshold,
    select_threshold,
)
from lurebench.metrics import confusion, evaluate, mcc_from_confusion, recall_at_fpr, roc_auc


def test_nan_ranking_rejects_without_a_tie_loop_hang():
    code = '''
from lurebench.metrics import roc_auc, recall_at_fpr
for call in (lambda: roc_auc([0, 1], [float('nan'), .5]),
             lambda: recall_at_fpr([0, 1], [float('nan'), .5], .1)):
    try:
        call()
    except ValueError:
        pass
    else:
        raise AssertionError('invalid score accepted')
'''
    subprocess.run([sys.executable, "-c", code], check=True, timeout=5)


@pytest.mark.parametrize("bad", [None, True, "0.4", float("nan"), float("inf"), -math.inf])
@pytest.mark.parametrize("operation", [
    lambda b: roc_auc([0, 1], [b, .5]),
    lambda b: recall_at_fpr([0, 1], [b, .5], .1),
    lambda b: evaluate([0, 1], [0, 1], [b, .5]),
    lambda b: calibration_metrics([0, 1], [b, .5]),
    lambda b: select_threshold([0, 1], [b, .5]),
    lambda b: select_risk_controlled_threshold([0, 1], [b, .5], .1),
    lambda b: bootstrap_ci([(0, b), (1, .5)], lambda y, s: sum(s), replicates=2),
])
def test_invalid_scores_rejected(bad, operation):
    with pytest.raises(ValueError):
        operation(bad)


@pytest.mark.parametrize("bad", [True, False, 0.0, 1.0, "1", None, 2, -1])
@pytest.mark.parametrize("operation", [
    lambda b: confusion([b, 1], [0, 1]),
    lambda b: confusion([0, 1], [b, 1]),
    lambda b: roc_auc([b, 1], [.1, .9]),
    lambda b: calibration_metrics([b, 1], [.1, .9]),
    lambda b: select_threshold([b, 1], [.1, .9]),
    lambda b: select_risk_controlled_threshold([b, 1], [.1, .9], .1),
])
def test_binary_labels_are_not_coerced(bad, operation):
    with pytest.raises(ValueError):
        operation(bad)


@pytest.mark.parametrize("bad", [None, True, -1, 2, "0.1", float("nan"), math.inf])
def test_fpr_budget_checked_even_when_class_absent(bad):
    with pytest.raises(ValueError):
        recall_at_fpr([1], [.5], bad)


@pytest.mark.parametrize("bad", [True, 2.0, "2", 0, -1])
def test_integer_calibration_controls(bad):
    with pytest.raises(ValueError):
        calibration_metrics([0, 1], [.1, .9], n_bins=bad)
    with pytest.raises(ValueError):
        select_risk_controlled_threshold([0, 1], [.1, .9], .1, threshold_grid_size=bad)
    with pytest.raises(ValueError):
        bootstrap_ci([(0, .1)], lambda y, s: sum(s), replicates=bad)


@pytest.mark.parametrize("bad", [True, 1.0, "1", -1])
def test_confusion_counts_reject_invalid_types_and_signs(bad):
    with pytest.raises(ValueError):
        mcc_from_confusion(bad, 0, 1, 0)


@pytest.mark.parametrize("bad", [True, 1.0, "1", None])
def test_binomial_counts_are_integers(bad):
    with pytest.raises(ValueError):
        binomial_cdf(bad, 10, .1)
    with pytest.raises(ValueError):
        clopper_pearson_upper(0, bad, .95)


def test_calibration_cannot_export_an_unusable_above_one_threshold():
    with pytest.raises(ValueError, match="no threshold"):
        select_threshold([0, 1], [1., 1.], objective="target_fpr", target_fpr=0.)
    threshold, _ = select_threshold([0, 1], [1., 1.])
    assert 0 <= threshold <= 1


def test_undefined_bootstrap_point_estimate_rejected():
    with pytest.raises(ValueError, match="observed sample"):
        bootstrap_ci([(0, .1)], lambda y, s: math.nan, replicates=2)


def test_ranking_metrics_against_independent_brute_force():
    rng = random.Random(421)
    for _ in range(150):
        labels = [0, 1] + rng.choices([0, 1], k=6)
        scores = rng.choices([-2., -.5, 0., 1., 2.], k=8)
        positives = [s for y, s in zip(labels, scores, strict=True) if y]
        negatives = [s for y, s in zip(labels, scores, strict=True) if not y]
        wins = sum((p > n) + .5 * (p == n) for p, n in itertools.product(positives, negatives))
        assert roc_auc(labels, scores) == pytest.approx(wins / (len(positives) * len(negatives)))
        for budget in (0., .1, .5, 1.):
            possibilities = [0.]
            for threshold in set(scores):
                if sum(s >= threshold for s in negatives) / len(negatives) <= budget:
                    possibilities.append(sum(s >= threshold for s in positives) / len(positives))
            assert recall_at_fpr(labels, scores, budget) == max(possibilities)


def test_numpy_confusion_counts_do_not_overflow_fixed_width_products():
    numpy = pytest.importorskip("numpy")
    n = numpy.int64(1_000_000_000)
    assert mcc_from_confusion(n, numpy.int64(0), n, numpy.int64(0)) == 1.
    assert mcc_from_confusion(n, n, n, n) == 0.
