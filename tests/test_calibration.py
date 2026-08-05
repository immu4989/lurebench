import json

import pytest

from lurebench.calibration import (
    DecisionPolicy,
    bootstrap_ci,
    build_policy,
    calibration_metrics,
    select_threshold,
)


def test_calibration_metrics_perfect_probabilities():
    result = calibration_metrics([0, 1], [0.0, 1.0], n_bins=2)
    assert result.brier == 0.0
    assert result.expected_calibration_error == 0.0


def test_select_threshold_max_mcc_uses_validation_scores():
    threshold, metrics = select_threshold([0, 0, 1, 1], [0.1, 0.2, 0.8, 0.9])
    assert threshold == 0.8
    assert metrics.mcc == 1.0


def test_target_fpr_respects_tied_thresholds():
    threshold, metrics = select_threshold(
        [1, 0, 1], [0.9, 0.9, 0.8], objective="target_fpr", target_fpr=0.0
    )
    assert threshold > 0.9
    assert metrics.fpr == 0.0
    assert metrics.recall == 0.0


def test_policy_round_trip_has_validation_provenance(tmp_path):
    policy, _ = build_policy(
        "detector", "fraud", ["a", "b"], [0, 1], [0.1, 0.9]
    )
    path = tmp_path / "policy.json"
    policy.save(str(path))
    loaded = DecisionPolicy.load(str(path))
    assert loaded == policy
    assert len(json.loads(path.read_text())["validation_sha256"]) == 64


def test_bootstrap_is_reproducible_and_contains_estimate():
    values = [(0, 0.1), (0, 0.2), (1, 0.8), (1, 0.9)]

    def statistic(truth, score):
        return sum(score) / len(score)

    first = bootstrap_ci(values, statistic, replicates=100, seed=7)
    second = bootstrap_ci(values, statistic, replicates=100, seed=7)
    assert first == second
    assert first.lower <= first.estimate <= first.upper


def test_invalid_calibration_inputs_fail_closed():
    with pytest.raises(ValueError):
        calibration_metrics([1], [1.2])
