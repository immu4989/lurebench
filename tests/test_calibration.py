import hashlib
import json
import math
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from lurebench.calibration import (
    DecisionPolicy,
    binomial_cdf,
    bootstrap_ci,
    build_policy,
    calibration_metrics,
    clopper_pearson_upper,
    minimum_zero_event_sample,
    select_risk_controlled_threshold,
    select_threshold,
)
from lurebench.cli import main
from lurebench.schema import Lure, save_jsonl


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
    validation_digest = hashlib.sha256(b"a\nb").hexdigest()
    legacy_material = f"detector\0fraud\0max_mcc\0None\0{validation_digest}"
    legacy_identity = hashlib.sha256(legacy_material.encode("utf-8")).hexdigest()[:12]
    assert policy.policy_id == f"detector-{legacy_identity}"


def test_exact_binomial_bound_matches_zero_event_closed_form():
    assert binomial_cdf(0, 10, 0.1) == pytest.approx(0.9 ** 10)
    expected = 1.0 - 0.05 ** (1 / 400)
    assert clopper_pearson_upper(0, 400, 0.95) == pytest.approx(expected)
    assert minimum_zero_event_sample(0.01, 0.95) == 299


@pytest.mark.parametrize("events,trials,probability", [(2, 10, 0.3), (7, 20, 0.4), (20, 50, 0.25)])
def test_binomial_cdf_matches_direct_finite_sum(events, trials, probability):
    expected = math.fsum(
        math.comb(trials, index)
        * probability ** index
        * (1 - probability) ** (trials - index)
        for index in range(events + 1)
    )
    assert binomial_cdf(events, trials, probability) == pytest.approx(expected, abs=1e-14)


def test_risk_controlled_threshold_has_finite_sample_fpr_bound():
    truths = [0] * 400 + [1] * 100
    scores = [0.1] * 400 + [0.9] * 100
    threshold, metrics, control = select_risk_controlled_threshold(
        truths, scores, target_fpr=0.01, confidence=0.95, threshold_grid_size=101
    )
    assert threshold == pytest.approx(0.11)
    assert metrics.recall == 1.0
    assert control.false_positives == 0
    assert control.validation_negatives == 400
    assert control.upper_confidence_bound <= 0.01
    assert control.hypothesis_p_value <= 0.05


def test_risk_control_fails_closed_when_validation_is_too_small():
    with pytest.raises(ValueError, match="at least 299"):
        select_risk_controlled_threshold(
            [0] * 100 + [1], [0.0] * 100 + [1.0], target_fpr=0.01
        )


def test_risk_controlled_policy_v2_round_trip(tmp_path):
    ids = [f"negative-{index}" for index in range(400)] + ["positive"]
    policy, metrics = build_policy(
        "detector",
        "fraud",
        ids,
        [0] * 400 + [1],
        [0.1] * 400 + [0.9],
        objective="risk_controlled_fpr",
        target_fpr=0.01,
        threshold_grid_size=101,
    )
    path = tmp_path / "policy-v2.json"
    policy.save(str(path))
    loaded = DecisionPolicy.load(str(path))
    payload = json.loads(path.read_text())
    assert loaded == policy
    assert metrics.recall == 1.0
    assert policy.schema_version == 2
    assert policy.risk_control is not None
    assert len(payload["evaluation_sha256"]) == 64
    assert payload["validation_true_positives"] == 1
    assert payload["validation_recall"] == 1.0
    assert payload["risk_control"]["risk"] == "false_positive_rate"
    schema_path = Path(__file__).parents[1] / "spec" / "decision-policy-v2.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(payload)


def test_calibrate_cli_exports_risk_controlled_policy(tmp_path, capsys):
    validation = tmp_path / "validation.jsonl"
    output = tmp_path / "policy.json"
    records = [
        Lure(
            id=f"benign-{index}",
            text="Weekly project meeting agenda and notes.",
            label=0,
            source="human",
            typology="benign",
        )
        for index in range(400)
    ]
    records.extend(
        Lure(
            id=f"fraud-{index}",
            text="Urgent: verify your account immediately at <<link>>.",
            label=1,
            source="ai",
            typology="phishing",
        )
        for index in range(20)
    )
    save_jsonl(records, validation)
    assert main([
        "calibrate",
        "-d", str(validation),
        "-m", "heuristic-v0",
        "--objective", "risk_controlled_fpr",
        "--target-fpr", "0.01",
        "--confidence", "0.95",
        "--threshold-grid-size", "1001",
        "-o", str(output),
    ]) == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    console = capsys.readouterr().out
    assert payload["schema_version"] == 2
    assert payload["risk_control"]["upper_confidence_bound"] <= 0.01
    assert "95.0% one-sided FPR bound" in console


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
