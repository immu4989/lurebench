"""Reject impossible/invalid calibration plans before constructing a detector."""

import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from lurebench import calibration, cli
from lurebench.schema import Lure, save_jsonl


def records(labels=(0, 1)):
    return [Lure(str(i), f"Synthetic notes {i}", label, "human",
                 "phishing" if label else "benign") for i, label in enumerate(labels)]


@pytest.mark.parametrize("options", [
    ["--bins", "0"], ["--bins", "10001"], ["--confidence", "nan"],
    ["--confidence", "1"], ["--threshold-grid-size", "1"],
    ["--threshold-grid-size", "100002"], ["--target-fpr", "nan"],
    ["--objective", "target_fpr"], ["--objective", "target_fpr", "--target-fpr", "2"],
    ["--objective", "risk_controlled_fpr", "--target-fpr", "0"],
    ["--objective", "risk_controlled_fpr", "--target-fpr", "1"],
])
def test_invalid_controls_stop_before_input_and_constructor(tmp_path, monkeypatch, capsys, options):
    calls = []
    monkeypatch.setattr(cli, "load_jsonl", lambda *a, **kw: calls.append("read"))
    monkeypatch.setattr(cli, "get_detector", lambda *a, **kw: calls.append("constructed"))
    output = tmp_path / "policy.json"
    output.write_text("existing evidence")
    assert cli.main(["calibrate", "-d", "private-sentinel", "-m", "heuristic-v0",
                     "-o", str(output), *options]) == 2
    assert calls == []
    assert output.read_text() == "existing evidence"
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "private-sentinel" not in captured.err


@pytest.mark.parametrize("population", [[], [0], [1], [0, 1]])
def test_impossible_risk_sample_never_constructs_detector(tmp_path, monkeypatch, population):
    source = tmp_path / "validation.jsonl"
    save_jsonl(records(population), source)
    called = []
    monkeypatch.setattr(cli, "get_detector", lambda *a, **kw: called.append(True))
    assert cli.main(["calibrate", "-d", str(source), "-m", "heuristic-v0",
                     "--objective", "risk_controlled_fpr", "--target-fpr", ".01",
                     "-o", str(tmp_path / "out.json")]) == 2
    assert called == []


def test_invalid_population_before_constructor(tmp_path, monkeypatch):
    source = tmp_path / "validation.jsonl"
    items = records()
    items[1].id = items[0].id
    # Bypass file-level duplicate-ID validation to exercise calibration preflight.
    monkeypatch.setattr(cli, "load_jsonl", lambda *a: items)
    called = []
    monkeypatch.setattr(cli, "get_detector", lambda *a, **kw: called.append(True))
    assert cli.main(["calibrate", "-d", str(source), "-m", "heuristic-v0",
                     "-o", str(tmp_path / "out.json")]) == 2
    assert called == []


def test_policy_record_cap_before_constructor(tmp_path, monkeypatch):
    monkeypatch.setattr(calibration, "MAX_POLICY_RECORDS", 1)
    monkeypatch.setattr(cli, "load_jsonl", lambda *a: records())
    called = []
    monkeypatch.setattr(cli, "get_detector", lambda *a, **kw: called.append(True))
    assert cli.main(["calibrate", "-d", "unused", "-m", "heuristic-v0",
                     "-o", str(tmp_path / "out.json")]) == 2
    assert called == []


def test_task_mismatch_rejected_before_scoring(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "load_jsonl", lambda *a: records())
    scored = []
    monkeypatch.setattr(cli, "get_detector", lambda *a, **kw: SimpleNamespace(
        name="synthetic", task="provenance", score=lambda r: scored.append(True),
    ))
    assert cli.main(["calibrate", "-d", "unused", "-m", "synthetic",
                     "--task", "fraud", "-o", str(tmp_path / "out.json")]) == 1
    assert scored == []


@pytest.mark.parametrize("objective,target", [("max_mcc", None), ("target_fpr", .1)])
def test_empirical_identity_commits_to_observed_scores_and_labels(objective, target):
    def build(labels, scores):
        return calibration.build_policy("synthetic", "fraud", ["a", "b", "c"],
                                         labels, scores, objective, target)[0]

    first = build([0, 0, 1], [.1, .2, .9])
    assert build([0, 0, 1], [.1, .2, .9]).policy_id == first.policy_id
    assert build([0, 0, 1], [.11, .2, .9]).policy_id != first.policy_id
    assert build([0, 1, 1], [.1, .2, .9]).policy_id != first.policy_id
    assert len(first.policy_id.rsplit("-", 1)[1]) == 64


def test_historical_policy_id_is_not_rewritten_when_loading(tmp_path):
    policy, _ = calibration.build_policy("synthetic", "fraud", ["a", "b"], [0, 1], [.1, .9])
    legacy = replace(policy, policy_id="legacy-arbitrary-reviewed-identifier")
    path = tmp_path / "historical.json"
    legacy.save(str(path))
    original = path.read_bytes()
    assert calibration.DecisionPolicy.load(str(path)).policy_id == legacy.policy_id
    assert path.read_bytes() == original
    assert json.loads(original)["schema_version"] == 1


@pytest.mark.parametrize("confidence,target,n_negative", [
    (.95, .01, 298), (.99, .01, 458), (.95, 5e-324, 400),
])
def test_risk_feasibility_rejects_before_selector(monkeypatch, confidence, target, n_negative):
    monkeypatch.setattr(calibration, "select_risk_controlled_threshold",
                        lambda *a, **kw: pytest.fail("selector invoked"))
    with pytest.raises(ValueError, match="insufficient validation negatives"):
        calibration.build_policy("fixed", "fraud", [str(i) for i in range(n_negative + 1)],
                                 [0] * n_negative + [1], [.1] * n_negative + [.9],
                                 "risk_controlled_fpr", target, confidence)


@pytest.mark.parametrize("confidence,target,n_negative", [(.95, .01, 299), (.99, .01, 459)])
def test_minimum_feasible_risk_plan_reaches_selector(confidence, target, n_negative):
    labels, scores = [0] * n_negative + [1], [.1] * n_negative + [.9]
    expected = calibration.select_risk_controlled_threshold(labels, scores, target, confidence)
    policy, metrics = calibration.build_policy(
        "fixed", "fraud", [str(i) for i in range(n_negative + 1)], labels, scores,
        "risk_controlled_fpr", target, confidence,
    )
    assert (policy.threshold, metrics, policy.risk_control) == expected


@pytest.mark.parametrize("overrides", [
    {"confidence": False}, {"confidence": float("nan")}, {"threshold_grid_size": True},
    {"threshold_grid_size": 2.5}, {"target_fpr": float("nan")}, {"objective": "unknown"},
])
def test_python_invalid_controls_before_selection(monkeypatch, overrides):
    monkeypatch.setattr(calibration, "select_threshold", lambda *a, **kw: pytest.fail("selection"))
    with pytest.raises(ValueError):
        calibration.build_policy("fixed", "fraud", ["a", "b"], [0, 1], [.1, .9], **overrides)


@pytest.mark.parametrize("bins", [True, 0, 10001, 2.5])
def test_python_invalid_diagnostic_bins(bins):
    with pytest.raises(ValueError):
        calibration.validate_calibration_configuration("max_mcc", None, .95, 1001, bins)


@pytest.mark.parametrize("task", ["fraud", "provenance"])
def test_successful_cli_preserves_empirical_selection(tmp_path, monkeypatch, task):
    items = records()
    items[1].source = "ai"
    monkeypatch.setattr(cli, "load_jsonl", lambda *a: items)
    seen = []

    def score(record):
        seen.append(record.id)
        return .1 if record.id == "0" else .9

    monkeypatch.setattr(cli, "get_detector", lambda *a, **kw: SimpleNamespace(
        name="synthetic", task=task, score=score,
    ))
    output = tmp_path / "policy.json"
    assert cli.main(["calibrate", "-d", "unused", "-m", "synthetic", "--task", task,
                     "--target-fpr", ".1", "-o", str(output)]) == 0
    assert seen == ["0", "1"]
    policy = calibration.DecisionPolicy.load(str(output))
    expected, _ = calibration.select_threshold([0, 1], [.1, .9])
    assert policy.threshold == expected
    assert policy.task == task


@pytest.mark.parametrize("error", [OSError, ValueError])
def test_dataset_failure_is_redacted_and_preserves_output(tmp_path, monkeypatch, capsys, error):
    def fail(*a):
        raise error("private-dataset-sentinel")

    monkeypatch.setattr(cli, "load_jsonl", fail)
    monkeypatch.setattr(cli, "get_detector", lambda *a, **kw: pytest.fail("detector invoked"))
    path = tmp_path / "policy.json"
    path.write_bytes(b"existing evidence")
    assert cli.main(["calibrate", "-d", "unused", "-m", "synthetic", "-o", str(path)]) == 2
    assert path.read_bytes() == b"existing evidence"
    assert "private-dataset-sentinel" not in capsys.readouterr().err


def test_empirical_id_matches_documented_canonical_evidence():
    policy, _ = calibration.build_policy("fixed", "fraud", ["a", "b"], [0, 1], [.1, .9])
    rows = b"".join(json.dumps({"id": key, "label": truth, "score_hex": score.hex()},
                    sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode() + b"\n"
                    for key, truth, score in [("a", 0, .1), ("b", 1, .9)])
    material = {"contract": "decision-policy-evidence-v1", "detector": "fixed", "task": "fraud",
                "objective": "max_mcc", "target_fpr_hex": None,
                "validation_sha256": hashlib.sha256(b"a\nb").hexdigest(),
                "evaluation_sha256": hashlib.sha256(rows).hexdigest(),
                "threshold_hex": float(policy.threshold).hex(), "risk_control": None}
    expected = hashlib.sha256(json.dumps(material, sort_keys=True,
                                        separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
    assert policy.policy_id == f"fixed-{expected}"
    assert policy.evaluation_sha256 is None  # No silent v1 schema extension.


def test_long_names_are_bounded_without_identity_aliasing():
    def build(name):
        return calibration.build_policy(name, "fraud", ["a", "b"], [0, 1], [.1, .9])[0]

    first, second = build("a" * 256), build("a" * 255 + "b")
    assert len(first.policy_id) == len(second.policy_id) == 256
    assert first.policy_id != second.policy_id


def test_risk_policy_identity_binds_grid_confidence_and_scores():
    def build(*, confidence=.95, grid=1001, first_score=.1):
        return calibration.build_policy("fixed", "fraud", [str(i) for i in range(501)],
                    [0] * 500 + [1], [first_score] + [.1] * 499 + [.9],
                    "risk_controlled_fpr", .01, confidence, grid)[0]

    first = build()
    assert first.policy_id == build().policy_id
    assert first.policy_id != build(confidence=.99).policy_id
    assert first.policy_id != build(grid=101).policy_id
    assert first.policy_id != build(first_score=.09).policy_id
    assert first.threshold == build(first_score=.09).threshold
