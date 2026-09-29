"""Strict producer-side policy files, arithmetic validation, and safe replacement."""

import copy
import hashlib
import json
import os
from dataclasses import replace

import pytest

from lurebench.calibration import DecisionPolicy, build_policy


def empirical():
    return build_policy("synthetic", "fraud", ["a", "b"], [0, 1], [.1, .9])[0]


@pytest.fixture(scope="module")
def risk_payload():
    return build_policy("synthetic", "fraud", [str(i) for i in range(401)],
                        [0] * 400 + [1], [.1] * 400 + [.9],
                        objective="risk_controlled_fpr", target_fpr=.01,
                        threshold_grid_size=101)[0].as_dict()


def load(tmp_path, value):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(value))
    return DecisionPolicy.load(str(path))


@pytest.mark.parametrize("field,bad", [
    ("schema_version", True), ("schema_version", 3), ("threshold", True),
    ("threshold", "0.5"), ("threshold", None), ("threshold", 1.1),
    ("task", "other"), ("validation_records", True), ("validation_records", 0),
    ("validation_records", 10_000_001), ("validation_sha256", "no-pin"),
    ("created_at", "2026-09-29T00:00:00"), ("created_at", "bad"),
    ("policy_id", ""), ("detector", "line\nbreak"), ("detector", "\ud800"),
    ("objective", "risk_controlled_fpr"), ("target_fpr", True),
    ("evaluation_sha256", "a" * 64), ("risk_control", {}),
])
def test_empirical_policy_rejects_invalid_fields(tmp_path, field, bad):
    value = empirical().as_dict()
    value[field] = bad
    with pytest.raises(ValueError):
        load(tmp_path, value)


@pytest.mark.parametrize("field,bad", [
    ("confidence", True), ("confidence", 1), ("method", "unreviewed"),
    ("risk", "accuracy"), ("threshold_grid_size", True), ("threshold_grid_size", 1),
    ("false_positives", -1), ("false_positives", True),
    ("validation_negatives", 401), ("validation_negatives", 0),
    ("empirical_fpr", .1), ("upper_confidence_bound", 0),
    ("hypothesis_p_value", .5),
])
def test_risk_control_arithmetic_rejected(tmp_path, risk_payload, field, bad):
    value = copy.deepcopy(risk_payload)
    value["risk_control"][field] = bad
    with pytest.raises(ValueError):
        load(tmp_path, value)


@pytest.mark.parametrize("field,bad", [
    ("evaluation_sha256", None), ("validation_true_positives", True),
    ("validation_true_positives", 2), ("validation_recall", 0),
    ("threshold", .111), ("target_fpr", 0), ("created_at", ""),
    ("objective", "max_mcc"),
])
def test_risk_policy_top_level_invariants(tmp_path, risk_payload, field, bad):
    value = copy.deepcopy(risk_payload)
    value[field] = bad
    with pytest.raises(ValueError):
        load(tmp_path, value)


@pytest.mark.parametrize("raw", [b'{}', b'[]', b'{"schema_version":1,"schema_version":2}',
                                  b'{"threshold":NaN}', b'{"threshold":1e999}',
                                  b'[' * 129 + b'0' + b']' * 129, b' ' * 65537])
def test_ambiguous_nonfinite_deep_and_oversized_json_fails(tmp_path, raw):
    path = tmp_path / "policy.json"
    path.write_bytes(raw)
    with pytest.raises(ValueError):
        DecisionPolicy.load(str(path))


def test_unknown_fields_are_rejected_without_echo(tmp_path):
    value = empirical().as_dict()
    value["private-token"] = "do-not-echo"
    with pytest.raises(ValueError) as failure:
        load(tmp_path, value)
    assert "private-token" not in str(failure.value)
    assert "do-not-echo" not in str(failure.value)


def test_atomic_save_does_not_damage_existing_policy_on_failure(tmp_path, monkeypatch):
    from lurebench import calibration

    path = tmp_path / "policy.json"
    policy = empirical()
    policy.save(str(path))
    previous = path.read_bytes()
    with pytest.raises(ValueError):
        replace(policy, threshold=True).save(str(path))
    assert path.read_bytes() == previous

    def fail(*args):
        raise OSError("injected replacement failure")

    monkeypatch.setattr(calibration.os, "replace", fail)
    with pytest.raises(OSError, match="injected"):
        policy.save(str(path))
    assert path.read_bytes() == previous
    assert sorted(p.name for p in tmp_path.iterdir()) == ["policy.json"]


@pytest.mark.parametrize("kind", ["symlink", "fifo", "directory"])
def test_special_file_policy_paths_are_rejected_for_load_and_save(tmp_path, kind):
    path = tmp_path / "policy"
    if kind == "symlink":
        target = tmp_path / "target"
        empirical().save(str(target))
        path.symlink_to(target)
    elif kind == "fifo":
        if not hasattr(os, "mkfifo"):
            pytest.skip("POSIX FIFO")
        os.mkfifo(path)
    else:
        path.mkdir()
    with pytest.raises(ValueError):
        DecisionPolicy.load(str(path))
    with pytest.raises(ValueError):
        empirical().save(str(path))


def test_long_detector_identity_fits_policy_schema_and_keeps_full_name(tmp_path):
    name = "d" * 256
    policy = build_policy(name, "fraud", ["a", "b"], [0, 1], [.1, .9])[0]
    assert len(policy.policy_id) == 256
    assert policy.detector == name
    path = tmp_path / "policy.json"
    policy.save(str(path))
    assert DecisionPolicy.load(str(path)) == policy


def test_provenance_policy_remains_supported_by_benchmark(tmp_path):
    policy = build_policy("synthetic", "provenance", ["a", "b"], [0, 1], [.1, .9])[0]
    assert load(tmp_path, policy.as_dict()) == policy


def test_external_digest_pin_is_checked_against_exact_bytes(tmp_path):
    path = tmp_path / "policy.json"
    policy = empirical()
    policy.save(str(path))
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    assert DecisionPolicy.load(str(path), expected_sha256=digest) == policy
    path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="digest mismatch"):
        DecisionPolicy.load(str(path), expected_sha256=digest)


@pytest.mark.parametrize("pin", [True, "", "A" * 64, "a" * 63])
def test_bad_pin_rejected_before_file_access(tmp_path, pin):
    with pytest.raises(ValueError, match="pin"):
        DecisionPolicy.load(str(tmp_path / "missing"), expected_sha256=pin)
