"""V3 binds declared inference configuration without rewriting historical evidence."""

import json
from dataclasses import replace
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from lurebench.calibration import DecisionPolicy, DetectorBinding, build_policy

BINDING = DetectorBinding("lurescope-portable-tfidf-exact-v1", "a" * 64, "b" * 64, "c" * 64)


def build(objective="max_mcc", binding=BINDING):
    return build_policy("tfidf-logreg", "fraud", [str(i) for i in range(401)],
                        [0] * 400 + [1], [.1] * 400 + [.9], objective, .01,
                        detector_binding=binding)[0]


@pytest.mark.parametrize("objective", ["max_mcc", "target_fpr", "risk_controlled_fpr"])
def test_bound_policy_round_trip_and_schema(tmp_path, objective):
    policy = build(objective)
    assert policy.schema_version == 3
    assert policy.evaluation_sha256 is not None
    path = tmp_path / "bound.json"
    policy.save(str(path))
    assert DecisionPolicy.load(str(path)) == policy
    schema = json.loads((Path(__file__).parents[1] / "spec/decision-policy-v3.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(json.loads(path.read_text()))


@pytest.mark.parametrize("field", ["artifact_sha256", "implementation_sha256", "runtime_sha256"])
def test_binding_changes_identity(field):
    assert build().policy_id != build(binding=replace(BINDING, **{field: "d" * 64})).policy_id


@pytest.mark.parametrize("field,value", [
    ("threshold", .8), ("validation_records", 402), ("evaluation_sha256", "d" * 64),
    ("validation_sha256", "e" * 64), ("policy_id", "copied-identity"),
    ("target_fpr", .02), ("objective", "target_fpr"),
])
def test_changed_evidence_without_new_id_is_rejected(tmp_path, field, value):
    path = tmp_path / "policy.json"
    policy = build()
    policy.save(str(path))
    raw = json.loads(path.read_text())
    raw[field] = value
    path.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="identity"):
        DecisionPolicy.load(str(path))


@pytest.mark.parametrize("binding", [None, {}, [], {"extra": "x"}])
def test_v3_requires_complete_binding(tmp_path, binding):
    raw = build().as_dict()
    raw["detector_binding"] = binding
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(raw))
    with pytest.raises(ValueError):
        DecisionPolicy.load(str(path))


@pytest.mark.parametrize("field,value", [
    ("profile", "caller-defined"), ("artifact_sha256", "A" * 64),
    ("implementation_sha256", True), ("runtime_sha256", "short"),
])
def test_invalid_binding_rejected(field, value):
    with pytest.raises(ValueError):
        build(binding=replace(BINDING, **{field: value}))


@pytest.mark.parametrize("detector,task", [("llm-judge", "fraud"), ("tfidf-logreg", "provenance")])
def test_binding_cannot_be_relabelled(detector, task):
    with pytest.raises(ValueError, match="binding"):
        build_policy(detector, task, ["a", "b"], [0, 1], [.1, .9], detector_binding=BINDING)


@pytest.mark.parametrize("version", [1, 2])
def test_binding_cannot_be_smuggled_into_legacy_schema(tmp_path, version):
    raw = build("risk_controlled_fpr" if version == 2 else "max_mcc").as_dict()
    raw["schema_version"] = version
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="legacy"):
        DecisionPolicy.load(str(path))


def test_bad_risk_arithmetic_still_rejected(tmp_path):
    raw = build("risk_controlled_fpr").as_dict()
    raw["risk_control"]["upper_confidence_bound"] = 0
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="inconsistent"):
        DecisionPolicy.load(str(path))


def test_legacy_builders_keep_their_schemas():
    assert build(binding=None).schema_version == 1
    assert build("risk_controlled_fpr", binding=None).schema_version == 2


def test_semantically_equal_numeric_json_preserves_id(tmp_path):
    policy = build("risk_controlled_fpr")
    payload = policy.as_dict()
    payload["risk_control"]["empirical_fpr"] = 0
    payload["validation_recall"] = 1
    path = tmp_path / "integers.json"
    path.write_text(json.dumps(payload))
    assert DecisionPolicy.load(str(path)).policy_id == policy.policy_id
