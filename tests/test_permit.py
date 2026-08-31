from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from lurebench.cli import main
from lurebench.permit import (
    default_permit,
    default_range_suite,
    load_permit,
    reference_permit_engine,
    run_range_evaluation,
    validate_permit,
    validate_range_evaluation,
    validate_range_suite,
)

ROOT = Path(__file__).parents[1]


def test_reference_permit_range_and_report_match_published_schemas():
    permit = default_permit()
    suite = default_range_suite()
    report = run_range_evaluation(generated_at="2026-08-30T12:00:00Z")
    artifacts = (
        ("lurepermit-v1.schema.json", permit),
        ("lurerange-suite-v1.schema.json", suite),
        ("lurerange-evaluation-v1.schema.json", report),
    )
    for filename, value in artifacts:
        schema = json.loads((ROOT / "spec" / filename).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(value)

    assert report["summary"] == {
        "total_scenarios": 21,
        "violation_scenarios": 15,
        "benign_scenarios": 6,
        "correct_decisions": 21,
        "incorrect_decisions": 0,
        "violation_control_rate": 1.0,
        "benign_allow_rate": 1.0,
        "reason_accuracy": 1.0,
        "safe_stop_recall": 1.0,
        "verdict": "pass",
    }


def test_engine_sees_only_typed_request_and_permit_not_ground_truth_or_prose():
    calls = []

    def inspected_engine(request, permit):
        calls.append((set(request), set(permit)))
        return reference_permit_engine(request, permit)

    report = run_range_evaluation(
        engine=inspected_engine,
        engine_id="inspected-engine",
        generated_at="2026-08-30T12:00:00Z",
    )
    assert report["summary"]["verdict"] == "pass"
    assert len(calls) == 21
    assert all("expected" not in request and "title" not in request for request, _ in calls)
    assert all("acceptance" in permit for _, permit in calls)


def test_incorrect_external_engine_fails_without_rewriting_metrics():
    def allow_everything(request, _permit):
        return {
            "request_id": request["request_id"],
            "sequence": request["sequence"],
            "decision": "allow",
            "reason_code": "permit_allows_request",
        }

    report = run_range_evaluation(
        engine=allow_everything,
        engine_id="allow-all-engine",
        generated_at="2026-08-30T12:00:00Z",
    )
    assert report["summary"]["verdict"] == "fail"
    assert report["summary"]["violation_control_rate"] == 0.0
    assert report["summary"]["benign_allow_rate"] == 1.0
    validate_range_evaluation(report)


def test_engine_cannot_mutate_embedded_permit_or_later_calls():
    original = default_permit()

    def mutating_engine(request, permit):
        permit["system_id"] = "mutated-system"
        return reference_permit_engine(request, permit)

    report = run_range_evaluation(
        engine=mutating_engine,
        engine_id="mutating-engine",
        generated_at="2026-08-30T12:00:00Z",
    )
    assert report["summary"]["verdict"] == "pass"
    assert report["inputs"]["permit"] == original


def test_structural_allowlists_refuse_content_secret_and_execution_fields():
    suite = default_range_suite()
    forbidden = ("prompt", "command", "payload", "credential", "hostname", "url", "reasoning")
    for key in forbidden:
        changed = json.loads(json.dumps(suite))
        changed["scenarios"][0]["request"][key] = "synthetic"
        with pytest.raises(ValueError, match="must contain exactly"):
            validate_range_suite(changed)

    permit = default_permit()
    changed = json.loads(json.dumps(permit))
    changed["authorization"]["allowed_urls"] = ["synthetic"]
    with pytest.raises(ValueError, match="must contain exactly"):
        validate_permit(changed)

    changed = json.loads(json.dumps(permit))
    changed["authorization"]["allowed_action_types"] = [{}]
    with pytest.raises(ValueError, match="unsupported value"):
        validate_permit(changed)


def test_engine_decision_types_fail_closed():
    def boolean_sequence(request, permit):
        decision = reference_permit_engine(request, permit)
        decision["sequence"] = True
        return decision

    with pytest.raises(ValueError, match="must be an integer"):
        run_range_evaluation(
            engine=boolean_sequence,
            generated_at="2026-08-30T12:00:00Z",
        )

    with pytest.raises(ValueError, match="digest must be"):
        run_range_evaluation(
            engine_artifact_sha256=True,
            generated_at="2026-08-30T12:00:00Z",
        )


def test_report_rejects_rewritten_metrics_decisions_and_input_digests():
    report = run_range_evaluation(generated_at="2026-08-30T12:00:00Z")
    changed = json.loads(json.dumps(report))
    changed["summary"]["violation_control_rate"] = 0.5
    with pytest.raises(ValueError, match="do not reconcile"):
        validate_range_evaluation(changed)

    changed = json.loads(json.dumps(report))
    changed["results"][0]["decision"]["request_id"] = "different-request"
    with pytest.raises(ValueError, match="does not bind"):
        validate_range_evaluation(changed)

    changed = json.loads(json.dumps(report))
    changed["inputs"]["permit_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="digests do not reconcile"):
        validate_range_evaluation(changed)

    changed = json.loads(json.dumps(report))
    changed["summary"]["incorrect_decisions"] = False
    with pytest.raises(ValueError, match="must be an integer"):
        validate_range_evaluation(changed)

    changed = json.loads(json.dumps(report))
    changed["schema_version"] = True
    with pytest.raises(ValueError, match="unsupported LureRange"):
        validate_range_evaluation(changed)


def test_external_suite_expectations_must_derive_from_permit(tmp_path: Path):
    suite = default_range_suite()
    suite["scenarios"][6]["expected"] = {
        "decision": "block",
        "reason_code": "actor_not_permitted",
    }
    path = tmp_path / "changed-suite.json"
    path.write_text(json.dumps(suite), encoding="utf-8")
    with pytest.raises(ValueError, match="expectation does not derive"):
        run_range_evaluation(suite_path=path)


def test_cli_exports_private_artifacts_and_never_overwrites(tmp_path: Path, capsys):
    permit = tmp_path / "permit.json"
    suite = tmp_path / "suite.json"
    report = tmp_path / "evaluation.json"
    assert main(["permit-init", "--out", str(permit)]) == 0
    assert main(["range-export", "--out", str(suite)]) == 0
    assert (
        main(
            [
                "range-eval",
                "--permit",
                str(permit),
                "--suite",
                str(suite),
                "--out",
                str(report),
            ]
        )
        == 0
    )
    assert "LURERANGE: PASS" in capsys.readouterr().out
    if os.name == "posix":
        assert all(path.stat().st_mode & 0o777 == 0o600 for path in (permit, suite, report))
    original = report.read_bytes()
    assert main(["range-eval", "--out", str(report)]) == 2
    assert report.read_bytes() == original
    assert "File exists" in capsys.readouterr().err


def test_external_permit_refuses_symlink_and_duplicate_json_keys(tmp_path: Path):
    source = tmp_path / "source.json"
    source.write_text(json.dumps(default_permit()), encoding="utf-8")
    linked = tmp_path / "linked.json"
    linked.symlink_to(source)
    with pytest.raises(ValueError, match="regular local JSON"):
        load_permit(linked)

    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema": 1, "schema": 2}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate JSON object key"):
        load_permit(duplicate)
