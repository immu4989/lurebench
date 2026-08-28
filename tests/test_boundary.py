from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from lurebench.boundary import (
    load_boundary_suite,
    run_boundary_evaluation,
    validate_boundary_evaluation,
    validate_boundary_suite,
)
from lurebench.cli import main

SUITE = Path("conformance/lureboundary-v1/suite.json")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_reference_suite_and_report_validate_against_published_schemas():
    suite = _load(SUITE)
    suite_schema = _load(Path("spec/agent-boundary-suite-v1.schema.json"))
    event_schema = _load(Path("spec/agent-boundary-event-v1.schema.json"))
    report_schema = _load(Path("spec/agent-boundary-evaluation-v1.schema.json"))

    for schema in (suite_schema, event_schema, report_schema):
        Draft202012Validator.check_schema(schema)
    Draft202012Validator(suite_schema).validate(suite)
    event_validator = Draft202012Validator(event_schema)
    for trajectory in suite["trajectories"]:
        for event in trajectory["events"]:
            event_validator.validate(event)

    report = run_boundary_evaluation()
    validate_boundary_evaluation(report)
    Draft202012Validator(report_schema, format_checker=FormatChecker()).validate(report)
    assert report["summary"] == {
        "total_trajectories": 14,
        "violation_trajectories": 9,
        "benign_trajectories": 5,
        "true_positive": 9,
        "false_negative": 0,
        "false_positive": 0,
        "true_negative": 5,
        "trajectory_recall": 1.0,
        "benign_false_positive_rate": 0.0,
        "category_accuracy": 1.0,
        "maximum_detection_delay_events": 0,
        "verdict": "pass",
    }


def test_monitor_receives_events_only_without_ground_truth_or_scenario_prose():
    calls = []

    def monitor(trajectory, policy):
        calls.append((set(trajectory), set(policy)))
        return []

    report = run_boundary_evaluation(monitor=monitor, monitor_id="empty-monitor")
    assert calls
    assert all(trajectory_keys == {"events"} for trajectory_keys, _ in calls)
    assert report["summary"]["verdict"] == "fail"
    assert report["summary"]["trajectory_recall"] == 0.0


def test_event_vocabulary_structurally_refuses_content_and_secret_fields():
    suite = _load(SUITE)
    event = suite["trajectories"][0]["events"][0]
    for forbidden in ("prompt", "command", "payload", "credential", "host", "url", "reasoning"):
        changed = json.loads(json.dumps(suite))
        changed["trajectories"][0]["events"][0][forbidden] = "synthetic"
        with pytest.raises(ValueError, match="must contain exactly"):
            validate_boundary_suite(changed)
    assert set(event) == {
        "event_id",
        "sequence",
        "event_type",
        "action",
        "resource_class",
        "authorization",
        "outcome",
        "agent_id",
        "parent_agent_id",
        "channel_id",
        "sensor_id",
    }


def test_evaluation_rejects_rewritten_metrics_and_alert_bindings():
    report = run_boundary_evaluation()
    changed = json.loads(json.dumps(report))
    changed["summary"]["trajectory_recall"] = 0.5
    with pytest.raises(ValueError, match="metrics do not reconcile"):
        validate_boundary_evaluation(changed)

    changed = json.loads(json.dumps(report))
    changed["results"][0]["alerts"][0]["sequence"] = 1
    with pytest.raises(ValueError, match="detection_delay_events does not reconcile"):
        validate_boundary_evaluation(changed)

    changed = json.loads(json.dumps(report))
    changed["summary"]["true_positive"] = True
    with pytest.raises(ValueError, match="must be an integer"):
        validate_boundary_evaluation(changed)


def test_boundary_cli_writes_private_report_without_overwrite(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    output = tmp_path / "boundary-evaluation.json"
    assert main(["boundary-eval", "--out", str(output)]) == 0
    assert "LUREBOUNDARY: PASS" in capsys.readouterr().out
    assert os.stat(output).st_mode & 0o777 == 0o600
    original = output.read_bytes()

    assert main(["boundary-eval", "--out", str(output)]) == 2
    assert output.read_bytes() == original
    assert "File exists" in capsys.readouterr().err


def test_external_suite_refuses_symlink_and_duplicate_json_keys(tmp_path: Path):
    linked = tmp_path / "suite.json"
    linked.symlink_to(SUITE.resolve())
    with pytest.raises(ValueError, match="regular local JSON"):
        load_boundary_suite(linked)

    linked_directory = tmp_path / "linked-suite"
    linked_directory.symlink_to(SUITE.resolve().parent, target_is_directory=True)
    with pytest.raises(ValueError, match="regular local JSON"):
        load_boundary_suite(linked_directory)

    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema": 1, "schema": 2}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate JSON object key"):
        load_boundary_suite(duplicate)
