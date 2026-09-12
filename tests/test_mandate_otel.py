from __future__ import annotations

import copy
import json
import os
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from lurebench.cli import main
from lurebench.mandate import default_mandate_plan, evaluate_mandate, reference_mandate_run
from lurebench.mandate_otel import (
    APPROVAL_EVENT,
    DECISION_EVENT,
    INTENT_EVENT,
    OUTCOME_EVENT,
    project_mandate_otel_run,
    reference_mandate_otel_export,
    validate_mandate_otel_log_export,
    validate_mandate_otel_projection,
)

ROOT = Path(__file__).parents[1]


def _registry() -> Registry:
    resources = []
    for path in (ROOT / "spec").glob("*.schema.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        if "$id" in schema:
            resources.append((schema["$id"], Resource.from_contents(schema)))
    return Registry().with_resources(resources)


def _artifacts() -> tuple[dict, dict, dict, dict]:
    plan = default_mandate_plan()
    run = reference_mandate_run(plan, engine_artifact_sha256="a" * 64)
    export = reference_mandate_otel_export(
        plan,
        run,
        generated_at="2026-09-05T15:20:00Z",
    )
    projection = project_mandate_otel_run(plan, export)
    return plan, run, export, projection


def test_body_free_otel_projection_exactly_reconstructs_evaluable_run():
    plan, run, export, projection = _artifacts()
    assert validate_mandate_otel_log_export(export, plan) == export
    assert validate_mandate_otel_projection(projection) == projection
    assert projection["run"] == run
    assert len(export["records"]) == 67
    assert {
        name: sum(item["EventName"] == name for item in export["records"])
        for name in (INTENT_EVENT, APPROVAL_EVENT, DECISION_EVENT, OUTCOME_EVENT)
    } == {
        INTENT_EVENT: 16,
        APPROVAL_EVENT: 19,
        DECISION_EVENT: 16,
        OUTCOME_EVENT: 16,
    }
    assert export["privacy"]["body_accepted"] is False
    assert projection["clock_boundary"]["observed_timestamp_used_for_benchmark_timing"] is False
    assert (
        evaluate_mandate(plan, projection["run"], evaluated_at="2026-09-05T15:17:00Z")["summary"][
            "verdict"
        ]
        == "pass"
    )

    registry = _registry()
    for filename, value in (
        ("luremandate-otel-log-export-v1.schema.json", export),
        ("luremandate-otel-projection-v1.schema.json", projection),
    ):
        schema = json.loads((ROOT / "spec" / filename).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(
            schema,
            registry=registry,
            format_checker=FormatChecker(),
        ).validate(value)


def test_record_order_does_not_change_run_but_remains_canonically_bound():
    plan, run, export, projection = _artifacts()
    reordered = copy.deepcopy(export)
    reordered["records"].reverse()
    changed = project_mandate_otel_run(plan, reordered)
    assert changed["run"] == run
    assert changed["run_sha256"] == projection["run_sha256"]
    assert (
        changed["inputs"]["otel_log_export_sha256"]
        != projection["inputs"]["otel_log_export_sha256"]
    )


def test_body_unknown_attribute_trace_split_missing_event_and_time_rebinding_fail_closed():
    plan, _, export, _ = _artifacts()

    body = copy.deepcopy(export)
    body["records"][0]["Body"] = "must never enter authority evidence"
    with pytest.raises(ValueError, match="must contain exactly"):
        validate_mandate_otel_log_export(body, plan)

    free_text = copy.deepcopy(export)
    free_text["records"][0]["Attributes"]["user.email"] = "person@example.gov"
    with pytest.raises(ValueError, match="must contain exactly"):
        validate_mandate_otel_log_export(free_text, plan)

    split_trace = copy.deepcopy(export)
    split_trace["records"][1]["TraceId"] = "f" * 32
    with pytest.raises(ValueError, match="exactly one OpenTelemetry trace"):
        validate_mandate_otel_log_export(split_trace, plan)

    missing = copy.deepcopy(export)
    missing["records"] = [
        item
        for item in missing["records"]
        if not (
            item["EventName"] == OUTCOME_EVENT
            and item["Attributes"]["luremandate.transaction.id"] == "tx-01"
        )
    ]
    with pytest.raises(ValueError, match="exactly one intent, decision, and outcome"):
        validate_mandate_otel_log_export(missing, plan)

    rebound = copy.deepcopy(export)
    rebound["records"][0]["Timestamp"] += 1_000_000
    with pytest.raises(ValueError, match="declared lifecycle time"):
        validate_mandate_otel_log_export(rebound, plan)


def test_observed_timestamp_is_bound_but_not_used_for_authority_timing():
    plan, run, export, projection = _artifacts()
    changed = copy.deepcopy(export)
    changed["records"][0]["ObservedTimestamp"] += 5_000_000
    changed_projection = project_mandate_otel_run(plan, changed)
    assert changed_projection["run"] == run
    assert changed_projection["run_sha256"] == projection["run_sha256"]
    assert (
        changed_projection["inputs"]["otel_log_export_sha256"]
        != projection["inputs"]["otel_log_export_sha256"]
    )


def test_mandate_otel_cli_writes_private_no_overwrite_artifacts(tmp_path: Path):
    plan, run, export, _ = _artifacts()
    plan_path = tmp_path / "plan.json"
    run_path = tmp_path / "source-run.json"
    export_path = tmp_path / "otel-export.json"
    projection_path = tmp_path / "projection.json"
    projected_run_path = tmp_path / "projected-run.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    run_path.write_text(json.dumps(run), encoding="utf-8")

    reference_command = [
        "mandate-otel-reference",
        "--plan",
        str(plan_path),
        "--run",
        str(run_path),
        "--generated-at",
        export["generated_at"],
        "--out",
        str(export_path),
    ]
    assert main(reference_command) == 0
    project_command = [
        "mandate-otel-project",
        "--plan",
        str(plan_path),
        "--logs",
        str(export_path),
        "--out",
        str(projection_path),
        "--run-out",
        str(projected_run_path),
    ]
    assert main(project_command) == 0
    assert json.loads(projected_run_path.read_text()) == run
    assert main(["mandate-otel-verify", str(projection_path)]) == 0
    assert main(reference_command) == 2
    assert main(project_command) == 2
    if os.name == "posix":
        for path in (export_path, projection_path, projected_run_path):
            assert path.stat().st_mode & 0o777 == 0o600
