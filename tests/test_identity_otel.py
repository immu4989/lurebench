from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import jsonschema
import pytest
from referencing import Registry, Resource

from lurebench.cli import main
from lurebench.identity import (
    default_identity_plan,
    evaluate_identity_run,
    reference_identity_run,
)
from lurebench.identity_otel import (
    ACCESS_EVENT,
    EXPORT_LIMITATIONS,
    LIFECYCLE_EVENT,
    OTEL_EXPORT_SCHEMA,
    project_identity_otel_run,
    validate_identity_otel_log_export,
    validate_identity_otel_projection,
)

ROOT = Path(__file__).parents[1]


def _schema_registry() -> Registry:
    resources = []
    for path in (ROOT / "spec").glob("*.schema.json"):
        value = json.loads(path.read_text(encoding="utf-8"))
        if "$id" in value:
            resources.append((value["$id"], Resource.from_contents(value)))
    return Registry().with_resources(resources)


def _otel_export() -> tuple[dict, dict, dict]:
    plan = default_identity_plan()
    run = reference_identity_run(
        plan,
        implementation_name="agency-identity-receiver",
        implementation_version="2.1.0",
        implementation_artifact_sha256="a" * 64,
        generated_at="2026-09-03T12:00:00Z",
    )
    origin = int(datetime(2026, 9, 3, tzinfo=timezone.utc).timestamp()) * 1_000_000_000
    probe_map = {item["probe_id"]: item for item in plan["probes"]}
    records = []
    for index, observation in enumerate(run["event_observations"], start=1):
        timestamp = origin + observation["received_at_ms"] * 1_000_000
        records.append(
            {
                "Timestamp": timestamp,
                "ObservedTimestamp": timestamp + 1_000_000,
                "TraceId": f"{index:032x}",
                "SpanId": f"{index:016x}",
                "EventName": LIFECYCLE_EVENT,
                "Resource": {
                    "service.name": "agency-identity-receiver",
                    "service.instance.id": observation["node_id"],
                    "service.version": "2.1.0",
                },
                "Attributes": {
                    key: value for key, value in observation.items() if key != "received_at_ms"
                },
            }
        )
    offset = len(records)
    for index, observation in enumerate(run["access_observations"], start=1):
        probe = probe_map[observation["probe_id"]]
        timestamp = origin + probe["attempted_at_ms"] * 1_000_000
        context = offset + index
        records.append(
            {
                "Timestamp": timestamp,
                "ObservedTimestamp": timestamp + 2_000_000,
                "TraceId": f"{context:032x}",
                "SpanId": f"{context:016x}",
                "EventName": ACCESS_EVENT,
                "Resource": {
                    "service.name": "agency-identity-receiver",
                    "service.instance.id": probe["node_id"],
                    "service.version": "2.1.0",
                },
                "Attributes": dict(observation),
            }
        )
    export = {
        "schema": OTEL_EXPORT_SCHEMA,
        "schema_version": 1,
        "export_id": "agency-identity-otel-1",
        "generated_at": "2026-09-03T12:00:00Z",
        "time_origin_unix_nano": origin,
        "receiver": {
            "name": "agency-identity-receiver",
            "version": "2.1.0",
            "artifact_sha256": "a" * 64,
        },
        "records": records,
        "limitations": list(EXPORT_LIMITATIONS),
    }
    return plan, run, export


def test_body_free_identity_otel_projection_reconstructs_evaluable_run():
    plan, expected_run, export = _otel_export()
    assert validate_identity_otel_log_export(export, plan) == export
    projection = project_identity_otel_run(plan, export, run_id=expected_run["run_id"])
    assert validate_identity_otel_projection(projection) == projection
    assert projection["run"] == expected_run
    reversed_export = json.loads(json.dumps(export))
    reversed_export["records"].reverse()
    reordered = project_identity_otel_run(plan, reversed_export, run_id=expected_run["run_id"])
    assert reordered["run"] == expected_run
    assert reordered["inputs"]["otel_log_export_sha256"] != projection["inputs"][
        "otel_log_export_sha256"
    ]
    assert projection["privacy"]["body_accepted"] is False
    assert projection["privacy"]["spiffe_ids_accepted_in_records"] is False
    assert projection["clock_boundary"]["observed_timestamp_used_for_benchmark_timing"] is False
    assert evaluate_identity_run(plan, projection["run"])["summary"]["verdict"] == "pass"

    registry = _schema_registry()
    for filename, value in (
        ("lureidentity-otel-log-export-v1.schema.json", export),
        ("lureidentity-otel-projection-v1.schema.json", projection),
    ):
        schema = json.loads((ROOT / "spec" / filename).read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator(
            schema,
            registry=registry,
            format_checker=jsonschema.FormatChecker(),
        ).validate(value)


def test_identity_otel_fails_closed_on_body_pii_context_and_time_rebinding():
    plan, run, export = _otel_export()
    body = json.loads(json.dumps(export))
    body["records"][0]["Body"] = "must never be accepted"
    with pytest.raises(ValueError, match="must contain exactly"):
        validate_identity_otel_log_export(body, plan)

    pii = json.loads(json.dumps(export))
    pii["records"][0]["Attributes"]["enduser.id"] = "person@example.gov"
    with pytest.raises(ValueError, match="must contain exactly"):
        validate_identity_otel_log_export(pii, plan)

    duplicate_context = json.loads(json.dumps(export))
    duplicate_context["records"][1]["TraceId"] = duplicate_context["records"][0]["TraceId"]
    duplicate_context["records"][1]["SpanId"] = duplicate_context["records"][0]["SpanId"]
    with pytest.raises(ValueError, match="duplicate trace/span"):
        validate_identity_otel_log_export(duplicate_context, plan)

    access = json.loads(json.dumps(export))
    first_access = next(item for item in access["records"] if item["EventName"] == ACCESS_EVENT)
    first_access["Timestamp"] += 1_000_000
    with pytest.raises(ValueError, match="planned probe"):
        validate_identity_otel_log_export(access, plan)

    projection = project_identity_otel_run(plan, export, run_id=run["run_id"])
    projection["inputs"]["otel_log_export_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="independently recompute"):
        validate_identity_otel_projection(projection)


def test_observed_timestamp_is_bound_but_never_used_for_benchmark_timing():
    plan, run, export = _otel_export()
    first = project_identity_otel_run(plan, export, run_id=run["run_id"])
    changed = json.loads(json.dumps(export))
    changed["records"][0]["ObservedTimestamp"] += 5_000_000
    second = project_identity_otel_run(plan, changed, run_id=run["run_id"])
    assert second["run"] == first["run"]
    assert (
        second["inputs"]["otel_log_export_sha256"]
        != first["inputs"]["otel_log_export_sha256"]
    )


def test_identity_otel_cli_writes_private_bound_projection_and_run(tmp_path: Path):
    plan, run, export = _otel_export()
    plan_path = tmp_path / "plan.json"
    logs_path = tmp_path / "otel-logs.json"
    projection_path = tmp_path / "projection.json"
    run_path = tmp_path / "run.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    logs_path.write_text(json.dumps(export), encoding="utf-8")
    command = [
        "identity-otel-project",
        "--plan",
        str(plan_path),
        "--logs",
        str(logs_path),
        "--run-id",
        run["run_id"],
        "--out",
        str(projection_path),
        "--run-out",
        str(run_path),
    ]
    assert main(command) == 0
    written = json.loads(run_path.read_text(encoding="utf-8"))
    assert evaluate_identity_run(plan, written)["summary"]["verdict"] == "pass"
    assert main(["identity-otel-verify", str(projection_path)]) == 0
    assert main(command) == 2
    if os.name == "posix":
        assert projection_path.stat().st_mode & 0o777 == 0o600
        assert run_path.stat().st_mode & 0o777 == 0o600
