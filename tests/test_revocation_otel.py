from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import jsonschema
import pytest
from referencing import Registry, Resource

from lurebench.cli import main
from lurebench.revocation import (
    default_revocation_plan,
    evaluate_revocation_run,
    reference_revocation_run,
)
from lurebench.revocation_otel import (
    ACCESS_EVENT,
    EXPORT_LIMITATIONS,
    OTEL_EXPORT_SCHEMA,
    SIGNAL_EVENT,
    project_otel_revocation_run,
    validate_otel_log_export,
    validate_otel_revocation_projection,
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
    plan = default_revocation_plan()
    run = reference_revocation_run(
        plan,
        implementation_name="agency-receiver",
        implementation_version="2.1.0",
        generated_at="2026-08-30T01:00:00Z",
    )
    origin = int(datetime(2026, 8, 30, tzinfo=timezone.utc).timestamp()) * 1_000_000_000
    probe_map = {item["probe_id"]: item for item in plan["probes"]}
    records = []
    for index, observation in enumerate(run["signal_observations"], start=1):
        timestamp = origin + observation["received_at_ms"] * 1_000_000
        records.append(
            {
                "Timestamp": timestamp,
                "ObservedTimestamp": timestamp + 1_000_000,
                "TraceId": f"{index:032x}",
                "SpanId": f"{index:016x}",
                "EventName": SIGNAL_EVENT,
                "Resource": {
                    "service.name": "agency-receiver",
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
                    "service.name": "agency-receiver",
                    "service.instance.id": probe["node_id"],
                    "service.version": "2.1.0",
                },
                "Attributes": dict(observation),
            }
        )
    export = {
        "schema": OTEL_EXPORT_SCHEMA,
        "schema_version": 1,
        "export_id": "agency-revocation-otel-1",
        "generated_at": "2026-08-30T01:00:00Z",
        "time_origin_unix_nano": origin,
        "receiver": {
            "name": "agency-receiver",
            "version": "2.1.0",
            "artifact_sha256": None,
        },
        "records": records,
        "limitations": list(EXPORT_LIMITATIONS),
    }
    return plan, run, export


def test_body_free_otel_projection_reconstructs_exact_evaluable_run():
    plan, expected_run, export = _otel_export()
    assert validate_otel_log_export(export, plan) == export
    projection = project_otel_revocation_run(plan, export, run_id=expected_run["run_id"])
    assert validate_otel_revocation_projection(projection) == projection
    assert projection["run"] | {"access_observations": []} == expected_run | {
        "access_observations": []
    }
    assert sorted(
        projection["run"]["access_observations"], key=lambda item: item["probe_id"]
    ) == sorted(expected_run["access_observations"], key=lambda item: item["probe_id"])
    assert projection["privacy"]["body_accepted"] is False
    assert projection["clock_boundary"]["observed_timestamp_used_for_benchmark_timing"] is False
    assert evaluate_revocation_run(plan, projection["run"])["summary"]["verdict"] == "pass"

    registry = _schema_registry()
    for filename, value in (
        ("lurerevoke-otel-log-export-v1.schema.json", export),
        ("lurerevoke-otel-projection-v1.schema.json", projection),
    ):
        schema = json.loads((ROOT / "spec" / filename).read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator(
            schema,
            registry=registry,
            format_checker=jsonschema.FormatChecker(),
        ).validate(value)


def test_otel_projection_fails_closed_on_body_identity_and_binding_changes():
    plan, run, export = _otel_export()
    body = json.loads(json.dumps(export))
    body["records"][0]["Body"] = "must never be accepted"
    with pytest.raises(ValueError, match="must contain exactly"):
        validate_otel_log_export(body, plan)

    wrong_node = json.loads(json.dumps(export))
    wrong_node["records"][0]["Resource"]["service.instance.id"] = "other-node"
    with pytest.raises(ValueError, match="service instance"):
        validate_otel_log_export(wrong_node, plan)

    projection = project_otel_revocation_run(plan, export, run_id=run["run_id"])
    projection["inputs"]["otel_log_export_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="independently recompute"):
        validate_otel_revocation_projection(projection)


def test_otel_projection_cli_writes_private_bound_projection_and_run(tmp_path: Path):
    plan, run, export = _otel_export()
    plan_path = tmp_path / "plan.json"
    logs_path = tmp_path / "otel-logs.json"
    projection_path = tmp_path / "projection.json"
    run_path = tmp_path / "run.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    logs_path.write_text(json.dumps(export), encoding="utf-8")
    command = [
        "revocation-otel-project",
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
    written_run = json.loads(run_path.read_text(encoding="utf-8"))
    assert written_run | {"access_observations": []} == run | {"access_observations": []}
    assert sorted(written_run["access_observations"], key=lambda item: item["probe_id"]) == sorted(
        run["access_observations"], key=lambda item: item["probe_id"]
    )
    assert main(["revocation-otel-verify", str(projection_path)]) == 0
    assert main(command) == 2
    if os.name == "posix":
        assert projection_path.stat().st_mode & 0o777 == 0o600
        assert run_path.stat().st_mode & 0o777 == 0o600
