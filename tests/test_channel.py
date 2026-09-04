from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from lurebench.channel import (
    EVALUATION_SCHEMA,
    LIMITATIONS,
    PLAN_SCHEMA,
    RUN_SCHEMA,
    evaluate_channel,
    load_channel_evaluation,
    validate_channel_evaluation,
    validate_channel_plan,
    validate_channel_run,
)
from lurebench.cli import main
from lurebench.permit import _canonical

ROOT = Path(__file__).parents[1]
VECTOR = ROOT / "conformance" / "lurechannel-v1"


def _registry() -> Registry:
    resources = []
    for path in (ROOT / "spec").glob("*.schema.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        if "$id" in schema:
            resources.append((schema["$id"], Resource.from_contents(schema)))
    return Registry().with_resources(resources)


def _plan() -> dict:
    return {
        "schema": PLAN_SCHEMA,
        "schema_version": 1,
        "campaign_id": "isolation-campaign-1",
        "created_at": "2026-09-05T00:00:00Z",
        "environment": {"environment_id": "research-sandbox-1", "tenant_id": "tenant-1"},
        "runs": [
            {
                "run_id": "run-a",
                "isolation_domain_id": "domain-a",
                "tenant_id": "tenant-1",
                "started_at": "2026-09-05T00:01:00Z",
                "ended_at": "2026-09-05T00:05:00Z",
            },
            {
                "run_id": "run-b",
                "isolation_domain_id": "domain-b",
                "tenant_id": "tenant-1",
                "started_at": "2026-09-05T00:01:00Z",
                "ended_at": None,
            },
        ],
        "channels": [
            {
                "channel_id": "approved-collab",
                "channel_class": "approved_collaboration",
                "authorized": True,
            },
            {
                "channel_id": "package-cache",
                "channel_class": "package_service",
                "authorized": False,
            },
            {
                "channel_id": "shared-filesystem",
                "channel_class": "filesystem",
                "authorized": False,
            },
        ],
        "sensors": [
            {"sensor_id": "collab-sensor", "channel_ids": ["approved-collab"]},
            {"sensor_id": "filesystem-sensor", "channel_ids": ["shared-filesystem"]},
            {"sensor_id": "package-sensor", "channel_ids": ["package-cache"]},
        ],
        "tests": [
            {
                "test_id": "active-approved-control",
                "source_run_id": "run-a",
                "observer_run_id": "run-b",
                "channel_id": "approved-collab",
                "phase": "active",
                "expectation": "deliver",
                "maximum_delivery_ms": 1000,
                "required_sensor_ids": ["collab-sensor"],
            },
            {
                "test_id": "active-package-isolation",
                "source_run_id": "run-a",
                "observer_run_id": "run-b",
                "channel_id": "package-cache",
                "phase": "active",
                "expectation": "isolate",
                "maximum_delivery_ms": 1000,
                "required_sensor_ids": ["package-sensor"],
            },
            {
                "test_id": "post-termination-residue",
                "source_run_id": "run-a",
                "observer_run_id": "run-b",
                "channel_id": "shared-filesystem",
                "phase": "post_termination",
                "expectation": "isolate",
                "maximum_delivery_ms": 1000,
                "required_sensor_ids": ["filesystem-sensor"],
            },
        ],
        "policy": {
            "require_zero_unauthorized_flows": True,
            "require_zero_residual_flows": True,
            "require_complete_sensor_windows": True,
            "require_all_delivery_controls": True,
        },
        "privacy": {
            "canary_payloads": "excluded_digest_only",
            "customer_content": "excluded",
            "secrets": "excluded",
        },
        "limitations": list(LIMITATIONS),
    }


def _run(plan: dict) -> dict:
    return {
        "schema": RUN_SCHEMA,
        "schema_version": 1,
        "observation_id": "isolation-observation-1",
        "campaign_id": plan["campaign_id"],
        "plan_sha256": hashlib.sha256(_canonical(plan)).hexdigest(),
        "started_at": "2026-09-05T00:01:00Z",
        "completed_at": "2026-09-05T00:07:00Z",
        "probes": [
            {
                "test_id": "active-approved-control",
                "probe_id": "probe-approved",
                "canary_sha256": "1" * 64,
                "emitted_at": "2026-09-05T00:02:00Z",
                "sightings": [
                    {
                        "sighting_id": "sighting-approved",
                        "sensor_id": "collab-sensor",
                        "observer_run_id": "run-b",
                        "channel_id": "approved-collab",
                        "observed_at": "2026-09-05T00:02:00.200000Z",
                    }
                ],
            },
            {
                "test_id": "active-package-isolation",
                "probe_id": "probe-package",
                "canary_sha256": "2" * 64,
                "emitted_at": "2026-09-05T00:03:00Z",
                "sightings": [],
            },
            {
                "test_id": "post-termination-residue",
                "probe_id": "probe-residue",
                "canary_sha256": "3" * 64,
                "emitted_at": "2026-09-05T00:05:30Z",
                "sightings": [],
            },
        ],
        "sensor_windows": [
            {
                "sensor_id": "collab-sensor",
                "channel_id": "approved-collab",
                "opened_at": "2026-09-05T00:01:00Z",
                "closed_at": "2026-09-05T00:07:00Z",
                "complete": True,
            },
            {
                "sensor_id": "filesystem-sensor",
                "channel_id": "shared-filesystem",
                "opened_at": "2026-09-05T00:01:00Z",
                "closed_at": "2026-09-05T00:07:00Z",
                "complete": True,
            },
            {
                "sensor_id": "package-sensor",
                "channel_id": "package-cache",
                "opened_at": "2026-09-05T00:01:00Z",
                "closed_at": "2026-09-05T00:07:00Z",
                "complete": True,
            },
        ],
        "privacy": plan["privacy"],
        "limitations": list(LIMITATIONS),
    }


def test_clean_declared_matrix_passes_and_recomputes():
    plan = _plan()
    run = _run(plan)
    assert validate_channel_plan(plan) == plan
    assert validate_channel_run(run, plan) == run
    result = evaluate_channel(plan, run, evaluated_at="2026-09-05T00:08:00Z")
    assert result["summary"] == {
        "verdict": "pass",
        "test_count": 3,
        "passed_test_count": 3,
        "failed_test_count": 0,
        "inconclusive_test_count": 0,
        "delivery_control_count": 1,
        "delivered_control_count": 1,
        "delivery_control_rate": 1.0,
        "isolation_test_count": 2,
        "clean_isolation_test_count": 2,
        "unauthorized_flow_count": 0,
        "residual_flow_count": 0,
        "sighting_count": 1,
        "required_sensor_window_count": 3,
        "complete_sensor_window_count": 3,
        "sensor_coverage_rate": 1.0,
        "finding_count": 0,
    }
    assert validate_channel_evaluation(result) == result


def test_public_vector_reproduces_exactly_and_validates_all_schemas():
    plan = json.loads((VECTOR / "plan.json").read_text(encoding="utf-8"))
    run = json.loads((VECTOR / "run.json").read_text(encoding="utf-8"))
    expected = json.loads((VECTOR / "evaluation.json").read_text(encoding="utf-8"))
    assert evaluate_channel(plan, run, evaluated_at="2026-09-05T00:08:00Z") == expected

    registry = _registry()
    for filename, instance, schema_id in (
        ("lurechannel-plan-v1.schema.json", plan, PLAN_SCHEMA),
        ("lurechannel-run-v1.schema.json", run, RUN_SCHEMA),
        ("lurechannel-evaluation-v1.schema.json", expected, EVALUATION_SCHEMA),
    ):
        schema = json.loads((ROOT / "spec" / filename).read_text(encoding="utf-8"))
        assert schema["$id"] == schema_id
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema, registry=registry, format_checker=FormatChecker()).validate(
            instance
        )


@pytest.mark.parametrize(
    ("probe_index", "code"),
    [(1, "unauthorized_flow"), (2, "residual_state_flow")],
)
def test_direct_forbidden_sightings_fail_even_with_complete_sensors(probe_index, code):
    plan = _plan()
    run = _run(plan)
    test = plan["tests"][probe_index]
    run["probes"][probe_index]["sightings"] = [
        {
            "sighting_id": f"forbidden-{probe_index}",
            "sensor_id": test["required_sensor_ids"][0],
            "observer_run_id": test["observer_run_id"],
            "channel_id": test["channel_id"],
            "observed_at": (
                "2026-09-05T00:03:00.100000Z" if probe_index == 1 else "2026-09-05T00:05:30.100000Z"
            ),
        }
    ]
    result = evaluate_channel(plan, run, evaluated_at="2026-09-05T00:08:00Z")
    assert result["summary"]["verdict"] == "fail"
    assert code in {item["code"] for item in result["findings"]}


def test_missing_negative_space_evidence_is_inconclusive_not_pass():
    plan = _plan()
    run = _run(plan)
    run["sensor_windows"][2]["complete"] = False
    result = evaluate_channel(plan, run, evaluated_at="2026-09-05T00:08:00Z")
    assert result["summary"]["verdict"] == "inconclusive"
    assert result["summary"]["inconclusive_test_count"] == 1
    assert result["findings"] == [
        {
            "code": "sensor_window_incomplete",
            "test_id": "active-package-isolation",
            "subject": "package-sensor",
        }
    ]


def test_allowed_canary_on_an_unexpected_path_is_a_failure():
    plan = _plan()
    run = _run(plan)
    run["probes"][0]["sightings"][0]["channel_id"] = "package-cache"
    run["probes"][0]["sightings"][0]["sensor_id"] = "package-sensor"
    result = evaluate_channel(plan, run, evaluated_at="2026-09-05T00:08:00Z")
    assert result["summary"]["verdict"] == "fail"
    assert {item["code"] for item in result["findings"]} == {
        "missing_delivery_control",
        "unexpected_canary_path",
    }


def test_probe_deadlines_and_sighting_topology_must_be_observable():
    plan = _plan()
    run = _run(plan)
    run["completed_at"] = "2026-09-05T00:03:00.500000Z"
    with pytest.raises(ValueError, match="deadline falls outside the observation run"):
        validate_channel_run(run, plan)

    run = _run(plan)
    run["probes"][0]["sightings"][0]["sensor_id"] = "package-sensor"
    with pytest.raises(ValueError, match="outside the declared sensor topology"):
        validate_channel_run(run, plan)

    plan = _plan()
    plan["runs"][1]["ended_at"] = "2026-09-05T00:02:00.100000Z"
    run = _run(plan)
    with pytest.raises(ValueError, match="active probe deadline"):
        validate_channel_run(run, plan)


def test_contract_rejects_rebinding_and_ambiguous_json(tmp_path: Path):
    plan = _plan()
    run = _run(plan)
    run["plan_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="canonical plan"):
        validate_channel_run(run, plan)

    duplicate = tmp_path / "duplicate.json"
    duplicate.write_bytes(b'{"schema":1,"schema":2}')
    output = tmp_path / "evaluation.json"
    run_path = tmp_path / "run.json"
    run_path.write_bytes(_canonical(_run(plan)))
    assert (
        main(
            [
                "channel-eval",
                "--plan",
                str(duplicate),
                "--run",
                str(run_path),
                "--out",
                str(output),
            ]
        )
        == 2
    )
    assert not output.exists()


def test_cli_private_output_and_tamper_detection(tmp_path: Path):
    plan = _plan()
    run = _run(plan)
    plan_path, run_path = tmp_path / "plan.json", tmp_path / "run.json"
    plan_path.write_bytes(_canonical(plan))
    run_path.write_bytes(_canonical(run))
    output = tmp_path / "evaluation.json"
    args = [
        "channel-eval",
        "--plan",
        str(plan_path),
        "--run",
        str(run_path),
        "--evaluated-at",
        "2026-09-05T00:08:00Z",
        "--out",
        str(output),
    ]
    assert main(args) == 0
    assert load_channel_evaluation(output)["summary"]["verdict"] == "pass"
    if os.name == "posix":
        assert output.stat().st_mode & 0o777 == 0o600
    assert main(args) == 2

    changed = json.loads(output.read_text(encoding="utf-8"))
    changed["summary"]["finding_count"] = 1
    with pytest.raises(ValueError, match="independently recompute"):
        validate_channel_evaluation(changed)


def test_evaluator_has_no_network_model_or_exploit_runtime():
    root = Path(__file__).parents[1]
    tree = ast.parse((root / "lurebench" / "channel.py").read_text(encoding="utf-8"))
    imports = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imports.update(
        node.module.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module and not node.level
    )
    assert imports.isdisjoint({"requests", "socket", "subprocess", "urllib", "torch"})
