from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from lurebench.cli import main
from lurebench.identity import (
    default_identity_plan,
    evaluate_identity_run,
    reference_identity_run,
    validate_identity_evaluation,
    validate_identity_plan,
    validate_identity_run,
)
from lurebench.identity_adapters import (
    SCIM_CHANGE_SCHEMA,
    SCIM_PROFILE,
    project_verified_scim_change,
)

ROOT = Path(__file__).parents[1]


def _registry() -> Registry:
    resources = []
    for path in (ROOT / "spec").glob("*.schema.json"):
        value = json.loads(path.read_text(encoding="utf-8"))
        if "$id" in value:
            resources.append((value["$id"], Resource.from_contents(value)))
    return Registry().with_resources(resources)


def _schema(filename: str, value: dict) -> None:
    schema = json.loads((ROOT / "spec" / filename).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, registry=_registry(), format_checker=FormatChecker()).validate(
        value
    )


def test_reference_identity_closure_matches_public_contracts():
    plan = default_identity_plan()
    run = reference_identity_run(plan, generated_at="2026-09-03T12:00:00Z")
    report = evaluate_identity_run(plan, run, generated_at="2026-09-03T12:01:00Z")

    _schema("lureidentity-plan-v1.schema.json", plan)
    _schema("lureidentity-run-v1.schema.json", run)
    _schema("lureidentity-evaluation-v1.schema.json", report)
    assert validate_identity_evaluation(report) == report
    assert report["summary"] == {
        "principal_count": 7,
        "authority_edge_count": 6,
        "grant_count": 1,
        "event_count": 4,
        "node_count": 9,
        "affected_authorization_count": 9,
        "required_delivery_count": 36,
        "applied_delivery_count": 36,
        "delivery_coverage_rate": 1.0,
        "maximum_convergence_ms": 450,
        "p95_convergence_ms": 450,
        "deadline_miss_count": 0,
        "post_deadline_stale_allow_count": 0,
        "collateral_block_count": 0,
        "cut_recall": 1.0,
        "pre_event_allow_rate": 1.0,
        "preserved_allow_rate": 1.0,
        "signal_disposition_accuracy": 1.0,
        "incorrect_decision_count": 0,
        "incorrect_reason_count": 0,
        "verdict": "pass",
    }
    assert [item["affected_authorization_count"] for item in report["event_results"]] == [
        3,
        3,
        2,
        1,
    ]
    assert len(plan["probes"]) == 279


def test_identity_plan_rejects_alternate_authority_cycles_and_probe_gaps():
    alternate = json.loads(json.dumps(default_identity_plan()))
    alternate["authority_edges"].append(
        {
            "edge_id": "alternate-alpha",
            "source_id": "human-bob",
            "target_id": "agent-alpha",
            "relationship": "delegates_to",
        }
    )
    with pytest.raises(ValueError, match="exactly cover"):
        validate_identity_plan(alternate)

    cyclic = json.loads(json.dumps(default_identity_plan()))
    cyclic["authority_edges"].extend(
        [
            {
                "edge_id": "agent-alpha-beta",
                "source_id": "agent-alpha",
                "target_id": "agent-beta",
                "relationship": "delegates_to",
            },
            {
                "edge_id": "agent-beta-alpha",
                "source_id": "agent-beta",
                "target_id": "agent-alpha",
                "relationship": "delegates_to",
            },
        ]
    )
    with pytest.raises(ValueError, match="acyclic"):
        validate_identity_plan(cyclic)

    missing = json.loads(json.dumps(default_identity_plan()))
    missing["probes"] = [
        probe
        for probe in missing["probes"]
        if probe["probe_id"]
        != "identity-1-identity-approval-gateway-human-alice-after"
    ]
    with pytest.raises(ValueError, match="probe every required cut after"):
        validate_identity_plan(missing)


def test_identity_plan_rejects_type_confusion_digest_tampering_and_bad_spiffe_id():
    plan = json.loads(json.dumps(default_identity_plan()))
    plan["authority_edges"][0]["relationship"] = "runs_as"
    with pytest.raises(ValueError, match="incompatible principal kinds"):
        validate_identity_plan(plan)

    plan = json.loads(json.dumps(default_identity_plan()))
    plan["events"][0]["required_cut_actor_ids"].remove("agent-alpha")
    with pytest.raises(ValueError, match="event digest does not reconcile"):
        validate_identity_plan(plan)

    plan = json.loads(json.dumps(default_identity_plan()))
    workload = next(item for item in plan["principals"] if item["kind"] == "workload")
    workload["spiffe_id"] = "https://not-spiffe.invalid/workload"
    with pytest.raises(ValueError, match="canonical SPIFFE ID"):
        validate_identity_plan(plan)


def test_identity_evaluator_detects_stale_authority_missing_delivery_and_collateral_denial():
    plan = default_identity_plan()
    run = reference_identity_run(plan)

    stale = json.loads(json.dumps(run))
    after = next(
        item
        for item in stale["access_observations"]
        if item["probe_id"].endswith("workload-alpha-after")
    )
    after["decision"] = "allow"
    report = evaluate_identity_run(plan, stale)
    assert report["summary"]["post_deadline_stale_allow_count"] == 1
    assert report["summary"]["cut_recall"] < 1.0
    assert report["summary"]["verdict"] == "fail"

    missing = json.loads(json.dumps(run))
    missing["event_observations"] = [
        item
        for item in missing["event_observations"]
        if not (
            item["event_id"] == "identity-1"
            and item["node_id"] == "identity-approval-gateway"
        )
    ]
    report = evaluate_identity_run(plan, missing)
    assert report["summary"]["delivery_coverage_rate"] == 35 / 36
    assert report["summary"]["deadline_miss_count"] == 1
    assert report["summary"]["verdict"] == "fail"

    collateral = json.loads(json.dumps(run))
    control = next(
        item for item in collateral["access_observations"] if item["probe_id"].endswith("-control")
    )
    control["decision"] = "block"
    report = evaluate_identity_run(plan, collateral)
    assert report["summary"]["collateral_block_count"] == 1
    assert report["summary"]["preserved_allow_rate"] < 1.0
    assert report["summary"]["verdict"] == "fail"


def test_identity_signal_dispositions_and_report_are_independently_recomputed():
    plan = default_identity_plan()
    run = reference_identity_run(plan)

    changed = json.loads(json.dumps(run))
    invalid = next(
        item for item in changed["event_observations"] if item["observation_id"].endswith("invalid")
    )
    invalid["disposition"] = "applied"
    report = evaluate_identity_run(plan, changed)
    assert report["summary"]["signal_disposition_accuracy"] < 1.0
    assert report["summary"]["verdict"] == "fail"

    changed = json.loads(json.dumps(run))
    changed["plan_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="plan digest does not reconcile"):
        validate_identity_run(changed, plan)

    tampered = json.loads(json.dumps(evaluate_identity_run(plan, run)))
    tampered["event_results"][0]["affected_authorization_count"] = 1
    with pytest.raises(ValueError, match="independently recompute"):
        validate_identity_evaluation(tampered)


def _verified_scim_change(change: dict) -> dict:
    return {
        "schema": SCIM_CHANGE_SCHEMA,
        "schema_version": 1,
        "profile": SCIM_PROFILE,
        "issuer_id": "synthetic-directory",
        "tenant_id": "tenant-a",
        "verification": {
            "transport_authenticated": True,
            "issuer_authorized": True,
            "operation_authorized": True,
            "schema_validated": True,
        },
        "source_event_sha256": "1" * 64,
        "change": change,
    }


def test_verified_scim_projection_is_strict_bound_and_plan_compatible():
    plan = default_identity_plan()
    source = _verified_scim_change(
        {
            "resource_type": "User",
            "resource_id": "human-alice",
            "attribute": "active",
            "operation": "replace",
            "value": False,
        }
    )
    _schema("lureidentity-scim-change-v1.schema.json", source)
    projected = project_verified_scim_change(
        source,
        directory=plan["directory"],
        authority_edges=plan["authority_edges"],
        event_id="identity-1",
        sequence=1,
        occurred_at_ms=10_000,
        required_cut_actor_ids=["human-alice", "agent-alpha", "workload-alpha"],
        required_preserve_actor_ids=["workload-beta"],
    )
    assert projected["event_type"] == "scim_user_deactivated"
    assert projected["target_principal_id"] == "human-alice"
    assert projected["source_event_sha256"] == "1" * 64
    changed = json.loads(json.dumps(plan))
    changed["events"][0] = projected
    assert validate_identity_plan(changed) == changed

    membership = _verified_scim_change(
        {
            "resource_type": "Group",
            "resource_id": "group-ops",
            "attribute": "members",
            "operation": "remove",
            "value": "human-alice",
        }
    )
    projected = project_verified_scim_change(
        membership,
        directory=plan["directory"],
        authority_edges=plan["authority_edges"],
        event_id="identity-2",
        sequence=2,
        occurred_at_ms=20_000,
        required_cut_actor_ids=["human-alice", "agent-alpha", "workload-alpha"],
        required_preserve_actor_ids=["workload-beta"],
    )
    assert projected["target_edge_id"] == "membership-alice"


def test_verified_scim_projection_rejects_untrusted_ambiguous_or_unsupported_changes():
    plan = default_identity_plan()
    source = _verified_scim_change(
        {
            "resource_type": "User",
            "resource_id": "human-alice",
            "attribute": "active",
            "operation": "replace",
            "value": False,
        }
    )
    kwargs = {
        "directory": plan["directory"],
        "authority_edges": plan["authority_edges"],
        "event_id": "projected-event",
        "sequence": 1,
        "occurred_at_ms": 1_000,
        "required_cut_actor_ids": ["human-alice", "agent-alpha", "workload-alpha"],
        "required_preserve_actor_ids": ["workload-beta"],
    }
    untrusted = json.loads(json.dumps(source))
    untrusted["verification"]["operation_authorized"] = False
    with pytest.raises(ValueError, match="every external verification"):
        project_verified_scim_change(untrusted, **kwargs)

    wrong_tenant = json.loads(json.dumps(source))
    wrong_tenant["tenant_id"] = "tenant-b"
    with pytest.raises(ValueError, match="issuer or tenant"):
        project_verified_scim_change(wrong_tenant, **kwargs)

    activation = json.loads(json.dumps(source))
    activation["change"]["value"] = True
    with pytest.raises(ValueError, match="not a supported"):
        project_verified_scim_change(activation, **kwargs)

    group = _verified_scim_change(
        {
            "resource_type": "Group",
            "resource_id": "group-ops",
            "attribute": "members",
            "operation": "remove",
            "value": "missing-human",
        }
    )
    with pytest.raises(ValueError, match="exactly one membership"):
        project_verified_scim_change(group, **kwargs)


def test_identity_cli_writes_private_non_overwriting_artifacts(tmp_path: Path, capsys):
    plan = tmp_path / "plan.json"
    run = tmp_path / "run.json"
    report = tmp_path / "evaluation.json"
    assert main(["identity-export", "--out", str(plan)]) == 0
    assert main(["identity-run", "--plan", str(plan), "--out", str(run)]) == 0
    assert (
        main(
            [
                "identity-eval",
                "--plan",
                str(plan),
                "--run",
                str(run),
                "--out",
                str(report),
            ]
        )
        == 0
    )
    assert "LUREIDENTITY: PASS" in capsys.readouterr().out
    if os.name == "posix":
        assert all(path.stat().st_mode & 0o777 == 0o600 for path in (plan, run, report))
    original = report.read_bytes()
    assert main(["identity-eval", "--out", str(report)]) == 2
    assert report.read_bytes() == original
