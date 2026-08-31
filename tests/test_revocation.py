from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from lurebench.cli import main
from lurebench.revocation import (
    default_revocation_plan,
    evaluate_revocation_run,
    reference_revocation_run,
    validate_revocation_evaluation,
    validate_revocation_plan,
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


def test_reference_revocation_campaign_matches_public_contracts():
    plan = default_revocation_plan()
    run = reference_revocation_run(plan, generated_at="2026-08-30T12:00:00Z")
    report = evaluate_revocation_run(plan, run, generated_at="2026-08-30T12:01:00Z")

    _schema("lurerevoke-plan-v1.schema.json", plan)
    _schema("lurerevoke-run-v1.schema.json", run)
    _schema("lurerevoke-evaluation-v1.schema.json", report)
    assert validate_revocation_evaluation(report) == report
    assert report["summary"] == {
        "event_count": 4,
        "node_count": 4,
        "required_delivery_count": 16,
        "applied_delivery_count": 16,
        "delivery_coverage_rate": 1.0,
        "maximum_convergence_ms": 400,
        "p95_convergence_ms": 400,
        "deadline_miss_count": 0,
        "post_deadline_allow_count": 0,
        "collateral_block_count": 0,
        "revoked_block_recall": 1.0,
        "pre_event_allow_rate": 1.0,
        "signal_disposition_accuracy": 1.0,
        "incorrect_decision_count": 0,
        "incorrect_reason_count": 0,
        "verdict": "pass",
    }
    assert len(report["probe_results"]) == 64


def test_revocation_evaluator_detects_bypass_missing_delivery_and_collateral_denial():
    plan = default_revocation_plan()
    run = reference_revocation_run(plan)

    bypass = json.loads(json.dumps(run))
    after = next(
        item for item in bypass["access_observations"] if item["probe_id"].endswith("-after")
    )
    after["decision"] = "allow"
    report = evaluate_revocation_run(plan, bypass)
    assert report["summary"]["verdict"] == "fail"
    assert report["summary"]["post_deadline_allow_count"] == 1
    assert report["summary"]["incorrect_decision_count"] == 1

    missing = json.loads(json.dumps(run))
    missing["signal_observations"] = [
        item
        for item in missing["signal_observations"]
        if not (item["event_id"] == "revocation-1" and item["node_id"] == "backup-policy")
    ]
    report = evaluate_revocation_run(plan, missing)
    assert report["summary"]["delivery_coverage_rate"] == 15 / 16
    assert report["summary"]["deadline_miss_count"] == 1
    assert report["summary"]["verdict"] == "fail"

    collateral = json.loads(json.dumps(run))
    unrelated = next(
        item
        for item in collateral["access_observations"]
        if item["probe_id"].endswith("-unrelated")
    )
    unrelated["decision"] = "block"
    report = evaluate_revocation_run(plan, collateral)
    assert report["summary"]["collateral_block_count"] == 1
    assert report["summary"]["verdict"] == "fail"


def test_revocation_signal_integrity_and_disposition_are_independently_checked():
    plan = default_revocation_plan()
    changed_plan = json.loads(json.dumps(plan))
    changed_plan["events"][0]["subject"]["id"] = "substituted-subject"
    with pytest.raises(ValueError, match="signal digest does not reconcile"):
        validate_revocation_plan(changed_plan)

    changed_plan = json.loads(json.dumps(plan))
    changed_plan["events"][0]["attenuation_reason"] = "risk_increased"
    with pytest.raises(ValueError, match="type and attenuation reason"):
        validate_revocation_plan(changed_plan)

    changed_plan = json.loads(json.dumps(plan))
    unrelated_probe = next(
        item
        for item in changed_plan["probes"]
        if item["event_id"] == "revocation-1" and item["probe_id"].endswith("-unrelated")
    )
    unrelated_probe["subject_id"] = changed_plan["events"][1]["subject"]["id"]
    with pytest.raises(ValueError, match="another campaign event"):
        validate_revocation_plan(changed_plan)

    run = reference_revocation_run(plan)
    wrong_disposition = json.loads(json.dumps(run))
    invalid = next(
        item
        for item in wrong_disposition["signal_observations"]
        if item["observation_id"].endswith("-invalid")
    )
    invalid["disposition"] = "applied"
    report = evaluate_revocation_run(plan, wrong_disposition)
    assert report["summary"]["signal_disposition_accuracy"] < 1.0
    assert report["summary"]["verdict"] == "fail"

    tampered_report = json.loads(json.dumps(evaluate_revocation_run(plan, run)))
    tampered_report["summary"]["p95_convergence_ms"] = 1
    with pytest.raises(ValueError, match="independently recompute"):
        validate_revocation_evaluation(tampered_report)


def test_revocation_cli_writes_private_non_overwriting_artifacts(tmp_path: Path, capsys):
    plan = tmp_path / "plan.json"
    run = tmp_path / "run.json"
    report = tmp_path / "evaluation.json"
    assert main(["revocation-export", "--out", str(plan)]) == 0
    assert main(["revocation-run", "--plan", str(plan), "--out", str(run)]) == 0
    assert (
        main(
            [
                "revocation-eval",
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
    assert "LUREREVOKE: PASS" in capsys.readouterr().out
    if os.name == "posix":
        assert all(path.stat().st_mode & 0o777 == 0o600 for path in (plan, run, report))
    original = report.read_bytes()
    assert main(["revocation-eval", "--out", str(report)]) == 2
    assert report.read_bytes() == original
