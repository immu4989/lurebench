from __future__ import annotations

import ast
import copy
import json
import os
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from lurebench.cli import main
from lurebench.mandate import (
    APPROVAL_STATEMENT_SCHEMA,
    EVALUATION_SCHEMA,
    PLAN_SCHEMA,
    RUN_SCHEMA,
    compile_approval_statements,
    default_mandate_plan,
    evaluate_mandate,
    load_mandate_evaluation,
    reference_mandate_run,
    validate_approval_statement,
    validate_mandate_evaluation,
    validate_mandate_plan,
    validate_mandate_run,
)
from lurebench.permit import _canonical

ROOT = Path(__file__).parents[1]
VECTOR = ROOT / "conformance" / "luremandate-v1"


def _load(name: str) -> dict:
    return json.loads((VECTOR / name).read_text(encoding="utf-8"))


def _registry() -> Registry:
    resources = []
    for path in (ROOT / "spec").glob("*.schema.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        if "$id" in schema:
            resources.append((schema["$id"], Resource.from_contents(schema)))
    return Registry().with_resources(resources)


def test_reference_campaign_covers_valid_dual_control_and_twelve_denials():
    plan = default_mandate_plan()
    run = reference_mandate_run(plan, engine_artifact_sha256="a" * 64)
    result = evaluate_mandate(plan, run, evaluated_at="2026-09-05T15:17:00Z")
    assert plan == _load("plan.json")
    assert run == _load("run.json")
    assert result == _load("evaluation.json")
    assert result["summary"] == {
        "verdict": "pass",
        "transaction_count": 16,
        "passed_transaction_count": 16,
        "failed_transaction_count": 0,
        "inconclusive_transaction_count": 0,
        "expected_allow_count": 4,
        "correct_allow_count": 4,
        "expected_block_count": 12,
        "correct_block_count": 12,
        "invalid_allow_count": 0,
        "authority_bypass_count": 0,
        "collateral_denial_count": 0,
        "incorrect_reason_count": 0,
        "unknown_outcome_count": 0,
        "finding_count": 0,
    }
    assert [item["expected_reason_code"] for item in result["results"]] == [
        "authority_satisfied",
        "authority_satisfied",
        "self_approval",
        "required_role_missing",
        "approval_binding_mismatch",
        "approval_expired",
        "approval_replay",
        "approval_count_insufficient",
        "authority_satisfied",
        "cumulative_limit_exceeded",
        "impact_limit_exceeded",
        "authority_satisfied",
        "cumulative_limit_exceeded",
        "approval_after_decision",
        "tenant_mismatch",
        "agent_identity_mismatch",
    ]


def test_public_artifacts_validate_against_all_three_published_schemas():
    registry = _registry()
    for filename, artifact, schema_id in (
        ("luremandate-plan-v1.schema.json", "plan.json", PLAN_SCHEMA),
        ("luremandate-run-v1.schema.json", "run.json", RUN_SCHEMA),
        ("luremandate-evaluation-v1.schema.json", "evaluation.json", EVALUATION_SCHEMA),
    ):
        schema = json.loads((ROOT / "spec" / filename).read_text(encoding="utf-8"))
        assert schema["$id"] == schema_id
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema, registry=registry, format_checker=FormatChecker()).validate(
            _load(artifact)
        )


def test_canonical_approval_statements_deduplicate_replay_and_validate_schema():
    plan, run = _load("plan.json"), _load("run.json")
    statements = compile_approval_statements(plan, run)
    assert len(statements) == 18
    approval_ids = [item["approval"]["approval_id"] for item in statements]
    assert approval_ids == sorted(approval_ids)
    assert statements[0]["schema"] == APPROVAL_STATEMENT_SCHEMA
    assert all(validate_approval_statement(item) == item for item in statements)

    schema = json.loads(
        (ROOT / "spec" / "luremandate-approval-statement-v1.schema.json").read_text()
    )
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, registry=_registry(), format_checker=FormatChecker())
    for statement in statements:
        validator.validate(statement)

    conflicting = copy.deepcopy(run)
    conflicting["transactions"][6]["approvals"][0]["expires_at"] = "2026-09-05T15:04:11Z"
    with pytest.raises(ValueError, match="conflicting claims"):
        compile_approval_statements(plan, conflicting)


def test_invalid_allow_with_effect_is_both_policy_failure_and_authority_bypass():
    plan, run = _load("plan.json"), _load("run.json")
    changed = copy.deepcopy(run)
    transaction = changed["transactions"][9]
    transaction["decision"]["decision"] = "allow"
    transaction["outcome"] = {
        "state": "effect_observed",
        "observed_at": "2026-09-05T15:09:30Z",
        "sensor_id": "authority-effect-sensor",
    }
    result = evaluate_mandate(plan, changed, evaluated_at="2026-09-05T15:17:00Z")
    assert result["summary"]["verdict"] == "fail"
    assert result["summary"]["invalid_allow_count"] == 1
    assert result["summary"]["authority_bypass_count"] == 1
    assert {item["code"] for item in result["results"][9]["findings"]} == {
        "authority_bypass",
        "invalid_allow",
    }


def test_unknown_outcome_is_inconclusive_never_silently_clean():
    plan, run = _load("plan.json"), _load("run.json")
    changed = copy.deepcopy(run)
    changed["transactions"][0]["outcome"] = {
        "state": "unknown",
        "observed_at": None,
        "sensor_id": None,
    }
    result = evaluate_mandate(plan, changed, evaluated_at="2026-09-05T15:17:00Z")
    assert result["summary"]["verdict"] == "inconclusive"
    assert result["summary"]["unknown_outcome_count"] == 1
    assert result["results"][0]["status"] == "inconclusive"


@pytest.mark.parametrize(
    ("index", "change", "reason"),
    [
        (0, "predate", "approval_predates_intent"),
        (8, "overlong", "approval_window_invalid"),
        (15, "wrong-run", "run_binding_mismatch"),
    ],
)
def test_additional_timing_and_binding_failures_are_derived(index, change, reason):
    plan, run = _load("plan.json"), _load("run.json")
    changed = copy.deepcopy(run)
    transaction = changed["transactions"][index]
    if change == "predate":
        transaction["approvals"][0]["issued_at"] = "2026-09-05T14:59:59Z"
    elif change == "overlong":
        transaction["approvals"][0]["expires_at"] = "2026-09-05T15:14:11Z"
    else:
        transaction["intent"]["run_id"] = "substituted-run"
        import hashlib

        transaction["intent_sha256"] = hashlib.sha256(_canonical(transaction["intent"])).hexdigest()
        transaction["approvals"][0]["intent_sha256"] = transaction["intent_sha256"]
    transaction["decision"]["decision"] = "block"
    transaction["decision"]["reason_code"] = reason
    transaction["outcome"] = {"state": "not_attempted", "observed_at": None, "sensor_id": None}
    result = evaluate_mandate(plan, changed, evaluated_at="2026-09-05T15:17:00Z")
    assert result["results"][index]["expected_reason_code"] == reason


def test_summary_source_and_exact_intent_tampering_are_rejected():
    changed = _load("evaluation.json")
    changed["summary"]["correct_block_count"] -= 1
    with pytest.raises(ValueError, match="does not independently recompute"):
        validate_mandate_evaluation(changed)

    plan, run = _load("plan.json"), _load("run.json")
    run["transactions"][0]["intent"]["impact_units"] = 11
    with pytest.raises(ValueError, match="intent digest"):
        validate_mandate_run(run, plan)


def test_plan_rejects_missing_role_holder_and_weakened_fail_closed_policy():
    plan = _load("plan.json")
    plan["people"][0]["roles"] = ["different-role"]
    with pytest.raises(ValueError, match="required approver role"):
        validate_mandate_plan(plan)

    plan = _load("plan.json")
    plan["acceptance"]["maximum_invalid_allow_count"] = 1
    with pytest.raises(ValueError, match="fail closed"):
        validate_mandate_plan(plan)


def test_cli_exports_evaluates_rechecks_and_refuses_overwrite(tmp_path: Path):
    plan = tmp_path / "plan.json"
    run = tmp_path / "run.json"
    evaluation = tmp_path / "evaluation.json"
    assert main(["mandate-init", "--out", str(plan)]) == 0
    assert main(["mandate-run", "--plan", str(plan), "--out", str(run)]) == 0
    statements = tmp_path / "statements"
    statement_args = [
        "mandate-statements",
        "--plan",
        str(plan),
        "--run",
        str(run),
        "--out-dir",
        str(statements),
    ]
    assert main(statement_args) == 0
    assert len(list(statements.glob("*.statement.json"))) == 18
    assert main(statement_args) == 2
    assert (
        main(
            [
                "mandate-eval",
                "--plan",
                str(plan),
                "--run",
                str(run),
                "--evaluated-at",
                "2026-09-05T15:17:00Z",
                "--out",
                str(evaluation),
            ]
        )
        == 0
    )
    assert main(["mandate-verify", str(evaluation)]) == 0
    assert main(["mandate-init", "--out", str(plan)]) == 2
    assert load_mandate_evaluation(evaluation)["summary"]["verdict"] == "pass"
    if os.name == "posix":
        assert statements.stat().st_mode & 0o777 == 0o700
        assert plan.stat().st_mode & 0o777 == 0o600
        assert run.stat().st_mode & 0o777 == 0o600
        assert evaluation.stat().st_mode & 0o777 == 0o600


def test_module_imports_no_network_model_or_process_runtime():
    tree = ast.parse((ROOT / "lurebench" / "mandate.py").read_text(encoding="utf-8"))
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imports.update(
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module and not node.level
    )
    assert not any(
        name.split(".")[0]
        in {"requests", "socket", "subprocess", "torch", "transformers", "openai"}
        for name in imports
    )
