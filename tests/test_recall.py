from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from lurebench.cli import main
from lurebench.permit import _canonical
from lurebench.recall import (
    ADVISORY_LIMITATIONS,
    ADVISORY_SCHEMA,
    EVALUATION_SCHEMA,
    LINEAGE_LIMITATIONS,
    LINEAGE_SCHEMA,
    PLAN_SCHEMA,
    RUN_SCHEMA,
    compose_recall_plan,
    evaluate_recall_run,
    reference_recall_run,
    validate_artifact_advisory,
    validate_artifact_lineage,
    validate_recall_evaluation,
    validate_recall_plan,
    validate_recall_run,
)

ROOT = Path(__file__).parents[1]
ARTIFACT_PLAN = ROOT / "conformance" / "lureartifact-v1" / "plan.json"
VECTOR = ROOT / "conformance" / "lurerecall-v1"


def _load_artifact_plan() -> dict:
    return json.loads(ARTIFACT_PLAN.read_text(encoding="utf-8"))


def _digest(value: dict) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _lineage(plan: dict) -> dict:
    kinds = {
        "ai_sbom": "ai_bom",
        "container_image": "container",
        "model_weights": "model",
        "policy_bundle": "policy",
    }
    components = []
    for workload in plan["workloads"]:
        for artifact in workload["artifacts"]:
            components.append(
                {
                    "component_id": f"{artifact['artifact_id']}-root",
                    "kind": kinds[artifact["role"]],
                    "sha256": artifact["sha256"],
                    "package_url": artifact["package_url"],
                    "root": {
                        "workload_principal_id": workload["workload_principal_id"],
                        "artifact_id": artifact["artifact_id"],
                    },
                }
            )
    components.append(
        {
            "component_id": "alpha-base-model",
            "kind": "model",
            "sha256": "9" * 64,
            "package_url": "pkg:huggingface/example/base-model@89abcdef01234567",
            "root": None,
        }
    )
    return {
        "schema": LINEAGE_SCHEMA,
        "schema_version": 1,
        "lineage_id": "artifact-lineage-1",
        "created_at": "2026-09-03T00:09:00Z",
        "artifact_plan_sha256": _digest(plan),
        "components": components,
        "relationships": [
            {
                "dependent_component_id": "alpha-model-root",
                "dependency_component_id": "alpha-base-model",
                "relationship": "fine_tuned_from",
            }
        ],
        "limitations": list(LINEAGE_LIMITATIONS),
    }


def _advisory(plan: dict, lineage: dict) -> dict:
    return {
        "schema": ADVISORY_SCHEMA,
        "schema_version": 1,
        "advisory_id": "artifact-incident-1",
        "issued_at": "2026-09-03T00:10:00Z",
        "issued_at_ms": 1_000,
        "artifact_plan_sha256": _digest(plan),
        "lineage_sha256": _digest(lineage),
        "source": {
            "format": "openvex-0.2.0",
            "document_sha256": "1" * 64,
            "authentication_boundary": "externally_verified_document_metadata",
        },
        "vulnerability": {
            "identifier": "CVE-2026-4989",
            "description_sha256": "2" * 64,
        },
        "statements": [
            {
                "component_id": "alpha-base-model",
                "sha256": "9" * 64,
                "status": "under_investigation",
                "justification": None,
            }
        ],
        "thresholds": {
            "quarantine_deadline_ms": 500,
            "recovery_deadline_ms": 2_000,
        },
        "replacements": [
            {
                "workload_principal_id": "workload-alpha",
                "artifact_id": "alpha-model",
                "replacement_sha256": "8" * 64,
                "provenance_statement_sha256": "3" * 64,
            }
        ],
        "limitations": list(ADVISORY_LIMITATIONS),
    }


def _plan() -> dict:
    artifact_plan = _load_artifact_plan()
    lineage = _lineage(artifact_plan)
    return compose_recall_plan(artifact_plan, lineage, _advisory(artifact_plan, lineage))


def _registry() -> Registry:
    resources = []
    for path in (ROOT / "spec").glob("*.schema.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        if "$id" in schema:
            resources.append((schema["$id"], Resource.from_contents(schema)))
    return Registry().with_resources(resources)


def test_all_lurerecall_artifacts_validate_against_draft_2020_12_schemas():
    artifact_plan = _load_artifact_plan()
    lineage = _lineage(artifact_plan)
    advisory = _advisory(artifact_plan, lineage)
    plan = compose_recall_plan(artifact_plan, lineage, advisory)
    run = reference_recall_run(plan, generated_at="2026-09-03T00:11:00Z")
    evaluation = evaluate_recall_run(plan, run, generated_at="2026-09-03T00:12:00Z")
    instances = [
        ("lureartifact-lineage-v1.schema.json", lineage),
        ("lureartifact-advisory-v1.schema.json", advisory),
        ("lurerecall-plan-v1.schema.json", plan),
        ("lurerecall-run-v1.schema.json", run),
        ("lurerecall-evaluation-v1.schema.json", evaluation),
    ]
    registry = _registry()
    for filename, instance in instances:
        schema = json.loads((ROOT / "spec" / filename).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema, registry=registry, format_checker=FormatChecker()).validate(
            instance
        )


def test_public_vector_recompiles_and_recomputes_exactly():
    artifact_plan = _load_artifact_plan()
    lineage = json.loads((VECTOR / "lineage.json").read_text(encoding="utf-8"))
    advisory = json.loads((VECTOR / "advisory.json").read_text(encoding="utf-8"))
    plan = json.loads((VECTOR / "plan.json").read_text(encoding="utf-8"))
    run = json.loads((VECTOR / "run.json").read_text(encoding="utf-8"))
    evaluation = json.loads((VECTOR / "evaluation.json").read_text(encoding="utf-8"))

    assert validate_artifact_lineage(lineage, artifact_plan) == lineage
    assert validate_artifact_advisory(advisory, artifact_plan, lineage) == advisory
    assert compose_recall_plan(artifact_plan, lineage, advisory) == plan
    assert reference_recall_run(plan, generated_at="2026-09-03T00:11:00Z") == run
    assert evaluate_recall_run(plan, run, generated_at="2026-09-03T00:12:00Z") == evaluation
    assert validate_recall_evaluation(evaluation) == evaluation


def test_transitive_lineage_derives_exact_blast_radius_and_recovery_matrix():
    plan = _plan()
    assert plan["schema"] == PLAN_SCHEMA
    assert plan["impact"] == {
        "actionable_component_ids": ["alpha-base-model"],
        "affected_component_ids": ["alpha-base-model", "alpha-model-root"],
        "affected_root_artifact_count": 1,
        "affected_workload_ids": ["workload-alpha"],
        "affected_node_ids": [
            "identity-credential-broker",
            "identity-policy-gateway",
        ],
    }
    assert len(plan["deployments"]) == 3
    assert sum(item["affected"] for item in plan["deployments"]) == 2
    assert len(plan["probes"]) == 9
    affected = next(item for item in plan["deployments"] if item["affected"])
    assert affected["impact_paths"] == [
        {
            "root_component_id": "alpha-model-root",
            "target_component_id": "alpha-base-model",
            "component_ids": ["alpha-model-root", "alpha-base-model"],
        }
    ]
    assert affected["original_artifact_set_sha256"] != affected["recovered_artifact_set_sha256"]
    assert validate_recall_plan(plan) == plan


def test_lineage_rejects_cycles_orphans_and_incomplete_root_mapping():
    artifact_plan = _load_artifact_plan()
    lineage = _lineage(artifact_plan)
    lineage["relationships"].append(
        {
            "dependent_component_id": "alpha-base-model",
            "dependency_component_id": "alpha-model-root",
            "relationship": "depends_on",
        }
    )
    with pytest.raises(ValueError, match="acyclic"):
        validate_artifact_lineage(lineage, artifact_plan)

    lineage = _lineage(artifact_plan)
    lineage["components"].append(
        {
            "component_id": "orphan-package",
            "kind": "package",
            "sha256": "4" * 64,
            "package_url": "pkg:pypi/orphan@1.0.0",
            "root": None,
        }
    )
    with pytest.raises(ValueError, match="unreachable"):
        validate_artifact_lineage(lineage, artifact_plan)

    lineage = _lineage(artifact_plan)
    lineage["components"].pop(0)
    with pytest.raises(ValueError, match="every artifact-plan root"):
        validate_artifact_lineage(lineage, artifact_plan)


def test_advisory_enforces_vex_state_digest_and_complete_replacement():
    artifact_plan = _load_artifact_plan()
    lineage = _lineage(artifact_plan)
    advisory = _advisory(artifact_plan, lineage)
    assert validate_artifact_advisory(advisory, artifact_plan, lineage) == advisory

    missing = copy.deepcopy(advisory)
    missing["replacements"] = []
    with pytest.raises(ValueError, match="non-empty bounded array|replace every"):
        validate_artifact_advisory(missing, artifact_plan, lineage)

    unbound = copy.deepcopy(advisory)
    unbound["statements"][0]["sha256"] = "4" * 64
    with pytest.raises(ValueError, match="does not match lineage"):
        validate_artifact_advisory(unbound, artifact_plan, lineage)

    not_affected = copy.deepcopy(advisory)
    not_affected["statements"][0]["status"] = "not_affected"
    with pytest.raises(ValueError, match="justification"):
        validate_artifact_advisory(not_affected, artifact_plan, lineage)

    non_actionable = copy.deepcopy(advisory)
    non_actionable["statements"][0]["status"] = "fixed"
    with pytest.raises(ValueError, match="actionable"):
        validate_artifact_advisory(non_actionable, artifact_plan, lineage)


def test_reference_run_passes_exact_quarantine_recovery_and_controls():
    plan = _plan()
    run = reference_recall_run(
        plan,
        generated_at="2026-09-03T00:11:00Z",
    )
    assert run["schema"] == RUN_SCHEMA
    evaluation = evaluate_recall_run(plan, run, generated_at="2026-09-03T00:12:00Z")
    assert evaluation["schema"] == EVALUATION_SCHEMA
    assert evaluation["summary"]["verdict"] == "pass"
    assert evaluation["summary"]["affected_deployment_count"] == 2
    assert evaluation["summary"]["quarantine_recall"] == 1
    assert evaluation["summary"]["recovery_recall"] == 1
    assert evaluation["summary"]["unaffected_preservation_rate"] == 1
    assert evaluation["summary"]["p95_delivery_ms"] == 50
    assert evaluation["summary"]["finding_count"] == 0
    assert validate_recall_run(run) == run
    assert validate_recall_evaluation(evaluation) == evaluation


def test_evaluator_reports_late_delivery_compromised_allow_bad_replacement_and_collateral():
    plan = _plan()
    run = reference_recall_run(plan, generated_at="2026-09-03T00:11:00Z")
    run["advisory_observations"][0]["received_at_ms"] = 1_501
    by_probe = {item["probe_id"]: item for item in run["response_observations"]}
    affected_quarantine = next(
        item
        for item in plan["probes"]
        if item["phase"] == "post_quarantine_deadline" and item["expected_decision"] == "block"
    )
    observation = by_probe[affected_quarantine["probe_id"]]
    observation["decision"] = "allow"
    observation["reason_code"] = "artifact_not_quarantined"
    observation["observed_artifact_set_sha256"] = affected_quarantine["artifact_set_sha256"]
    affected_recovery = next(
        item
        for item in plan["probes"]
        if item["phase"] == "post_recovery_deadline"
        and item["expected_reason"] == "replacement_authorized"
    )
    by_probe[affected_recovery["probe_id"]]["observed_artifact_set_sha256"] = "4" * 64
    unaffected = next(
        item
        for item in plan["probes"]
        if item["phase"] == "post_quarantine_deadline"
        and item["expected_reason"] == "unaffected_artifact_preserved"
    )
    observation = by_probe[unaffected["probe_id"]]
    observation["decision"] = "block"
    observation["reason_code"] = "collateral_block"
    observation["observed_artifact_set_sha256"] = None

    evaluation = evaluate_recall_run(plan, run, generated_at="2026-09-03T00:12:00Z")
    reasons = {item["reason"] for item in evaluation["findings"]}
    assert {
        "advisory_delivery_late",
        "collateral_block",
        "compromised_artifact_allowed_post_deadline",
        "replacement_artifact_set_mismatch",
        "response_reason_mismatch",
    } <= reasons
    assert evaluation["summary"]["verdict"] == "fail"
    assert evaluation["summary"]["post_deadline_compromised_allow_count"] == 1
    assert evaluation["summary"]["wrong_replacement_count"] == 1
    assert evaluation["summary"]["collateral_block_count"] == 1


def test_evaluator_fails_closed_on_missing_duplicate_unexpected_and_contract_drift():
    plan = _plan()
    run = reference_recall_run(plan, generated_at="2026-09-03T00:11:00Z")
    missing = run["response_observations"].pop()
    duplicate = copy.deepcopy(run["response_observations"][0])
    duplicate["observation_id"] = "response-duplicate"
    run["response_observations"].append(duplicate)
    unexpected = copy.deepcopy(run["response_observations"][1])
    unexpected["observation_id"] = "response-unexpected"
    unexpected["probe_id"] = "unknown-probe"
    run["response_observations"].append(unexpected)
    run["plan_sha256"] = "4" * 64
    evaluation = evaluate_recall_run(plan, run, generated_at="2026-09-03T00:12:00Z")
    reasons = {item["reason"] for item in evaluation["findings"]}
    assert {
        "plan_digest_mismatch",
        "response_probe_duplicate",
        "response_probe_missing",
        "response_probe_unexpected",
    } <= reasons
    assert missing["probe_id"] not in {item["probe_id"] for item in run["response_observations"]}


def test_cli_outputs_are_private_and_never_overwritten(tmp_path: Path):
    artifact_plan = _load_artifact_plan()
    lineage = _lineage(artifact_plan)
    advisory = _advisory(artifact_plan, lineage)
    lineage_path = tmp_path / "lineage.json"
    advisory_path = tmp_path / "advisory.json"
    lineage_path.write_text(json.dumps(lineage), encoding="utf-8")
    advisory_path.write_text(json.dumps(advisory), encoding="utf-8")
    plan_path = tmp_path / "plan.json"
    assert (
        main(
            [
                "recall-compose",
                "--artifact-plan",
                str(ARTIFACT_PLAN),
                "--lineage",
                str(lineage_path),
                "--advisory",
                str(advisory_path),
                "--out",
                str(plan_path),
            ]
        )
        == 0
    )
    assert os.stat(plan_path).st_mode & 0o777 == 0o600
    assert main(["recall-run", "--plan", str(plan_path), "--out", str(tmp_path / "run.json")]) == 0
    assert (
        main(
            [
                "recall-eval",
                "--plan",
                str(plan_path),
                "--run",
                str(tmp_path / "run.json"),
                "--out",
                str(tmp_path / "evaluation.json"),
            ]
        )
        == 0
    )
    assert main(["recall-verify", str(tmp_path / "evaluation.json")]) == 0
    assert (
        main(
            [
                "recall-compose",
                "--artifact-plan",
                str(ARTIFACT_PLAN),
                "--lineage",
                str(lineage_path),
                "--advisory",
                str(advisory_path),
                "--out",
                str(plan_path),
            ]
        )
        == 2
    )
