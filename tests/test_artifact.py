from __future__ import annotations

import copy
import json
import os
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from lurebench.artifact import (
    CAMPAIGN_SCHEMA,
    EVALUATION_SCHEMA,
    OBSERVATION_SCHEMA,
    PLAN_SCHEMA,
    compose_artifact_plan,
    evaluate_artifact_observation,
    reference_artifact_observation,
    validate_artifact_campaign,
    validate_artifact_evaluation,
    validate_artifact_observation,
    validate_artifact_plan,
)
from lurebench.cli import main

ROOT = Path(__file__).parents[1]
VECTOR = ROOT / "conformance" / "lureartifact-v1"


def _load(name: str) -> dict:
    return json.loads((VECTOR / name).read_text(encoding="utf-8"))


def _registry() -> Registry:
    resources = []
    for path in (ROOT / "spec").glob("*.schema.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        if "$id" in schema:
            resources.append((schema["$id"], Resource.from_contents(schema)))
    return Registry().with_resources(resources)


@pytest.mark.parametrize(
    ("filename", "schema_name", "schema_id"),
    [
        ("campaign.json", "lureartifact-campaign-v1.schema.json", CAMPAIGN_SCHEMA),
        ("plan.json", "lureartifact-plan-v1.schema.json", PLAN_SCHEMA),
        (
            "observation.json",
            "lureartifact-observation-v1.schema.json",
            OBSERVATION_SCHEMA,
        ),
        (
            "evaluation.json",
            "lureartifact-evaluation-v1.schema.json",
            EVALUATION_SCHEMA,
        ),
    ],
)
def test_public_vector_is_draft_2020_12_schema_valid(filename, schema_name, schema_id):
    schema = json.loads((ROOT / "spec" / schema_name).read_text(encoding="utf-8"))
    assert schema["$id"] == schema_id
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(
        schema, registry=_registry(), format_checker=FormatChecker()
    ).validate(_load(filename))


def test_public_vector_compiles_and_recomputes_exactly():
    identity = _load("identity-plan.json")
    campaign = _load("campaign.json")
    plan = _load("plan.json")
    observation = _load("observation.json")
    evaluation = _load("evaluation.json")

    assert validate_artifact_campaign(campaign, identity) == campaign
    assert compose_artifact_plan(identity, campaign) == plan
    assert validate_artifact_plan(plan) == plan
    assert reference_artifact_observation(
        plan,
        observation_id="lureartifact-conformance-observation",
        captured_at="2026-09-03T00:06:00Z",
    ) == observation
    assert evaluate_artifact_observation(
        plan, observation, generated_at="2026-09-03T00:07:00Z"
    ) == evaluation
    assert validate_artifact_evaluation(evaluation) == evaluation
    assert evaluation["summary"] == {
        "active_workload_count": 2,
        "declared_node_count": 2,
        "expected_deployment_count": 3,
        "observed_deployment_count": 3,
        "compliant_deployment_count": 3,
        "finding_count": 0,
        "verdict": "pass",
    }


def test_compiler_requires_exact_active_workload_coverage_and_identity_binding():
    identity = _load("identity-plan.json")
    campaign = _load("campaign.json")
    campaign["workloads"].pop()
    with pytest.raises(ValueError, match="every active workload"):
        compose_artifact_plan(identity, campaign)

    campaign = _load("campaign.json")
    campaign["identity_plan_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="does not bind"):
        compose_artifact_plan(identity, campaign)

    campaign = _load("campaign.json")
    campaign["workloads"][0]["node_ids"] = ["undeclared-node"]
    with pytest.raises(ValueError, match="outside the identity plan"):
        compose_artifact_plan(identity, campaign)


def test_compiler_rejects_executable_model_formats_and_unapproved_builders():
    identity = _load("identity-plan.json")
    campaign = _load("campaign.json")
    model = next(
        item
        for item in campaign["workloads"][0]["artifacts"]
        if item["role"] == "model_weights"
    )
    model["model_serialization"] = "pickle"
    with pytest.raises(ValueError, match="model_serialization"):
        compose_artifact_plan(identity, campaign)

    campaign = _load("campaign.json")
    model = next(
        item
        for item in campaign["workloads"][0]["artifacts"]
        if item["role"] == "model_weights"
    )
    model["remote_code_required"] = True
    with pytest.raises(ValueError, match="embedded or remote code"):
        compose_artifact_plan(identity, campaign)

    campaign = _load("campaign.json")
    campaign["workloads"][0]["attestations"][0]["builder_id"] = (
        "https://unapproved.example/builder"
    )
    with pytest.raises(ValueError, match="approved allowlist"):
        compose_artifact_plan(identity, campaign)


def test_compiler_rejects_unbound_provenance_and_incomplete_ai_bom():
    identity = _load("identity-plan.json")
    campaign = _load("campaign.json")
    campaign["workloads"][0]["attestations"][0]["subject_sha256"] = "9" * 64
    with pytest.raises(ValueError, match="subject digest"):
        compose_artifact_plan(identity, campaign)

    campaign = _load("campaign.json")
    campaign["workloads"][0]["ai_bom"]["subject_artifact_ids"].pop()
    with pytest.raises(ValueError, match="cover model, container, and policy"):
        compose_artifact_plan(identity, campaign)


def test_evaluator_reports_valid_but_substituted_model_provenance_and_bom():
    plan = _load("plan.json")
    observation = _load("observation.json")
    deployment = observation["deployments"][0]
    model = next(item for item in deployment["artifacts"] if item["role"] == "model_weights")
    model["sha256"] = "1" * 64
    model["model_serialization"] = "pickle"
    provenance = next(
        item
        for item in deployment["attestations"]
        if item["subject_artifact_id"] == "alpha-model"
    )
    provenance["subject_sha256"] = "1" * 64
    provenance["statement_sha256"] = "2" * 64
    deployment["ai_bom"]["document_sha256"] = "3" * 64
    ai_bom_artifact = next(
        item for item in deployment["artifacts"] if item["role"] == "ai_sbom"
    )
    ai_bom_artifact["sha256"] = "3" * 64

    reviewed = validate_artifact_observation(observation)
    evaluation = evaluate_artifact_observation(
        plan, reviewed, generated_at="2026-09-03T00:07:00Z"
    )
    assert evaluation["summary"]["verdict"] == "fail"
    assert {item["reason"] for item in evaluation["findings"]} == {
        "artifact_metadata_mismatch",
        "provenance_metadata_mismatch",
        "ai_bom_metadata_mismatch",
        "observed_model_serialization_disallowed",
    }
    status = {item["check_id"]: item["status"] for item in evaluation["checks"]}
    assert status["artifact_inventory_exact"] == "fail"
    assert status["slsa_provenance_exact"] == "fail"
    assert status["ai_bom_binding_exact"] == "fail"
    assert status["non_executable_model_policy"] == "fail"


def test_evaluator_reports_missing_extra_duplicate_identity_and_freshness():
    plan = _load("plan.json")
    observation = _load("observation.json")
    observation["deployments"].pop()
    duplicate = copy.deepcopy(observation["deployments"][0])
    duplicate["observation_id"] = "duplicate-observation"
    observation["deployments"].append(duplicate)
    extra = copy.deepcopy(observation["deployments"][0])
    extra["observation_id"] = "extra-observation"
    extra["node_id"] = "shadow-node"
    observation["deployments"].append(extra)
    observation["captured_at"] = "2026-09-02T23:59:00Z"
    observation["system_id"] = "different-system"
    observation["plan_sha256"] = "4" * 64

    evaluation = evaluate_artifact_observation(
        plan, observation, generated_at="2026-09-03T00:07:00Z"
    )
    reasons = {item["reason"] for item in evaluation["findings"]}
    assert {
        "plan_digest_mismatch",
        "system_id_mismatch",
        "observation_predates_plan",
        "deployment_missing",
        "deployment_unexpected",
        "deployment_duplicate",
    } <= reasons
    assert evaluation["summary"]["verdict"] == "fail"


def test_saved_evaluation_rejects_tampering():
    evaluation = _load("evaluation.json")
    evaluation["summary"]["finding_count"] = 1
    with pytest.raises(ValueError, match="independently recompute"):
        validate_artifact_evaluation(evaluation)


def test_artifact_cli_pipeline_is_private_and_never_overwrites(tmp_path: Path, capsys):
    identity = tmp_path / "identity.json"
    campaign = tmp_path / "campaign.json"
    identity.write_text(json.dumps(_load("identity-plan.json")), encoding="utf-8")
    campaign.write_text(json.dumps(_load("campaign.json")), encoding="utf-8")
    plan = tmp_path / "plan.json"
    observation = tmp_path / "observation.json"
    evaluation = tmp_path / "evaluation.json"

    assert main(
        [
            "artifact-compose",
            "--identity-plan",
            str(identity),
            "--campaign",
            str(campaign),
            "--out",
            str(plan),
        ]
    ) == 0
    assert main(
        [
            "artifact-observe",
            "--plan",
            str(plan),
            "--captured-at",
            "2026-09-03T00:06:00Z",
            "--out",
            str(observation),
        ]
    ) == 0
    assert main(
        [
            "artifact-eval",
            "--plan",
            str(plan),
            "--observation",
            str(observation),
            "--generated-at",
            "2026-09-03T00:07:00Z",
            "--out",
            str(evaluation),
        ]
    ) == 0
    assert main(["artifact-verify", str(evaluation)]) == 0
    assert "LUREARTIFACT VERIFIED: PASS" in capsys.readouterr().out
    if os.name == "posix":
        assert all(path.stat().st_mode & 0o777 == 0o600 for path in (plan, observation, evaluation))
    original = plan.read_bytes()
    assert main(
        [
            "artifact-compose",
            "--identity-plan",
            str(identity),
            "--campaign",
            str(campaign),
            "--out",
            str(plan),
        ]
    ) == 2
    assert plan.read_bytes() == original
