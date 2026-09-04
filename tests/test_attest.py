from __future__ import annotations

import ast
import copy
import hashlib
import json
import os
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from lurebench.attest import (
    PLAN_SCHEMA,
    TRUST_POLICY_SCHEMA,
    compose_attest_plan,
    validate_attest_plan,
    validate_trust_policy,
)
from lurebench.cli import main
from lurebench.permit import _canonical

ROOT = Path(__file__).parents[1]
VECTOR = ROOT / "conformance" / "lureattest-v1"


def _load(name: str) -> dict:
    return json.loads((VECTOR / name).read_text(encoding="utf-8"))


def _registry() -> Registry:
    resources = []
    for path in (ROOT / "spec").glob("*.schema.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        if "$id" in schema:
            resources.append((schema["$id"], Resource.from_contents(schema)))
    return Registry().with_resources(resources)


def test_public_vector_recompiles_exactly_and_schemas_validate():
    artifact_plan = _load("artifact-plan.json")
    policy = _load("trust-policy.json")
    plan = _load("plan.json")
    assert validate_trust_policy(policy, artifact_plan) == policy
    assert compose_attest_plan(artifact_plan, policy) == plan
    assert validate_attest_plan(plan) == plan

    registry = _registry()
    for filename, instance, schema_id in (
        ("lureattest-trust-policy-v1.schema.json", policy, TRUST_POLICY_SCHEMA),
        ("lureattest-plan-v1.schema.json", plan, PLAN_SCHEMA),
    ):
        schema = json.loads((ROOT / "spec" / filename).read_text(encoding="utf-8"))
        assert schema["$id"] == schema_id
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(
            schema, registry=registry, format_checker=FormatChecker()
        ).validate(instance)


def test_policy_requires_exact_plan_builder_and_attestation_coverage():
    artifact_plan = _load("artifact-plan.json")

    policy = _load("trust-policy.json")
    policy["artifact_plan_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="does not bind"):
        validate_trust_policy(policy, artifact_plan)

    policy = _load("trust-policy.json")
    policy["attestation_expectations"].pop()
    with pytest.raises(ValueError, match="cover every"):
        validate_trust_policy(policy, artifact_plan)

    policy = _load("trust-policy.json")
    policy["trusted_builders"][0]["builder_id"] = "https://builder.example.invalid"
    with pytest.raises(ValueError, match="exactly match"):
        validate_trust_policy(policy, artifact_plan)


def test_policy_rejects_signer_builder_substitution_and_overclaimed_level():
    artifact_plan = _load("artifact-plan.json")
    policy = _load("trust-policy.json")
    policy["attestation_expectations"][0]["public_key_sha256"] = "1" * 64
    with pytest.raises(ValueError, match="untrusted public key"):
        validate_trust_policy(policy, artifact_plan)


def test_policy_allows_one_signer_for_explicit_distinct_builder_pairs():
    artifact_plan = _load("artifact-plan.json")
    policy = _load("trust-policy.json")
    second_builder = "https://github.com/actions/model-builder"
    artifact_plan["workloads"][0]["attestations"][0]["builder_id"] = second_builder
    artifact_plan["policy"]["approved_builder_ids"].append(second_builder)
    artifact_plan["policy"]["approved_builder_ids"].sort()
    policy["artifact_plan_sha256"] = hashlib.sha256(_canonical(artifact_plan)).hexdigest()
    second_trust = copy.deepcopy(policy["trusted_builders"][0])
    second_trust["builder_id"] = second_builder
    policy["trusted_builders"].append(second_trust)
    assert validate_trust_policy(policy, artifact_plan) == policy
    assert compose_attest_plan(artifact_plan, policy)["trusted_builders"] == sorted(
        policy["trusted_builders"], key=lambda item: item["builder_id"]
    )


def test_policy_cannot_predate_its_artifact_plan():
    artifact_plan = _load("artifact-plan.json")
    policy = _load("trust-policy.json")
    policy["created_at"] = "2026-09-04T15:59:59Z"
    with pytest.raises(ValueError, match="predates"):
        validate_trust_policy(policy, artifact_plan)

    policy = _load("trust-policy.json")
    policy["trusted_builders"][0]["maximum_trusted_slsa_build_level"] = 1
    with pytest.raises(ValueError, match="exceeds reviewed"):
        validate_trust_policy(policy, artifact_plan)


def test_plan_rejects_unsafe_filename_and_ambiguous_attestation():
    plan = _load("plan.json")
    plan["workloads"][0]["attestations"][0]["evidence_file"] = "../escape.json"
    with pytest.raises(ValueError, match="canonical safe filename"):
        validate_attest_plan(plan)

    plan = _load("plan.json")
    plan["workloads"][0]["attestations"][1]["attestation_id"] = plan["workloads"][0][
        "attestations"
    ][0]["attestation_id"]
    plan["workloads"][0]["attestations"][1]["evidence_file"] = plan["workloads"][0][
        "attestations"
    ][0]["evidence_file"]
    with pytest.raises(ValueError, match="duplicate"):
        validate_attest_plan(plan)


def test_compiler_has_no_crypto_or_network_dependency():
    tree = ast.parse((ROOT / "lurebench" / "attest.py").read_text(encoding="utf-8"))
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported.update(
        node.module.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module and not node.level
    )
    assert imported.isdisjoint({"cryptography", "requests", "socket", "urllib"})


def test_cli_compose_is_private_and_refuses_overwrite(tmp_path: Path):
    output = tmp_path / "attest-plan.json"
    args = [
        "attest-compose",
        "--artifact-plan",
        str(VECTOR / "artifact-plan.json"),
        "--policy",
        str(VECTOR / "trust-policy.json"),
        "--out",
        str(output),
    ]
    assert main(args) == 0
    assert json.loads(output.read_text(encoding="utf-8")) == _load("plan.json")
    if os.name == "posix":
        assert output.stat().st_mode & 0o777 == 0o600
    assert main(args) == 2


def test_mutations_do_not_change_inputs():
    artifact_plan = _load("artifact-plan.json")
    policy = _load("trust-policy.json")
    before_artifact = copy.deepcopy(artifact_plan)
    before_policy = copy.deepcopy(policy)
    compose_attest_plan(artifact_plan, policy)
    assert artifact_plan == before_artifact
    assert policy == before_policy
