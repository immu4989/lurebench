"""Compile offline authentication expectations for LureArtifact provenance.

LureAttest deliberately separates policy compilation from cryptographic
verification.  LureBench binds every SLSA provenance claim in one exact
LureArtifact plan to a reviewed signer, source URI, and external-parameter
commitment.  LureScope is the independent verifier that opens the DSSE
envelopes and public keys.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from .artifact import (
    IN_TOTO_STATEMENT_TYPE,
    SLSA_PREDICATE_TYPE,
    _uri,
    validate_artifact_plan,
)
from .identity import _digest, _read, _write
from .permit import _canonical, _exact, _identifier, _sha256, _timestamp

TRUST_POLICY_SCHEMA = "https://github.com/immu4989/lurebench/spec/lureattest-trust-policy-v1"
PLAN_SCHEMA = "https://github.com/immu4989/lurebench/spec/lureattest-plan-v1"
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"
SIGNATURE_ALGORITHM = "ecdsa-p256-sha256"
MAX_BUILDERS = 64
MAX_ATTESTATIONS = 384

REQUIREMENTS = {
    "payload_type": DSSE_PAYLOAD_TYPE,
    "signature_algorithm": SIGNATURE_ALGORITHM,
    "signature_threshold": 1,
    "require_exactly_one_signature": True,
    "require_exactly_one_subject": True,
    "require_statement_sha256": True,
    "require_subject_sha256": True,
    "require_builder_identity": True,
    "require_build_type": True,
    "require_source_dependency": True,
    "require_external_parameters_commitment": True,
}

POLICY_LIMITATIONS = [
    "trusted_builder_levels_and_public_key_fingerprints_are_reviewed_external_policy_inputs",
    "external_parameter_commitments_hide_values_but_do_not_establish_that_they_are_safe",
    "policy_compilation_reads_no_dsse_envelope_public_key_source_tree_or_artifact_bytes",
    "sigstore_certificate_transparency_timestamp_and_identity_verification_are_out_of_scope",
]
PLAN_LIMITATIONS = [
    "plan_binds_every_lureartifact_provenance_claim_to_one_reviewed_signer_and_expectation",
    "plan_compilation_does_not_authenticate_signatures_or_certify_build_platforms",
    "source_matching_requires_one_exact_uri_and_sha256_resolved_dependency",
    "actual_artifact_bytes_ai_bom_documents_and_build_execution_are_not_inspected",
    "a_matching_plan_is_not_artifact_safety_quality_licensing_compliance_or_authorization",
]


def _bounded_list(
    value: Any, field: str, maximum: int, *, allow_empty: bool = False
) -> list[Any]:
    minimum = 0 if allow_empty else 1
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        qualifier = "bounded" if allow_empty else "non-empty bounded"
        raise ValueError(f"{field} must be a {qualifier} array")
    return value


def _level(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value not in (1, 2, 3):
        raise ValueError(f"{field} must be an integer from 1 through 3")
    return value


def _trusted_builder(value: Any, field: str) -> Dict[str, Any]:
    builder = _exact(
        value,
        field,
        (
            "builder_id",
            "public_key_sha256",
            "signature_algorithm",
            "maximum_trusted_slsa_build_level",
        ),
    )
    _uri(builder["builder_id"], f"{field}.builder_id")
    _digest(builder["public_key_sha256"], f"{field}.public_key_sha256")
    if builder["signature_algorithm"] != SIGNATURE_ALGORITHM:
        raise ValueError(f"{field}.signature_algorithm is unsupported")
    _level(
        builder["maximum_trusted_slsa_build_level"],
        f"{field}.maximum_trusted_slsa_build_level",
    )
    return dict(builder)


def _trusted_builders(value: Any, field: str) -> list[Dict[str, Any]]:
    builders = [
        _trusted_builder(item, f"{field}[{index}]")
        for index, item in enumerate(_bounded_list(value, field, MAX_BUILDERS))
    ]
    ids = [item["builder_id"] for item in builders]
    if len(ids) != len(set(ids)):
        raise ValueError(f"{field} contains duplicate builder identities")
    return builders


def _expectation(value: Any, field: str) -> Dict[str, Any]:
    expectation = _exact(
        value,
        field,
        (
            "attestation_id",
            "public_key_sha256",
            "source_uri",
            "external_parameters_sha256",
            "minimum_slsa_build_level",
        ),
    )
    _identifier(expectation["attestation_id"], f"{field}.attestation_id")
    _digest(expectation["public_key_sha256"], f"{field}.public_key_sha256")
    _uri(expectation["source_uri"], f"{field}.source_uri")
    _digest(
        expectation["external_parameters_sha256"],
        f"{field}.external_parameters_sha256",
    )
    _level(expectation["minimum_slsa_build_level"], f"{field}.minimum_slsa_build_level")
    return dict(expectation)


def _expectations(value: Any, field: str) -> list[Dict[str, Any]]:
    expectations = [
        _expectation(item, f"{field}[{index}]")
        for index, item in enumerate(_bounded_list(value, field, MAX_ATTESTATIONS))
    ]
    ids = [item["attestation_id"] for item in expectations]
    if len(ids) != len(set(ids)):
        raise ValueError(f"{field} contains duplicate attestation identifiers")
    return expectations


def _validate_requirements(value: Any, field: str) -> Dict[str, Any]:
    requirements = _exact(value, field, tuple(REQUIREMENTS))
    if requirements != REQUIREMENTS:
        raise ValueError(f"{field} does not match the LureAttest v1 fail-closed profile")
    return dict(requirements)


def _artifact_attestations(
    artifact_plan: Mapping[str, Any],
) -> dict[str, tuple[str, Mapping[str, Any]]]:
    result: dict[str, tuple[str, Mapping[str, Any]]] = {}
    for workload in artifact_plan["workloads"]:
        workload_id = workload["workload_principal_id"]
        for attestation in workload["attestations"]:
            attestation_id = attestation["attestation_id"]
            if attestation_id in result:
                raise ValueError("artifact plan contains ambiguous attestation identifiers")
            result[attestation_id] = (workload_id, attestation)
    if not result or len(result) > MAX_ATTESTATIONS:
        raise ValueError("artifact plan contains an unsupported attestation count")
    return result


def validate_trust_policy(
    value: Any, artifact_plan: Optional[Mapping[str, Any]] = None
) -> Dict[str, Any]:
    policy = _exact(
        value,
        "LureAttest trust policy",
        (
            "schema",
            "schema_version",
            "policy_id",
            "created_at",
            "artifact_plan_sha256",
            "trusted_builders",
            "attestation_expectations",
            "requirements",
            "limitations",
        ),
    )
    if policy["schema"] != TRUST_POLICY_SCHEMA or policy["schema_version"] != 1:
        raise ValueError("unsupported LureAttest trust-policy schema")
    _identifier(policy["policy_id"], "LureAttest trust policy.policy_id")
    _timestamp(policy["created_at"], "LureAttest trust policy.created_at")
    _digest(policy["artifact_plan_sha256"], "LureAttest trust policy.artifact_plan_sha256")
    builders = _trusted_builders(policy["trusted_builders"], "trusted_builders")
    expectations = _expectations(
        policy["attestation_expectations"], "attestation_expectations"
    )
    _validate_requirements(policy["requirements"], "requirements")
    if policy["limitations"] != POLICY_LIMITATIONS:
        raise ValueError("LureAttest trust policy limitations are not canonical")

    builder_by_id = {item["builder_id"]: item for item in builders}
    trusted_keys = {item["public_key_sha256"] for item in builders}
    for expectation in expectations:
        if expectation["public_key_sha256"] not in trusted_keys:
            raise ValueError("attestation expectation references an untrusted public key")

    if artifact_plan is not None:
        reviewed_plan = validate_artifact_plan(artifact_plan)
        if policy["artifact_plan_sha256"] != _sha256(_canonical(reviewed_plan)):
            raise ValueError("LureAttest trust policy does not bind the artifact plan")
        policy_time = datetime.fromisoformat(policy["created_at"].replace("Z", "+00:00"))
        plan_time = datetime.fromisoformat(
            reviewed_plan["created_at"].replace("Z", "+00:00")
        )
        if policy_time < plan_time:
            raise ValueError("LureAttest trust policy predates the artifact plan")
        expected_attestations = _artifact_attestations(reviewed_plan)
        expectation_by_id = {item["attestation_id"]: item for item in expectations}
        if set(expectation_by_id) != set(expected_attestations):
            raise ValueError("trust policy must cover every artifact attestation exactly once")
        used_builders = {item[1]["builder_id"] for item in expected_attestations.values()}
        if set(builder_by_id) != used_builders:
            raise ValueError("trust policy builders must exactly match artifact-plan builders")
        for attestation_id, (_, attestation) in expected_attestations.items():
            builder = builder_by_id[attestation["builder_id"]]
            expectation = expectation_by_id[attestation_id]
            if expectation["public_key_sha256"] != builder["public_key_sha256"]:
                raise ValueError("attestation signer is not bound to its claimed builder")
            if (
                expectation["minimum_slsa_build_level"]
                > builder["maximum_trusted_slsa_build_level"]
            ):
                raise ValueError("required SLSA level exceeds reviewed builder trust")
    return dict(policy)


def _planned_attestation(value: Any, field: str) -> Dict[str, Any]:
    item = _exact(
        value,
        field,
        (
            "attestation_id",
            "evidence_file",
            "subject_artifact_id",
            "subject_sha256",
            "statement_sha256",
            "statement_type",
            "predicate_type",
            "builder_id",
            "build_type",
            "source_uri",
            "source_sha256",
            "external_parameters_sha256",
            "public_key_sha256",
            "minimum_slsa_build_level",
        ),
    )
    attestation_id = _identifier(item["attestation_id"], f"{field}.attestation_id")
    if item["evidence_file"] != f"{attestation_id}.dsse.json":
        raise ValueError(f"{field}.evidence_file is not the canonical safe filename")
    _identifier(item["subject_artifact_id"], f"{field}.subject_artifact_id")
    for name in (
        "subject_sha256",
        "statement_sha256",
        "source_sha256",
        "external_parameters_sha256",
        "public_key_sha256",
    ):
        _digest(item[name], f"{field}.{name}")
    if item["statement_type"] != IN_TOTO_STATEMENT_TYPE:
        raise ValueError(f"{field}.statement_type is unsupported")
    if item["predicate_type"] != SLSA_PREDICATE_TYPE:
        raise ValueError(f"{field}.predicate_type is unsupported")
    for name in ("builder_id", "build_type", "source_uri"):
        _uri(item[name], f"{field}.{name}")
    _level(item["minimum_slsa_build_level"], f"{field}.minimum_slsa_build_level")
    return dict(item)


def _planned_workload(value: Any, field: str) -> Dict[str, Any]:
    workload = _exact(value, field, ("workload_principal_id", "attestations"))
    _identifier(workload["workload_principal_id"], f"{field}.workload_principal_id")
    attestations = [
        _planned_attestation(item, f"{field}.attestations[{index}]")
        for index, item in enumerate(
            _bounded_list(workload["attestations"], f"{field}.attestations", 3)
        )
    ]
    ids = [item["attestation_id"] for item in attestations]
    if len(ids) != len(set(ids)):
        raise ValueError(f"{field} contains duplicate attestation identifiers")
    return dict(workload)


def validate_attest_plan(value: Any) -> Dict[str, Any]:
    plan = _exact(
        value,
        "LureAttest plan",
        (
            "schema",
            "schema_version",
            "plan_id",
            "created_at",
            "artifact_plan",
            "trust_policy",
            "trusted_builders",
            "workloads",
            "requirements",
            "limitations",
        ),
    )
    if plan["schema"] != PLAN_SCHEMA or plan["schema_version"] != 1:
        raise ValueError("unsupported LureAttest plan schema")
    _identifier(plan["plan_id"], "LureAttest plan.plan_id")
    _timestamp(plan["created_at"], "LureAttest plan.created_at")
    artifact_ref = _exact(plan["artifact_plan"], "artifact_plan", ("plan_id", "sha256"))
    policy_ref = _exact(plan["trust_policy"], "trust_policy", ("policy_id", "sha256"))
    _identifier(artifact_ref["plan_id"], "artifact_plan.plan_id")
    _digest(artifact_ref["sha256"], "artifact_plan.sha256")
    _identifier(policy_ref["policy_id"], "trust_policy.policy_id")
    _digest(policy_ref["sha256"], "trust_policy.sha256")
    builders = _trusted_builders(plan["trusted_builders"], "trusted_builders")
    workloads = [
        _planned_workload(item, f"workloads[{index}]")
        for index, item in enumerate(_bounded_list(plan["workloads"], "workloads", 128))
    ]
    workload_ids = [item["workload_principal_id"] for item in workloads]
    if len(workload_ids) != len(set(workload_ids)):
        raise ValueError("LureAttest plan contains duplicate workloads")
    all_attestations = [item for workload in workloads for item in workload["attestations"]]
    attestation_ids = [item["attestation_id"] for item in all_attestations]
    if len(attestation_ids) != len(set(attestation_ids)):
        raise ValueError("LureAttest plan contains globally duplicate attestations")
    if len(all_attestations) > MAX_ATTESTATIONS:
        raise ValueError("LureAttest plan exceeds the attestation safety limit")
    builders_by_id = {item["builder_id"]: item for item in builders}
    for item in all_attestations:
        builder = builders_by_id.get(item["builder_id"])
        if builder is None or builder["public_key_sha256"] != item["public_key_sha256"]:
            raise ValueError("planned attestation is not bound to its builder trust key")
        if item["minimum_slsa_build_level"] > builder["maximum_trusted_slsa_build_level"]:
            raise ValueError("planned attestation exceeds reviewed builder trust")
    _validate_requirements(plan["requirements"], "requirements")
    if plan["limitations"] != PLAN_LIMITATIONS:
        raise ValueError("LureAttest plan limitations are not canonical")
    return dict(plan)


def compose_attest_plan(
    artifact_plan: Mapping[str, Any],
    trust_policy: Mapping[str, Any],
) -> Dict[str, Any]:
    reviewed_artifact_plan = validate_artifact_plan(artifact_plan)
    reviewed_policy = validate_trust_policy(trust_policy, reviewed_artifact_plan)
    timestamp = reviewed_policy["created_at"]
    _timestamp(timestamp, "LureAttest plan.created_at")
    expectation_by_id = {
        item["attestation_id"]: item
        for item in reviewed_policy["attestation_expectations"]
    }
    workloads = []
    for workload in sorted(
        reviewed_artifact_plan["workloads"], key=lambda item: item["workload_principal_id"]
    ):
        planned = []
        for attestation in sorted(
            workload["attestations"], key=lambda item: item["attestation_id"]
        ):
            expectation = expectation_by_id[attestation["attestation_id"]]
            planned.append(
                {
                    "attestation_id": attestation["attestation_id"],
                    "evidence_file": f"{attestation['attestation_id']}.dsse.json",
                    "subject_artifact_id": attestation["subject_artifact_id"],
                    "subject_sha256": attestation["subject_sha256"],
                    "statement_sha256": attestation["statement_sha256"],
                    "statement_type": attestation["statement_type"],
                    "predicate_type": attestation["predicate_type"],
                    "builder_id": attestation["builder_id"],
                    "build_type": attestation["build_type"],
                    "source_uri": expectation["source_uri"],
                    "source_sha256": attestation["source_sha256"],
                    "external_parameters_sha256": expectation[
                        "external_parameters_sha256"
                    ],
                    "public_key_sha256": expectation["public_key_sha256"],
                    "minimum_slsa_build_level": expectation[
                        "minimum_slsa_build_level"
                    ],
                }
            )
        workloads.append(
            {
                "workload_principal_id": workload["workload_principal_id"],
                "attestations": planned,
            }
        )
    return validate_attest_plan(
        {
            "schema": PLAN_SCHEMA,
            "schema_version": 1,
            "plan_id": reviewed_policy["policy_id"],
            "created_at": timestamp,
            "artifact_plan": {
                "plan_id": reviewed_artifact_plan["plan_id"],
                "sha256": _sha256(_canonical(reviewed_artifact_plan)),
            },
            "trust_policy": {
                "policy_id": reviewed_policy["policy_id"],
                "sha256": _sha256(_canonical(reviewed_policy)),
            },
            "trusted_builders": sorted(
                reviewed_policy["trusted_builders"], key=lambda item: item["builder_id"]
            ),
            "workloads": workloads,
            "requirements": dict(REQUIREMENTS),
            "limitations": list(PLAN_LIMITATIONS),
        }
    )


def _load(path: Path, label: str) -> Any:
    return _read(Path(path), label)


def load_trust_policy(
    path: Path, artifact_plan: Optional[Mapping[str, Any]] = None
) -> Dict[str, Any]:
    return validate_trust_policy(_load(path, "LureAttest trust policy"), artifact_plan)


def load_attest_plan(path: Path) -> Dict[str, Any]:
    return validate_attest_plan(_load(path, "LureAttest plan"))


def write_attest_plan(path: Path, value: Mapping[str, Any]) -> None:
    _write(Path(path), validate_attest_plan(value))
