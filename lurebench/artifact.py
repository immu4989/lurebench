"""Workload-to-artifact authorization benchmark for AI deployments.

LureArtifact compiles a reviewed artifact campaign against an exact
LureIdentity plan.  Every active workload must be represented, and each
declared deployment node is bound to exact model, container, policy, AI-BOM,
and SLSA provenance metadata.  The evaluator compares claimed observations
without fetching, importing, executing, or deserializing artifact bytes.
"""

from __future__ import annotations

import re
import secrets
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence
from urllib.parse import urlsplit

from . import __version__
from .identity import _digest, _read, _write, validate_identity_plan
from .permit import _canonical, _exact, _identifier, _sha256, _timestamp
from .spiffe import parse_spiffe_id

CAMPAIGN_SCHEMA = "https://github.com/immu4989/lurebench/spec/lureartifact-campaign-v1"
PLAN_SCHEMA = "https://github.com/immu4989/lurebench/spec/lureartifact-plan-v1"
OBSERVATION_SCHEMA = "https://github.com/immu4989/lurebench/spec/lureartifact-observation-v1"
EVALUATION_SCHEMA = "https://github.com/immu4989/lurebench/spec/lureartifact-evaluation-v1"
SLSA_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"

MAX_WORKLOADS = 128
MAX_NODES = 64
MAX_DEPLOYMENTS = MAX_WORKLOADS * MAX_NODES
MAX_BUILDERS = 64
REQUIRED_ARTIFACT_ROLES = (
    "ai_sbom",
    "container_image",
    "model_weights",
    "policy_bundle",
)
PROVENANCE_ROLES = ("container_image", "model_weights", "policy_bundle")
ARTIFACT_ROLES = set(REQUIRED_ARTIFACT_ROLES)
SAFE_MODEL_SERIALIZATIONS = {"gguf", "onnx", "safetensors"}
OBSERVED_MODEL_SERIALIZATIONS = SAFE_MODEL_SERIALIZATIONS | {
    "hdf5",
    "pickle",
    "pytorch_pickle",
    "unknown",
}
SBOM_FORMATS = {"cyclonedx-1.6", "cyclonedx-1.7", "spdx-3.0.1"}
URI_SCHEMES = {"https", "urn"}
_MEDIA_TYPE = re.compile(r"^[a-z0-9][a-z0-9.+-]{0,63}/[a-z0-9][a-z0-9.+-]{0,127}$")

CAMPAIGN_LIMITATIONS = [
    "declared_artifact_metadata_only_no_artifact_bytes_credentials_prompts_or_model_content",
    "campaign_is_compiled_against_one_exact_lureidentity_plan_and_does_not_discover_deployments",
    "safe_serialization_and_provenance_fields_are_reviewed_claims_not_content_inspection",
    "hashes_prove_equality_to_reviewed_bytes_not_that_content_builders_or_sources_are_benign",
    "compilation_performs_no_network_access_artifact_loading_import_execution_or_deserialization",
]
PLAN_LIMITATIONS = [
    "plan_binds_every_active_declared_workload_to_reviewed_artifact_metadata_at_declared_nodes",
    "spiffe_ids_are_identifiers_only_and_do_not_prove_svid_issuance_validation_or_possession",
    "slsa_fields_are_a_bounded_projection_not_statement_signature_or_build-platform_verification",
    "ai_bom_fields_are_a_bounded_projection_not_spdx_or_cyclonedx_document_validation",
    "plan_validation_does_not_fetch_scan_load_import_execute_or_deserialize_artifact_bytes",
]
OBSERVATION_LIMITATIONS = [
    "observations_are_claimed_runtime_inventory_metadata_not_trusted_measurement_or_attestation",
    "observation_collection_completeness_clock_quality_and_workload_identity_are_external",
    "no_artifact_bytes_credentials_prompts_model_content_or_reasoning_are_collected",
]
EVALUATION_LIMITATIONS = [
    "evaluation_recomputes_declared_identity_deployment_artifact_provenance_and_ai_bom_equality",
    "a_pass_does_not_authenticate_observation_origin_workload_identity_builder_or_artifact_source",
    "digest_equality_does_not_establish_artifact_safety_quality_licensing_or_vulnerability_status",
    "passing_is_not_supply_chain_containment_compliance_certification_or_deployment_authorization",
]


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _enum(value: Any, field: str, allowed: set[str]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise ValueError(f"{field} is unsupported")
    return value


def _uri(value: Any, field: str, *, schemes: set[str] = URI_SCHEMES) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        raise ValueError(f"{field} must be a bounded absolute URI")
    if any(character.isspace() or ord(character) < 0x20 for character in value):
        raise ValueError(f"{field} must not contain whitespace or controls")
    parsed = urlsplit(value)
    if parsed.scheme not in schemes:
        raise ValueError(f"{field} uses an unsupported URI scheme")
    if parsed.scheme == "https" and (not parsed.netloc or parsed.username or parsed.password):
        raise ValueError(f"{field} must be an absolute credential-free HTTPS URI")
    if parsed.scheme == "urn" and not parsed.path:
        raise ValueError(f"{field} must be an absolute URN")
    if parsed.fragment:
        raise ValueError(f"{field} must not contain a fragment")
    return value


def _package_url(value: Any, field: str) -> Optional[str]:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or not 5 <= len(value) <= 2048
        or not value.startswith("pkg:")
        or any(character.isspace() or ord(character) < 0x20 for character in value)
    ):
        raise ValueError(f"{field} must be null or a bounded package URL")
    return value


def _ids(values: Any, field: str, maximum: int) -> list[str]:
    if not isinstance(values, list) or not 1 <= len(values) <= maximum:
        raise ValueError(f"{field} must be a non-empty bounded array")
    result = [_identifier(item, f"{field}[{index}]") for index, item in enumerate(values)]
    if len(set(result)) != len(result):
        raise ValueError(f"{field} contains duplicate identifiers")
    return result


def _artifact(value: Any, field: str, *, observed: bool) -> Dict[str, Any]:
    artifact = _exact(
        value,
        field,
        (
            "artifact_id",
            "role",
            "sha256",
            "media_type",
            "package_url",
            "model_serialization",
            "model_embedded_code",
            "remote_code_required",
        ),
    )
    _identifier(artifact["artifact_id"], f"{field}.artifact_id")
    role = _enum(artifact["role"], f"{field}.role", ARTIFACT_ROLES)
    _digest(artifact["sha256"], f"{field}.sha256")
    if not isinstance(artifact["media_type"], str) or _MEDIA_TYPE.fullmatch(
        artifact["media_type"]
    ) is None:
        raise ValueError(f"{field}.media_type must be a bounded lowercase media type")
    _package_url(artifact["package_url"], f"{field}.package_url")
    if not isinstance(artifact["model_embedded_code"], bool) or not isinstance(
        artifact["remote_code_required"], bool
    ):
        raise ValueError(f"{field} code-presence fields must be boolean")
    if role == "model_weights":
        serializations = OBSERVED_MODEL_SERIALIZATIONS if observed else SAFE_MODEL_SERIALIZATIONS
        _enum(
            artifact["model_serialization"],
            f"{field}.model_serialization",
            serializations,
        )
        if not observed and (
            artifact["model_embedded_code"] or artifact["remote_code_required"]
        ):
            raise ValueError("reviewed model weights must not declare embedded or remote code")
    elif (
        artifact["model_serialization"] is not None
        or artifact["model_embedded_code"]
        or artifact["remote_code_required"]
    ):
        raise ValueError(f"{field} non-model artifacts cannot declare model execution metadata")
    return dict(artifact)


def _artifacts(
    value: Any,
    field: str,
    *,
    observed: bool,
    require_complete: bool,
) -> list[Dict[str, Any]]:
    if not isinstance(value, list) or len(value) > len(REQUIRED_ARTIFACT_ROLES):
        raise ValueError(f"{field} must be a bounded array")
    result = [_artifact(item, f"{field}[{index}]", observed=observed) for index, item in enumerate(value)]
    ids = [item["artifact_id"] for item in result]
    roles = [item["role"] for item in result]
    if len(set(ids)) != len(ids) or len(set(roles)) != len(roles):
        raise ValueError(f"{field} contains duplicate artifact identifiers or roles")
    if require_complete and set(roles) != ARTIFACT_ROLES:
        raise ValueError(f"{field} must contain every required artifact role exactly once")
    return result


def _attestation(value: Any, field: str, artifact_by_id: Mapping[str, Mapping[str, Any]]) -> Dict[str, Any]:
    attestation = _exact(
        value,
        field,
        (
            "attestation_id",
            "subject_artifact_id",
            "subject_sha256",
            "statement_sha256",
            "statement_type",
            "predicate_type",
            "builder_id",
            "build_type",
            "source_sha256",
        ),
    )
    _identifier(attestation["attestation_id"], f"{field}.attestation_id")
    subject_id = _identifier(
        attestation["subject_artifact_id"], f"{field}.subject_artifact_id"
    )
    _digest(attestation["subject_sha256"], f"{field}.subject_sha256")
    _digest(attestation["statement_sha256"], f"{field}.statement_sha256")
    if attestation["statement_type"] != IN_TOTO_STATEMENT_TYPE:
        raise ValueError(f"{field}.statement_type is unsupported")
    if attestation["predicate_type"] != SLSA_PREDICATE_TYPE:
        raise ValueError(f"{field}.predicate_type is unsupported")
    _uri(attestation["builder_id"], f"{field}.builder_id")
    _uri(attestation["build_type"], f"{field}.build_type")
    _digest(attestation["source_sha256"], f"{field}.source_sha256")
    if subject_id in artifact_by_id and not secrets.compare_digest(
        attestation["subject_sha256"], artifact_by_id[subject_id]["sha256"]
    ):
        raise ValueError(f"{field} subject digest does not match its artifact")
    return dict(attestation)


def _attestations(
    value: Any,
    field: str,
    artifacts: Sequence[Mapping[str, Any]],
    *,
    require_complete: bool,
) -> list[Dict[str, Any]]:
    if not isinstance(value, list) or len(value) > len(PROVENANCE_ROLES):
        raise ValueError(f"{field} must be a bounded array")
    artifact_by_id = {item["artifact_id"]: item for item in artifacts}
    result = [
        _attestation(item, f"{field}[{index}]", artifact_by_id)
        for index, item in enumerate(value)
    ]
    ids = [item["attestation_id"] for item in result]
    subjects = [item["subject_artifact_id"] for item in result]
    if len(set(ids)) != len(ids) or len(set(subjects)) != len(subjects):
        raise ValueError(f"{field} contains duplicate attestation identifiers or subjects")
    for subject in subjects:
        if subject not in artifact_by_id:
            if require_complete:
                raise ValueError(f"{field} references an unknown artifact")
            continue
        if artifact_by_id[subject]["role"] not in PROVENANCE_ROLES:
            raise ValueError(f"{field} provenance subject role is unsupported")
    if require_complete:
        subject_roles = {artifact_by_id[item]["role"] for item in subjects}
        if subject_roles != set(PROVENANCE_ROLES):
            raise ValueError(f"{field} must cover every provenance-required role exactly once")
    return result


def _sbom(
    value: Any,
    field: str,
    artifacts: Sequence[Mapping[str, Any]],
    *,
    required: bool,
) -> Optional[Dict[str, Any]]:
    if value is None:
        if required:
            raise ValueError(f"{field} is required")
        return None
    sbom = _exact(
        value,
        field,
        ("artifact_id", "format", "document_sha256", "subject_artifact_ids"),
    )
    artifact_id = _identifier(sbom["artifact_id"], f"{field}.artifact_id")
    _enum(sbom["format"], f"{field}.format", SBOM_FORMATS)
    _digest(sbom["document_sha256"], f"{field}.document_sha256")
    subjects = _ids(sbom["subject_artifact_ids"], f"{field}.subject_artifact_ids", 4)
    artifact_by_id = {item["artifact_id"]: item for item in artifacts}
    if artifact_id in artifact_by_id:
        artifact = artifact_by_id[artifact_id]
        if artifact["role"] != "ai_sbom" or not secrets.compare_digest(
            sbom["document_sha256"], artifact["sha256"]
        ):
            raise ValueError(f"{field} document must bind the AI-BOM artifact digest")
    elif required:
        raise ValueError(f"{field} references an unknown AI-BOM artifact")
    if required:
        try:
            subject_roles = {artifact_by_id[item]["role"] for item in subjects}
        except KeyError as exc:
            raise ValueError(f"{field} references an unknown subject artifact") from exc
        if subject_roles != set(PROVENANCE_ROLES):
            raise ValueError(f"{field} must cover model, container, and policy artifacts")
    return dict(sbom)


def _policy(value: Any) -> Dict[str, Any]:
    policy = _exact(
        value,
        "artifact policy",
        (
            "required_artifact_roles",
            "provenance_required_for_roles",
            "sbom_subject_roles",
            "allowed_model_serializations",
            "approved_builder_ids",
            "model_embedded_code_allowed",
            "remote_model_code_allowed",
        ),
    )
    if policy["required_artifact_roles"] != list(REQUIRED_ARTIFACT_ROLES):
        raise ValueError("artifact policy required roles are not the strict v1 set")
    if policy["provenance_required_for_roles"] != list(PROVENANCE_ROLES):
        raise ValueError("artifact policy provenance roles are not the strict v1 set")
    if policy["sbom_subject_roles"] != list(PROVENANCE_ROLES):
        raise ValueError("artifact policy AI-BOM subjects are not the strict v1 set")
    serializations = policy["allowed_model_serializations"]
    if (
        not isinstance(serializations, list)
        or not serializations
        or serializations != sorted(set(serializations))
        or not set(serializations) <= SAFE_MODEL_SERIALIZATIONS
    ):
        raise ValueError("artifact policy model serializations must be sorted safe formats")
    builders = policy["approved_builder_ids"]
    if not isinstance(builders, list) or not 1 <= len(builders) <= MAX_BUILDERS:
        raise ValueError("artifact policy approved builders must be a non-empty bounded array")
    if builders != sorted(set(builders)):
        raise ValueError("artifact policy approved builders must be sorted and unique")
    for index, builder_id in enumerate(builders):
        _uri(builder_id, f"artifact policy approved_builder_ids[{index}]")
    if policy["model_embedded_code_allowed"] is not False:
        raise ValueError("artifact policy must deny model-embedded executable code")
    if policy["remote_model_code_allowed"] is not False:
        raise ValueError("artifact policy must deny required remote model code")
    return dict(policy)


def _standards(value: Any) -> Dict[str, Any]:
    standards = _exact(
        value,
        "artifact standards",
        ("statement_type", "provenance_predicate_type", "supported_ai_bom_formats"),
    )
    if standards != {
        "statement_type": IN_TOTO_STATEMENT_TYPE,
        "provenance_predicate_type": SLSA_PREDICATE_TYPE,
        "supported_ai_bom_formats": sorted(SBOM_FORMATS),
    }:
        raise ValueError("artifact standards profile is unsupported")
    return dict(standards)


def _campaign_workload(
    value: Any,
    field: str,
    *,
    node_ids: set[str],
    policy: Mapping[str, Any],
) -> Dict[str, Any]:
    workload = _exact(
        value,
        field,
        ("workload_principal_id", "node_ids", "artifacts", "attestations", "ai_bom"),
    )
    _identifier(workload["workload_principal_id"], f"{field}.workload_principal_id")
    declared_nodes = _ids(workload["node_ids"], f"{field}.node_ids", MAX_NODES)
    if not set(declared_nodes) <= node_ids:
        raise ValueError(f"{field} references a node outside the identity plan")
    artifacts = _artifacts(
        workload["artifacts"], f"{field}.artifacts", observed=False, require_complete=True
    )
    model = next(item for item in artifacts if item["role"] == "model_weights")
    if model["model_serialization"] not in policy["allowed_model_serializations"]:
        raise ValueError(f"{field} model serialization is not allowed by policy")
    attestations = _attestations(
        workload["attestations"],
        f"{field}.attestations",
        artifacts,
        require_complete=True,
    )
    if any(item["builder_id"] not in policy["approved_builder_ids"] for item in attestations):
        raise ValueError(f"{field} names a builder outside the approved allowlist")
    ai_bom = _sbom(workload["ai_bom"], f"{field}.ai_bom", artifacts, required=True)
    return {
        "workload_principal_id": workload["workload_principal_id"],
        "node_ids": sorted(declared_nodes),
        "artifacts": sorted(artifacts, key=lambda item: item["role"]),
        "attestations": sorted(
            attestations,
            key=lambda item: next(
                artifact["role"]
                for artifact in artifacts
                if artifact["artifact_id"] == item["subject_artifact_id"]
            ),
        ),
        "ai_bom": ai_bom,
    }


def compose_artifact_plan(identity_plan: Mapping[str, Any], value: Any) -> Dict[str, Any]:
    """Compile a complete artifact plan for every active workload identity."""

    identity = validate_identity_plan(identity_plan)
    campaign = _exact(
        value,
        "artifact campaign",
        (
            "schema",
            "schema_version",
            "campaign_id",
            "created_at",
            "identity_plan_sha256",
            "workloads",
            "policy",
            "standards",
            "limitations",
        ),
    )
    if campaign["schema"] != CAMPAIGN_SCHEMA or campaign["schema_version"] != 1:
        raise ValueError("unsupported LureArtifact campaign schema")
    _identifier(campaign["campaign_id"], "artifact campaign id")
    _timestamp(campaign["created_at"], "artifact campaign created_at")
    identity_digest = _sha256(_canonical(identity))
    _digest(campaign["identity_plan_sha256"], "artifact campaign identity plan digest")
    if not secrets.compare_digest(campaign["identity_plan_sha256"], identity_digest):
        raise ValueError("artifact campaign does not bind the supplied identity plan")
    if _time(campaign["created_at"]) < _time(identity["created_at"]):
        raise ValueError("artifact campaign predates its identity plan")
    if campaign["limitations"] != CAMPAIGN_LIMITATIONS:
        raise ValueError("artifact campaign limitations are invalid")
    policy = _policy(campaign["policy"])
    standards = _standards(campaign["standards"])
    active_workloads = {
        item["principal_id"]: item
        for item in identity["principals"]
        if item["kind"] == "workload" and item["active"] is True
    }
    if not active_workloads:
        raise ValueError("identity plan must contain an active workload")
    raw_workloads = campaign["workloads"]
    if not isinstance(raw_workloads, list) or not 1 <= len(raw_workloads) <= MAX_WORKLOADS:
        raise ValueError("artifact campaign workloads must be a non-empty bounded array")
    identity_node_ids = {item["node_id"] for item in identity["nodes"]}
    workloads = [
        _campaign_workload(
            item,
            f"artifact campaign workloads[{index}]",
            node_ids=identity_node_ids,
            policy=policy,
        )
        for index, item in enumerate(raw_workloads)
    ]
    workload_ids = [item["workload_principal_id"] for item in workloads]
    if len(set(workload_ids)) != len(workload_ids):
        raise ValueError("artifact campaign contains duplicate workload principals")
    if set(workload_ids) != set(active_workloads):
        raise ValueError("artifact campaign must cover every active workload exactly once")
    compiled_workloads = []
    for workload in sorted(workloads, key=lambda item: item["workload_principal_id"]):
        principal = active_workloads[workload["workload_principal_id"]]
        parse_spiffe_id(principal["spiffe_id"], "artifact workload SPIFFE ID", require_path=True)
        compiled_workloads.append(
            {
                "workload_principal_id": workload["workload_principal_id"],
                "spiffe_id": principal["spiffe_id"],
                "node_ids": workload["node_ids"],
                "artifacts": workload["artifacts"],
                "attestations": workload["attestations"],
                "ai_bom": workload["ai_bom"],
            }
        )
    plan = {
        "schema": PLAN_SCHEMA,
        "schema_version": 1,
        "plan_id": campaign["campaign_id"],
        "created_at": campaign["created_at"],
        "system_id": identity["system_id"],
        "identity": {"plan_id": identity["plan_id"], "plan_sha256": identity_digest},
        "nodes": [dict(item) for item in identity["nodes"]],
        "workloads": compiled_workloads,
        "policy": policy,
        "standards": standards,
        "limitations": list(PLAN_LIMITATIONS),
    }
    return validate_artifact_plan(plan)


def validate_artifact_campaign(
    value: Any, identity_plan: Mapping[str, Any]
) -> Dict[str, Any]:
    campaign = dict(_exact(
        value,
        "artifact campaign",
        (
            "schema",
            "schema_version",
            "campaign_id",
            "created_at",
            "identity_plan_sha256",
            "workloads",
            "policy",
            "standards",
            "limitations",
        ),
    ))
    compose_artifact_plan(identity_plan, campaign)
    return campaign


def validate_artifact_plan(value: Any) -> Dict[str, Any]:
    plan = _exact(
        value,
        "artifact plan",
        (
            "schema",
            "schema_version",
            "plan_id",
            "created_at",
            "system_id",
            "identity",
            "nodes",
            "workloads",
            "policy",
            "standards",
            "limitations",
        ),
    )
    if plan["schema"] != PLAN_SCHEMA or plan["schema_version"] != 1:
        raise ValueError("unsupported LureArtifact plan schema")
    _identifier(plan["plan_id"], "artifact plan id")
    _timestamp(plan["created_at"], "artifact plan created_at")
    _identifier(plan["system_id"], "artifact plan system id")
    identity = _exact(plan["identity"], "artifact plan identity", ("plan_id", "plan_sha256"))
    _identifier(identity["plan_id"], "artifact plan identity plan id")
    _digest(identity["plan_sha256"], "artifact plan identity plan digest")
    if not isinstance(plan["nodes"], list) or not 1 <= len(plan["nodes"]) <= MAX_NODES:
        raise ValueError("artifact plan nodes must be a non-empty bounded array")
    node_ids = set()
    for index, value_node in enumerate(plan["nodes"]):
        node = _exact(
            value_node,
            f"artifact plan nodes[{index}]",
            ("node_id", "enforcement_point_id"),
        )
        node_id = _identifier(node["node_id"], "artifact plan node id")
        _identifier(node["enforcement_point_id"], "artifact plan enforcement point id")
        if node_id in node_ids:
            raise ValueError("artifact plan contains duplicate nodes")
        node_ids.add(node_id)
    policy = _policy(plan["policy"])
    _standards(plan["standards"])
    if not isinstance(plan["workloads"], list) or not 1 <= len(plan["workloads"]) <= MAX_WORKLOADS:
        raise ValueError("artifact plan workloads must be a non-empty bounded array")
    workload_ids = set()
    for index, item in enumerate(plan["workloads"]):
        workload = _exact(
            item,
            f"artifact plan workloads[{index}]",
            (
                "workload_principal_id",
                "spiffe_id",
                "node_ids",
                "artifacts",
                "attestations",
                "ai_bom",
            ),
        )
        workload_id = _identifier(
            workload["workload_principal_id"], "artifact plan workload principal"
        )
        if workload_id in workload_ids:
            raise ValueError("artifact plan contains duplicate workload principals")
        workload_ids.add(workload_id)
        parse_spiffe_id(workload["spiffe_id"], "artifact plan workload SPIFFE ID", require_path=True)
        declared_nodes = _ids(workload["node_ids"], "artifact plan workload nodes", MAX_NODES)
        if not set(declared_nodes) <= node_ids:
            raise ValueError("artifact plan workload references an unknown node")
        artifacts = _artifacts(
            workload["artifacts"],
            "artifact plan workload artifacts",
            observed=False,
            require_complete=True,
        )
        model = next(value_artifact for value_artifact in artifacts if value_artifact["role"] == "model_weights")
        if model["model_serialization"] not in policy["allowed_model_serializations"]:
            raise ValueError("artifact plan model serialization is not allowed")
        attestations = _attestations(
            workload["attestations"],
            "artifact plan workload attestations",
            artifacts,
            require_complete=True,
        )
        if any(item_attestation["builder_id"] not in policy["approved_builder_ids"] for item_attestation in attestations):
            raise ValueError("artifact plan contains an unapproved builder")
        _sbom(
            workload["ai_bom"],
            "artifact plan workload AI-BOM",
            artifacts,
            required=True,
        )
    if plan["limitations"] != PLAN_LIMITATIONS:
        raise ValueError("artifact plan limitations are invalid")
    return dict(plan)


def _observed_deployment(value: Any, index: int) -> Dict[str, Any]:
    field = f"artifact observation deployments[{index}]"
    deployment = _exact(
        value,
        field,
        (
            "observation_id",
            "node_id",
            "workload_principal_id",
            "spiffe_id",
            "artifacts",
            "attestations",
            "ai_bom",
        ),
    )
    _identifier(deployment["observation_id"], f"{field}.observation_id")
    _identifier(deployment["node_id"], f"{field}.node_id")
    _identifier(deployment["workload_principal_id"], f"{field}.workload_principal_id")
    parse_spiffe_id(deployment["spiffe_id"], f"{field}.spiffe_id", require_path=True)
    artifacts = _artifacts(
        deployment["artifacts"], f"{field}.artifacts", observed=True, require_complete=False
    )
    attestations = _attestations(
        deployment["attestations"],
        f"{field}.attestations",
        artifacts,
        require_complete=False,
    )
    ai_bom = _sbom(deployment["ai_bom"], f"{field}.ai_bom", artifacts, required=False)
    return {
        "observation_id": deployment["observation_id"],
        "node_id": deployment["node_id"],
        "workload_principal_id": deployment["workload_principal_id"],
        "spiffe_id": deployment["spiffe_id"],
        "artifacts": artifacts,
        "attestations": attestations,
        "ai_bom": ai_bom,
    }


def validate_artifact_observation(value: Any) -> Dict[str, Any]:
    observation = _exact(
        value,
        "artifact observation",
        (
            "schema",
            "schema_version",
            "observation_id",
            "captured_at",
            "system_id",
            "plan_sha256",
            "deployments",
            "limitations",
        ),
    )
    if observation["schema"] != OBSERVATION_SCHEMA or observation["schema_version"] != 1:
        raise ValueError("unsupported LureArtifact observation schema")
    _identifier(observation["observation_id"], "artifact observation id")
    _timestamp(observation["captured_at"], "artifact observation captured_at")
    _identifier(observation["system_id"], "artifact observation system id")
    _digest(observation["plan_sha256"], "artifact observation plan digest")
    raw = observation["deployments"]
    if not isinstance(raw, list) or len(raw) > MAX_DEPLOYMENTS:
        raise ValueError("artifact observation deployments must be a bounded array")
    deployments = [_observed_deployment(item, index) for index, item in enumerate(raw)]
    ids = [item["observation_id"] for item in deployments]
    if len(set(ids)) != len(ids):
        raise ValueError("artifact observation contains duplicate observation identifiers")
    if observation["limitations"] != OBSERVATION_LIMITATIONS:
        raise ValueError("artifact observation limitations are invalid")
    return {**dict(observation), "deployments": deployments}


def reference_artifact_observation(
    plan: Mapping[str, Any],
    *,
    observation_id: str = "lureartifact-reference-observation",
    captured_at: Optional[str] = None,
) -> Dict[str, Any]:
    reviewed = validate_artifact_plan(plan)
    _identifier(observation_id, "artifact observation id")
    deployments = []
    for workload_number, workload in enumerate(reviewed["workloads"], start=1):
        for node_number, node_id in enumerate(workload["node_ids"], start=1):
            deployments.append(
                {
                    "observation_id": f"w{workload_number:03d}-n{node_number:03d}",
                    "node_id": node_id,
                    "workload_principal_id": workload["workload_principal_id"],
                    "spiffe_id": workload["spiffe_id"],
                    "artifacts": [dict(item) for item in workload["artifacts"]],
                    "attestations": [dict(item) for item in workload["attestations"]],
                    "ai_bom": dict(workload["ai_bom"]),
                }
            )
    return validate_artifact_observation(
        {
            "schema": OBSERVATION_SCHEMA,
            "schema_version": 1,
            "observation_id": observation_id,
            "captured_at": captured_at or reviewed["created_at"],
            "system_id": reviewed["system_id"],
            "plan_sha256": _sha256(_canonical(reviewed)),
            "deployments": deployments,
            "limitations": list(OBSERVATION_LIMITATIONS),
        }
    )


def _finding(
    reason: str,
    *,
    node_id: Optional[str] = None,
    workload_id: Optional[str] = None,
    subject_id: Optional[str] = None,
    expected_sha256: Optional[str] = None,
    observed_sha256: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "finding_id": "pending",
        "reason": reason,
        "node_id": node_id,
        "workload_principal_id": workload_id,
        "subject_id": subject_id,
        "expected_sha256": expected_sha256,
        "observed_sha256": observed_sha256,
    }


def _object_digest(value: Mapping[str, Any]) -> str:
    return _sha256(_canonical(value))


def _compare_deployment(
    expected: Mapping[str, Any],
    observed: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> list[Dict[str, Any]]:
    node_id = expected["node_id"]
    workload_id = expected["workload_principal_id"]
    findings = []
    if observed["spiffe_id"] != expected["spiffe_id"]:
        findings.append(
            _finding("spiffe_id_mismatch", node_id=node_id, workload_id=workload_id)
        )
    expected_artifacts = {item["role"]: item for item in expected["artifacts"]}
    observed_artifacts = {item["role"]: item for item in observed["artifacts"]}
    observed_model = observed_artifacts.get("model_weights")
    if observed_model is not None:
        if observed_model["model_serialization"] not in policy["allowed_model_serializations"]:
            findings.append(
                _finding(
                    "observed_model_serialization_disallowed",
                    node_id=node_id,
                    workload_id=workload_id,
                    subject_id=observed_model["artifact_id"],
                    observed_sha256=observed_model["sha256"],
                )
            )
        if observed_model["model_embedded_code"]:
            findings.append(
                _finding(
                    "observed_model_embedded_code",
                    node_id=node_id,
                    workload_id=workload_id,
                    subject_id=observed_model["artifact_id"],
                    observed_sha256=observed_model["sha256"],
                )
            )
        if observed_model["remote_code_required"]:
            findings.append(
                _finding(
                    "observed_remote_model_code_required",
                    node_id=node_id,
                    workload_id=workload_id,
                    subject_id=observed_model["artifact_id"],
                    observed_sha256=observed_model["sha256"],
                )
            )
    for role in sorted(expected_artifacts.keys() - observed_artifacts.keys()):
        findings.append(
            _finding(
                "artifact_missing",
                node_id=node_id,
                workload_id=workload_id,
                subject_id=role,
                expected_sha256=expected_artifacts[role]["sha256"],
            )
        )
    for role in sorted(observed_artifacts.keys() - expected_artifacts.keys()):
        findings.append(
            _finding(
                "artifact_unexpected",
                node_id=node_id,
                workload_id=workload_id,
                subject_id=role,
                observed_sha256=observed_artifacts[role]["sha256"],
            )
        )
    for role in sorted(expected_artifacts.keys() & observed_artifacts.keys()):
        expected_artifact = expected_artifacts[role]
        observed_artifact = observed_artifacts[role]
        if observed_artifact != expected_artifact:
            findings.append(
                _finding(
                    "artifact_metadata_mismatch",
                    node_id=node_id,
                    workload_id=workload_id,
                    subject_id=role,
                    expected_sha256=expected_artifact["sha256"],
                    observed_sha256=observed_artifact["sha256"],
                )
            )
    expected_attestations = {
        item["subject_artifact_id"]: item for item in expected["attestations"]
    }
    observed_attestations = {
        item["subject_artifact_id"]: item for item in observed["attestations"]
    }
    for item in observed_attestations.values():
        if item["builder_id"] not in policy["approved_builder_ids"]:
            findings.append(
                _finding(
                    "observed_builder_unapproved",
                    node_id=node_id,
                    workload_id=workload_id,
                    subject_id=item["subject_artifact_id"],
                    observed_sha256=item["statement_sha256"],
                )
            )
    for subject in sorted(expected_attestations.keys() - observed_attestations.keys()):
        findings.append(
            _finding(
                "provenance_missing",
                node_id=node_id,
                workload_id=workload_id,
                subject_id=subject,
                expected_sha256=expected_attestations[subject]["statement_sha256"],
            )
        )
    for subject in sorted(observed_attestations.keys() - expected_attestations.keys()):
        findings.append(
            _finding(
                "provenance_unexpected",
                node_id=node_id,
                workload_id=workload_id,
                subject_id=subject,
                observed_sha256=observed_attestations[subject]["statement_sha256"],
            )
        )
    for subject in sorted(expected_attestations.keys() & observed_attestations.keys()):
        expected_attestation = expected_attestations[subject]
        observed_attestation = observed_attestations[subject]
        if observed_attestation != expected_attestation:
            findings.append(
                _finding(
                    "provenance_metadata_mismatch",
                    node_id=node_id,
                    workload_id=workload_id,
                    subject_id=subject,
                    expected_sha256=expected_attestation["statement_sha256"],
                    observed_sha256=observed_attestation["statement_sha256"],
                )
            )
    expected_sbom = expected["ai_bom"]
    observed_sbom = observed["ai_bom"]
    if observed_sbom is None:
        findings.append(
            _finding(
                "ai_bom_missing",
                node_id=node_id,
                workload_id=workload_id,
                subject_id=expected_sbom["artifact_id"],
                expected_sha256=expected_sbom["document_sha256"],
            )
        )
    elif observed_sbom != expected_sbom:
        findings.append(
            _finding(
                "ai_bom_metadata_mismatch",
                node_id=node_id,
                workload_id=workload_id,
                subject_id=expected_sbom["artifact_id"],
                expected_sha256=expected_sbom["document_sha256"],
                observed_sha256=observed_sbom["document_sha256"],
            )
        )
    return findings


def _evaluation_value(
    plan: Mapping[str, Any], observation: Mapping[str, Any], generated_at: str
) -> Dict[str, Any]:
    reviewed_plan = validate_artifact_plan(plan)
    reviewed_observation = validate_artifact_observation(observation)
    _timestamp(generated_at, "artifact evaluation generated_at")
    if _time(generated_at) < _time(reviewed_observation["captured_at"]):
        raise ValueError("artifact evaluation predates its deployment observation")
    plan_sha256 = _sha256(_canonical(reviewed_plan))
    findings: list[Dict[str, Any]] = []
    if reviewed_observation["plan_sha256"] != plan_sha256:
        findings.append(
            _finding(
                "plan_digest_mismatch",
                expected_sha256=plan_sha256,
                observed_sha256=reviewed_observation["plan_sha256"],
            )
        )
    if reviewed_observation["system_id"] != reviewed_plan["system_id"]:
        findings.append(_finding("system_id_mismatch"))
    if _time(reviewed_observation["captured_at"]) < _time(reviewed_plan["created_at"]):
        findings.append(_finding("observation_predates_plan"))

    expected_deployments = {}
    for workload in reviewed_plan["workloads"]:
        for node_id in workload["node_ids"]:
            key = (node_id, workload["workload_principal_id"])
            expected_deployments[key] = {
                "node_id": node_id,
                "workload_principal_id": workload["workload_principal_id"],
                "spiffe_id": workload["spiffe_id"],
                "artifacts": workload["artifacts"],
                "attestations": workload["attestations"],
                "ai_bom": workload["ai_bom"],
            }
    observed_groups: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    for deployment in reviewed_observation["deployments"]:
        key = (deployment["node_id"], deployment["workload_principal_id"])
        observed_groups.setdefault(key, []).append(deployment)
    for key in sorted(expected_deployments.keys() - observed_groups.keys()):
        findings.append(
            _finding("deployment_missing", node_id=key[0], workload_id=key[1])
        )
    for key in sorted(observed_groups.keys() - expected_deployments.keys()):
        for deployment in observed_groups[key]:
            findings.append(
                _finding(
                    "deployment_unexpected",
                    node_id=key[0],
                    workload_id=key[1],
                    subject_id=deployment["observation_id"],
                )
            )
    for key in sorted(expected_deployments.keys() & observed_groups.keys()):
        group = observed_groups[key]
        if len(group) != 1:
            findings.append(
                _finding("deployment_duplicate", node_id=key[0], workload_id=key[1])
            )
            continue
        findings.extend(
            _compare_deployment(expected_deployments[key], group[0], reviewed_plan["policy"])
        )

    for index, finding in enumerate(findings, start=1):
        finding["finding_id"] = f"finding-{index:04d}"
    reasons = {item["reason"] for item in findings}
    check_reasons = {
        "identity_contract_bound": {"plan_digest_mismatch", "system_id_mismatch"},
        "observation_not_predated": {"observation_predates_plan"},
        "deployment_matrix_exact": {
            "deployment_missing",
            "deployment_unexpected",
            "deployment_duplicate",
        },
        "workload_identity_exact": {"spiffe_id_mismatch"},
        "artifact_inventory_exact": {
            "artifact_missing",
            "artifact_unexpected",
            "artifact_metadata_mismatch",
        },
        "slsa_provenance_exact": {
            "provenance_missing",
            "provenance_unexpected",
            "provenance_metadata_mismatch",
        },
        "ai_bom_binding_exact": {"ai_bom_missing", "ai_bom_metadata_mismatch"},
        "approved_builder_policy": {"observed_builder_unapproved"},
        "non_executable_model_policy": {
            "observed_model_serialization_disallowed",
            "observed_model_embedded_code",
            "observed_remote_model_code_required",
        },
    }
    checks = [
        {
            "check_id": check_id,
            "status": "fail" if reasons & associated else "pass",
        }
        for check_id, associated in check_reasons.items()
    ]
    failed_keys = {
        (item["node_id"], item["workload_principal_id"])
        for item in findings
        if item["node_id"] is not None and item["workload_principal_id"] is not None
    }
    return {
        "schema": EVALUATION_SCHEMA,
        "schema_version": 1,
        "generated_at": generated_at,
        "implementation": {"name": "lurebench", "version": __version__},
        "plan": reviewed_plan,
        "plan_sha256": plan_sha256,
        "observation": reviewed_observation,
        "observation_sha256": _sha256(_canonical(reviewed_observation)),
        "summary": {
            "active_workload_count": len(reviewed_plan["workloads"]),
            "declared_node_count": len(reviewed_plan["nodes"]),
            "expected_deployment_count": len(expected_deployments),
            "observed_deployment_count": len(reviewed_observation["deployments"]),
            "compliant_deployment_count": len(expected_deployments) - len(
                set(expected_deployments) & failed_keys
            ),
            "finding_count": len(findings),
            "verdict": "pass" if not findings else "fail",
        },
        "checks": checks,
        "findings": findings,
        "limitations": list(EVALUATION_LIMITATIONS),
    }


def evaluate_artifact_observation(
    plan: Mapping[str, Any],
    observation: Mapping[str, Any],
    *,
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    return _evaluation_value(
        plan,
        observation,
        generated_at or datetime.now().astimezone().isoformat(timespec="milliseconds"),
    )


def validate_artifact_evaluation(value: Any) -> Dict[str, Any]:
    evaluation = _exact(
        value,
        "artifact evaluation",
        (
            "schema",
            "schema_version",
            "generated_at",
            "implementation",
            "plan",
            "plan_sha256",
            "observation",
            "observation_sha256",
            "summary",
            "checks",
            "findings",
            "limitations",
        ),
    )
    if evaluation["schema"] != EVALUATION_SCHEMA or evaluation["schema_version"] != 1:
        raise ValueError("unsupported LureArtifact evaluation schema")
    implementation = _exact(
        evaluation["implementation"], "artifact evaluation implementation", ("name", "version")
    )
    if implementation["name"] != "lurebench":
        raise ValueError("artifact evaluation implementation is unsupported")
    expected = _evaluation_value(
        evaluation["plan"], evaluation["observation"], evaluation["generated_at"]
    )
    expected["implementation"]["version"] = implementation["version"]
    if evaluation != expected:
        raise ValueError("artifact evaluation does not independently recompute")
    return dict(evaluation)


def load_artifact_campaign(path: Path, identity_plan: Mapping[str, Any]) -> Dict[str, Any]:
    return validate_artifact_campaign(_read(Path(path), "artifact campaign"), identity_plan)


def load_artifact_plan(path: Path) -> Dict[str, Any]:
    return validate_artifact_plan(_read(Path(path), "artifact plan"))


def load_artifact_observation(path: Path) -> Dict[str, Any]:
    return validate_artifact_observation(_read(Path(path), "artifact observation"))


def load_artifact_evaluation(path: Path) -> Dict[str, Any]:
    return validate_artifact_evaluation(_read(Path(path), "artifact evaluation"))


def write_artifact_plan(path: Path, value: Mapping[str, Any]) -> None:
    _write(Path(path), validate_artifact_plan(value))


def write_artifact_observation(path: Path, value: Mapping[str, Any]) -> None:
    _write(Path(path), validate_artifact_observation(value))


def write_artifact_evaluation(path: Path, value: Mapping[str, Any]) -> None:
    _write(Path(path), validate_artifact_evaluation(value))
