"""Deterministic transitive AI-artifact recall and recovery benchmark.

LureRecall projects caller-reviewed supply-chain metadata into a bounded DAG,
derives every deployment affected by an actionable VEX-like statement, and
scores claimed quarantine and replacement observations.  It never downloads,
loads, imports, executes, or deserializes an artifact.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence

from . import __version__
from .artifact import validate_artifact_plan
from .permit import _canonical, _exact, _identifier, _integer, _timestamp
from .receipts import loads_strict_json

LINEAGE_SCHEMA = "https://github.com/immu4989/lurebench/spec/lureartifact-lineage-v1"
ADVISORY_SCHEMA = "https://github.com/immu4989/lurebench/spec/lureartifact-advisory-v1"
PLAN_SCHEMA = "https://github.com/immu4989/lurebench/spec/lurerecall-plan-v1"
RUN_SCHEMA = "https://github.com/immu4989/lurebench/spec/lurerecall-run-v1"
EVALUATION_SCHEMA = "https://github.com/immu4989/lurebench/spec/lurerecall-evaluation-v1"
VERSION = "1.0.0"

MAX_BYTES = 8 * 1024 * 1024
MAX_COMPONENTS = 8192
MAX_RELATIONSHIPS = 32768
MAX_DEPLOYMENTS = 8192
MAX_PROBES = 24576
MAX_OBSERVATIONS = 65536
MAX_FINDINGS = 65536

COMPONENT_KINDS = {"ai_bom", "container", "dataset", "model", "package", "policy", "runtime"}
RELATIONSHIPS = {"contains", "depends_on", "fine_tuned_from", "trained_on"}
VEX_FORMATS = {"cisa-vex-minimum", "csaf-2.0-vex", "openvex-0.2.0"}
VEX_STATUSES = {"affected", "fixed", "not_affected", "under_investigation"}
ACTIONABLE_STATUSES = {"affected", "under_investigation"}
NOT_AFFECTED_JUSTIFICATIONS = {
    "component_not_present",
    "inline_mitigations_already_exist",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_not_present",
}
PHASES = {"post_quarantine_deadline", "post_recovery_deadline", "pre_advisory"}
DECISIONS = {"allow", "block"}
REASONS = {
    "artifact_authorized",
    "artifact_not_quarantined",
    "artifact_quarantined",
    "collateral_block",
    "replacement_authorized",
    "replacement_unavailable",
    "unaffected_artifact_preserved",
}
DISPOSITIONS = {"applied", "duplicate", "invalid"}
ROLE_KIND = {
    "ai_sbom": "ai_bom",
    "container_image": "container",
    "model_weights": "model",
    "policy_bundle": "policy",
}
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_VULNERABILITY = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._:/-]{0,126}[A-Za-z0-9])?$")

LINEAGE_LIMITATIONS = [
    "lineage_is_a_caller_supplied_normalized_projection_not_direct_sbom_or_guac_ingestion",
    "dependency_edges_express_declared_impact_reachability_not_runtime_execution_or_exploitability",
    "component_and_root_digests_are_metadata_bindings_and_artifact_bytes_are_never_loaded",
    "graph_completeness_authenticity_and_freshness_require_external_controls",
]
ADVISORY_LIMITATIONS = [
    "vex_statuses_are_bounded_metadata_projections_not_openvex_csaf_or_cisa_document_validation",
    "source_document_authentication_issuer_authority_and_vulnerability_truth_are_not_established",
    "affected_and_under_investigation_are_fail_closed_actionable_states_for_this_benchmark",
    "replacement_digests_and_provenance_are_declared_metadata_not_artifact_safety_evidence",
]
PLAN_LIMITATIONS = [
    "impact_is_derived_only_from_the_exact_supplied_artifact_plan_lineage_and_advisory",
    "shortest_paths_explain_declared_transitive_reachability_not_root_cause_or_exploitability",
    "probes_are_synthetic_metadata_and_do_not_start_stop_fetch_or_replace_workloads_or_artifacts",
    "passing_a_future_run_will_not_establish_incident_containment_recovery_or_compliance",
]
RUN_LIMITATIONS = [
    "observations_are_claimed_receiver_metadata_not_proof_of_advisory_delivery_or_enforcement",
    "reference_run_is_offline_and_performs_no_quarantine_replacement_or_artifact_access",
    "artifact_set_digests_are_metadata_commitments_and_no_artifact_bytes_are_collected",
]
EVALUATION_LIMITATIONS = [
    "metrics_are_recomputed_from_embedded_plan_and_run_metadata",
    "deadlines_depend_on_external_clock_quality_and_complete_observation_instrumentation",
    "a_pass_does_not_authenticate_the_advisory_lineage_builder_receiver_or_replacement",
    "evaluation_is_not_incident_containment_recovery_authorization_certification_or_compliance",
]


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _enum(value: Any, field: str, allowed: set[str]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise ValueError(f"{field} is unsupported")
    return value


def _bounded_list(value: Any, field: str, maximum: int, *, allow_empty: bool = False) -> list[Any]:
    minimum = 0 if allow_empty else 1
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        qualifier = "bounded" if allow_empty else "non-empty bounded"
        raise ValueError(f"{field} must be a {qualifier} array")
    return value


def _artifact_roots(plan: Mapping[str, Any]) -> dict[tuple[str, str], Mapping[str, Any]]:
    roots: dict[tuple[str, str], Mapping[str, Any]] = {}
    for workload in plan["workloads"]:
        workload_id = workload["workload_principal_id"]
        for artifact in workload["artifacts"]:
            key = (workload_id, artifact["artifact_id"])
            if key in roots:
                raise ValueError("artifact plan root identifiers are ambiguous")
            roots[key] = artifact
    return roots


def validate_artifact_lineage(value: Any, artifact_plan: Mapping[str, Any]) -> Dict[str, Any]:
    plan = validate_artifact_plan(artifact_plan)
    lineage = _exact(
        value,
        "artifact lineage",
        (
            "schema",
            "schema_version",
            "lineage_id",
            "created_at",
            "artifact_plan_sha256",
            "components",
            "relationships",
            "limitations",
        ),
    )
    if lineage["schema"] != LINEAGE_SCHEMA or lineage["schema_version"] != 1:
        raise ValueError("unsupported LureArtifact lineage schema")
    _identifier(lineage["lineage_id"], "artifact lineage id")
    _timestamp(lineage["created_at"], "artifact lineage created_at")
    if _time(lineage["created_at"]) < _time(plan["created_at"]):
        raise ValueError("artifact lineage predates its artifact plan")
    plan_digest = _sha256(_canonical(plan))
    _digest(lineage["artifact_plan_sha256"], "artifact lineage plan digest")
    if lineage["artifact_plan_sha256"] != plan_digest:
        raise ValueError("artifact lineage does not bind the supplied artifact plan")
    if lineage["limitations"] != LINEAGE_LIMITATIONS:
        raise ValueError("artifact lineage limitations are invalid")

    components: dict[str, Mapping[str, Any]] = {}
    roots_seen: dict[tuple[str, str], str] = {}
    for index, raw in enumerate(
        _bounded_list(lineage["components"], "artifact lineage components", MAX_COMPONENTS)
    ):
        component = _exact(
            raw,
            f"artifact lineage components[{index}]",
            ("component_id", "kind", "sha256", "package_url", "root"),
        )
        component_id = _identifier(component["component_id"], "lineage component id")
        if component_id in components:
            raise ValueError("artifact lineage contains duplicate component identifiers")
        _enum(component["kind"], "lineage component kind", COMPONENT_KINDS)
        _digest(component["sha256"], "lineage component digest")
        package_url = component["package_url"]
        if package_url is not None and (
            not isinstance(package_url, str) or not 1 <= len(package_url) <= 512
        ):
            raise ValueError("lineage component package_url must be null or bounded text")
        root = component["root"]
        if root is not None:
            root = _exact(
                root,
                "lineage component root",
                ("workload_principal_id", "artifact_id"),
            )
            key = (
                _identifier(root["workload_principal_id"], "lineage root workload"),
                _identifier(root["artifact_id"], "lineage root artifact"),
            )
            if key in roots_seen:
                raise ValueError("artifact lineage maps one artifact root more than once")
            roots_seen[key] = component_id
        components[component_id] = component

    expected_roots = _artifact_roots(plan)
    if set(roots_seen) != set(expected_roots):
        raise ValueError("artifact lineage must map every artifact-plan root exactly once")
    for key, component_id in roots_seen.items():
        artifact = expected_roots[key]
        component = components[component_id]
        if component["kind"] != ROLE_KIND[artifact["role"]]:
            raise ValueError("artifact lineage root kind does not match artifact role")
        if component["sha256"] != artifact["sha256"]:
            raise ValueError("artifact lineage root digest does not match artifact plan")
        if component["package_url"] != artifact["package_url"]:
            raise ValueError("artifact lineage root package_url does not match artifact plan")

    adjacency: dict[str, list[str]] = {component_id: [] for component_id in components}
    pairs: set[tuple[str, str]] = set()
    for index, raw in enumerate(
        _bounded_list(
            lineage["relationships"],
            "artifact lineage relationships",
            MAX_RELATIONSHIPS,
            allow_empty=True,
        )
    ):
        edge = _exact(
            raw,
            f"artifact lineage relationships[{index}]",
            ("dependent_component_id", "dependency_component_id", "relationship"),
        )
        dependent = _identifier(edge["dependent_component_id"], "lineage dependent")
        dependency = _identifier(edge["dependency_component_id"], "lineage dependency")
        _enum(edge["relationship"], "lineage relationship", RELATIONSHIPS)
        if dependent not in components or dependency not in components:
            raise ValueError("artifact lineage relationship references an unknown component")
        if dependent == dependency:
            raise ValueError("artifact lineage cannot contain a self dependency")
        pair = (dependent, dependency)
        if pair in pairs:
            raise ValueError("artifact lineage contains duplicate component relationships")
        pairs.add(pair)
        adjacency[dependent].append(dependency)

    state: dict[str, int] = {}

    def visit(component_id: str) -> None:
        marker = state.get(component_id, 0)
        if marker == 1:
            raise ValueError("artifact lineage dependency graph must be acyclic")
        if marker == 2:
            return
        state[component_id] = 1
        for dependency in adjacency[component_id]:
            visit(dependency)
        state[component_id] = 2

    for component_id in sorted(components):
        visit(component_id)

    reachable: set[str] = set()
    queue = deque(sorted(roots_seen.values()))
    while queue:
        component_id = queue.popleft()
        if component_id in reachable:
            continue
        reachable.add(component_id)
        queue.extend(sorted(adjacency[component_id]))
    if reachable != set(components):
        raise ValueError("artifact lineage contains components unreachable from a deployment root")
    return dict(lineage)


def _lineage_indexes(
    lineage: Mapping[str, Any],
) -> tuple[dict[str, Mapping[str, Any]], dict[str, list[str]], dict[tuple[str, str], str]]:
    components = {item["component_id"]: item for item in lineage["components"]}
    adjacency = {component_id: [] for component_id in components}
    for edge in lineage["relationships"]:
        adjacency[edge["dependent_component_id"]].append(edge["dependency_component_id"])
    for values in adjacency.values():
        values.sort()
    roots = {
        (item["root"]["workload_principal_id"], item["root"]["artifact_id"]): item["component_id"]
        for item in lineage["components"]
        if item["root"] is not None
    }
    return components, adjacency, roots


def _path(adjacency: Mapping[str, Sequence[str]], start: str, target: str) -> Optional[list[str]]:
    queue: deque[list[str]] = deque([[start]])
    visited = {start}
    while queue:
        path = queue.popleft()
        if path[-1] == target:
            return path
        for child in sorted(adjacency[path[-1]]):
            if child not in visited:
                visited.add(child)
                queue.append([*path, child])
    return None


def _review_advisory(
    value: Any,
    artifact_plan: Mapping[str, Any],
    lineage: Mapping[str, Any],
) -> tuple[Dict[str, Any], dict[tuple[str, str], list[dict[str, Any]]]]:
    plan = validate_artifact_plan(artifact_plan)
    reviewed_lineage = validate_artifact_lineage(lineage, plan)
    advisory = _exact(
        value,
        "artifact advisory",
        (
            "schema",
            "schema_version",
            "advisory_id",
            "issued_at",
            "issued_at_ms",
            "artifact_plan_sha256",
            "lineage_sha256",
            "source",
            "vulnerability",
            "statements",
            "thresholds",
            "replacements",
            "limitations",
        ),
    )
    if advisory["schema"] != ADVISORY_SCHEMA or advisory["schema_version"] != 1:
        raise ValueError("unsupported LureArtifact advisory schema")
    _identifier(advisory["advisory_id"], "artifact advisory id")
    _timestamp(advisory["issued_at"], "artifact advisory issued_at")
    if _time(advisory["issued_at"]) < _time(reviewed_lineage["created_at"]):
        raise ValueError("artifact advisory predates its lineage")
    issued_at_ms = _integer(
        advisory["issued_at_ms"], "artifact advisory issued_at_ms", 1, 86_400_000
    )
    plan_digest = _sha256(_canonical(plan))
    lineage_digest = _sha256(_canonical(reviewed_lineage))
    _digest(advisory["artifact_plan_sha256"], "artifact advisory plan digest")
    _digest(advisory["lineage_sha256"], "artifact advisory lineage digest")
    if advisory["artifact_plan_sha256"] != plan_digest:
        raise ValueError("artifact advisory does not bind the supplied artifact plan")
    if advisory["lineage_sha256"] != lineage_digest:
        raise ValueError("artifact advisory does not bind the supplied lineage")
    if advisory["limitations"] != ADVISORY_LIMITATIONS:
        raise ValueError("artifact advisory limitations are invalid")

    source = _exact(
        advisory["source"],
        "artifact advisory source",
        ("format", "document_sha256", "authentication_boundary"),
    )
    _enum(source["format"], "artifact advisory source format", VEX_FORMATS)
    _digest(source["document_sha256"], "artifact advisory document digest")
    if source["authentication_boundary"] != "externally_verified_document_metadata":
        raise ValueError("artifact advisory authentication boundary is unsupported")
    vulnerability = _exact(
        advisory["vulnerability"],
        "artifact advisory vulnerability",
        ("identifier", "description_sha256"),
    )
    if (
        not isinstance(vulnerability["identifier"], str)
        or _VULNERABILITY.fullmatch(vulnerability["identifier"]) is None
    ):
        raise ValueError("artifact advisory vulnerability identifier is invalid")
    _digest(vulnerability["description_sha256"], "vulnerability description digest")

    components, adjacency, roots = _lineage_indexes(reviewed_lineage)
    statements: dict[str, Mapping[str, Any]] = {}
    actionable: set[str] = set()
    for index, raw in enumerate(
        _bounded_list(advisory["statements"], "artifact advisory statements", MAX_COMPONENTS)
    ):
        statement = _exact(
            raw,
            f"artifact advisory statements[{index}]",
            ("component_id", "sha256", "status", "justification"),
        )
        component_id = _identifier(statement["component_id"], "advisory component id")
        if component_id in statements:
            raise ValueError("artifact advisory contains duplicate component statements")
        if component_id not in components:
            raise ValueError("artifact advisory references an unknown lineage component")
        _digest(statement["sha256"], "artifact advisory component digest")
        if statement["sha256"] != components[component_id]["sha256"]:
            raise ValueError("artifact advisory component digest does not match lineage")
        status = _enum(statement["status"], "artifact advisory status", VEX_STATUSES)
        justification = statement["justification"]
        if status == "not_affected":
            _enum(justification, "not_affected justification", NOT_AFFECTED_JUSTIFICATIONS)
        elif justification is not None:
            raise ValueError("only not_affected statements may carry a justification")
        if status in ACTIONABLE_STATUSES:
            actionable.add(component_id)
        statements[component_id] = statement
    if not actionable:
        raise ValueError("artifact advisory must contain an actionable component statement")

    thresholds = _exact(
        advisory["thresholds"],
        "artifact advisory thresholds",
        ("quarantine_deadline_ms", "recovery_deadline_ms"),
    )
    quarantine_ms = _integer(
        thresholds["quarantine_deadline_ms"], "quarantine deadline", 1, 86_400_000
    )
    recovery_ms = _integer(thresholds["recovery_deadline_ms"], "recovery deadline", 2, 172_800_000)
    if recovery_ms <= quarantine_ms:
        raise ValueError("recovery deadline must follow quarantine deadline")
    if issued_at_ms + recovery_ms > 259_200_000:
        raise ValueError("artifact advisory benchmark clock exceeds the bounded horizon")

    impacted_roots: dict[tuple[str, str], list[dict[str, Any]]] = {}
    reached_targets: set[str] = set()
    for root_key, root_component in sorted(roots.items()):
        paths = []
        for target in sorted(actionable):
            component_path = _path(adjacency, root_component, target)
            if component_path is not None:
                reached_targets.add(target)
                paths.append(
                    {
                        "root_component_id": root_component,
                        "target_component_id": target,
                        "component_ids": component_path,
                    }
                )
        if paths:
            impacted_roots[root_key] = paths
    if reached_targets != actionable:
        raise ValueError("artifact advisory targets no reachable deployment root")

    replacements: dict[tuple[str, str], Mapping[str, Any]] = {}
    original_roots = _artifact_roots(plan)
    target_digests = {components[item]["sha256"] for item in actionable}
    for index, raw in enumerate(
        _bounded_list(advisory["replacements"], "artifact advisory replacements", MAX_COMPONENTS)
    ):
        replacement = _exact(
            raw,
            f"artifact advisory replacements[{index}]",
            (
                "workload_principal_id",
                "artifact_id",
                "replacement_sha256",
                "provenance_statement_sha256",
            ),
        )
        key = (
            _identifier(replacement["workload_principal_id"], "replacement workload"),
            _identifier(replacement["artifact_id"], "replacement artifact"),
        )
        if key in replacements:
            raise ValueError("artifact advisory contains duplicate replacements")
        replacement_digest = _digest(
            replacement["replacement_sha256"], "replacement artifact digest"
        )
        _digest(replacement["provenance_statement_sha256"], "replacement provenance digest")
        if key not in original_roots:
            raise ValueError("artifact advisory replacement references an unknown artifact root")
        if (
            replacement_digest == original_roots[key]["sha256"]
            or replacement_digest in target_digests
        ):
            raise ValueError("replacement digest must differ from recalled artifact material")
        replacements[key] = replacement
    if set(replacements) != set(impacted_roots):
        raise ValueError("artifact advisory must replace every impacted artifact root exactly once")
    return dict(advisory), impacted_roots


def validate_artifact_advisory(
    value: Any, artifact_plan: Mapping[str, Any], lineage: Mapping[str, Any]
) -> Dict[str, Any]:
    advisory, _ = _review_advisory(value, artifact_plan, lineage)
    return advisory


def _artifact_set(
    artifacts: Sequence[Mapping[str, Any]],
    replacements: Mapping[str, Mapping[str, Any]],
) -> str:
    values = [
        {
            "artifact_id": artifact["artifact_id"],
            "role": artifact["role"],
            "sha256": replacements.get(artifact["artifact_id"], artifact)[
                "replacement_sha256" if artifact["artifact_id"] in replacements else "sha256"
            ],
        }
        for artifact in sorted(artifacts, key=lambda item: item["role"])
    ]
    return _sha256(_canonical({"artifacts": values}))


def compose_recall_plan(
    artifact_plan: Mapping[str, Any],
    lineage: Mapping[str, Any],
    advisory: Mapping[str, Any],
) -> Dict[str, Any]:
    reviewed_plan = validate_artifact_plan(artifact_plan)
    reviewed_lineage = validate_artifact_lineage(lineage, reviewed_plan)
    reviewed_advisory, impacted_roots = _review_advisory(advisory, reviewed_plan, reviewed_lineage)
    components, adjacency, roots = _lineage_indexes(reviewed_lineage)
    actionable = {
        item["component_id"]
        for item in reviewed_advisory["statements"]
        if item["status"] in ACTIONABLE_STATUSES
    }
    affected_components = {
        component_id
        for component_id in components
        if any(_path(adjacency, component_id, target) is not None for target in actionable)
    }
    replacements = {
        (item["workload_principal_id"], item["artifact_id"]): item
        for item in reviewed_advisory["replacements"]
    }
    issued_at_ms = reviewed_advisory["issued_at_ms"]
    quarantine_ms = reviewed_advisory["thresholds"]["quarantine_deadline_ms"]
    recovery_ms = reviewed_advisory["thresholds"]["recovery_deadline_ms"]

    deployments = []
    probes = []
    deployment_ids: set[str] = set()
    for workload in sorted(
        reviewed_plan["workloads"], key=lambda item: item["workload_principal_id"]
    ):
        workload_id = workload["workload_principal_id"]
        impacted_artifact_ids = sorted(
            artifact_id
            for candidate_workload, artifact_id in impacted_roots
            if candidate_workload == workload_id
        )
        replacement_by_id = {
            artifact_id: replacements[(workload_id, artifact_id)]
            for artifact_id in impacted_artifact_ids
        }
        paths = sorted(
            (
                path
                for key, key_paths in impacted_roots.items()
                if key[0] == workload_id
                for path in key_paths
            ),
            key=lambda item: (item["root_component_id"], item["target_component_id"]),
        )
        triggers = sorted({item["target_component_id"] for item in paths})
        original_set = _artifact_set(workload["artifacts"], {})
        recovered_set = _artifact_set(workload["artifacts"], replacement_by_id)
        for node_id in sorted(workload["node_ids"]):
            identity = _sha256(f"{workload_id}\x00{node_id}".encode("utf-8"))[:20]
            deployment_id = f"deployment-{identity}"
            if deployment_id in deployment_ids:
                raise ValueError("derived artifact deployment identifier collision")
            deployment_ids.add(deployment_id)
            affected = bool(impacted_artifact_ids)
            deployment = {
                "deployment_id": deployment_id,
                "workload_principal_id": workload_id,
                "spiffe_id": workload["spiffe_id"],
                "node_id": node_id,
                "affected": affected,
                "original_artifact_set_sha256": original_set,
                "recovered_artifact_set_sha256": recovered_set,
                "affected_artifact_ids": impacted_artifact_ids,
                "trigger_component_ids": triggers,
                "impact_paths": paths,
                "replacements": [replacement_by_id[key] for key in sorted(replacement_by_id)],
            }
            deployments.append(deployment)
            probe_specs = [
                (
                    "pre_advisory",
                    issued_at_ms - 1,
                    original_set,
                    "allow",
                    "artifact_authorized",
                ),
                (
                    "post_quarantine_deadline",
                    issued_at_ms + quarantine_ms,
                    original_set,
                    "block" if affected else "allow",
                    "artifact_quarantined" if affected else "unaffected_artifact_preserved",
                ),
                (
                    "post_recovery_deadline",
                    issued_at_ms + recovery_ms,
                    recovered_set,
                    "allow",
                    "replacement_authorized" if affected else "unaffected_artifact_preserved",
                ),
            ]
            for phase, attempted_at_ms, artifact_set, decision, reason in probe_specs:
                probes.append(
                    {
                        "probe_id": f"{deployment_id}-{phase}",
                        "deployment_id": deployment_id,
                        "phase": phase,
                        "attempted_at_ms": attempted_at_ms,
                        "artifact_set_sha256": artifact_set,
                        "expected_decision": decision,
                        "expected_reason": reason,
                    }
                )
    if not 1 <= len(deployments) <= MAX_DEPLOYMENTS or len(probes) > MAX_PROBES:
        raise ValueError("derived LureRecall deployment/probe matrix exceeds bounded limits")
    affected_deployments = [item for item in deployments if item["affected"]]
    if not affected_deployments:
        raise ValueError("artifact advisory does not affect a declared deployment")
    affected_nodes = sorted({item["node_id"] for item in affected_deployments})
    affected_workloads = sorted({item["workload_principal_id"] for item in affected_deployments})
    result = {
        "schema": PLAN_SCHEMA,
        "schema_version": 1,
        "plan_id": reviewed_advisory["advisory_id"],
        "created_at": reviewed_advisory["issued_at"],
        "system_id": reviewed_plan["system_id"],
        "artifact_plan": reviewed_plan,
        "artifact_plan_sha256": _sha256(_canonical(reviewed_plan)),
        "lineage": reviewed_lineage,
        "lineage_sha256": _sha256(_canonical(reviewed_lineage)),
        "advisory": reviewed_advisory,
        "advisory_sha256": _sha256(_canonical(reviewed_advisory)),
        "impact": {
            "actionable_component_ids": sorted(actionable),
            "affected_component_ids": sorted(affected_components),
            "affected_root_artifact_count": len(impacted_roots),
            "affected_workload_ids": affected_workloads,
            "affected_node_ids": affected_nodes,
        },
        "deployments": deployments,
        "probes": sorted(probes, key=lambda item: (item["deployment_id"], item["attempted_at_ms"])),
        "standards": [
            "cisa-vex-minimum-requirements-2023",
            "guac-dependency-graph-concepts",
            "nist-sp-800-61r3",
            "openvex-status-model",
        ],
        "limitations": list(PLAN_LIMITATIONS),
    }
    return _validate_recall_plan_shape(result)


def _validate_recall_plan_shape(value: Any) -> Dict[str, Any]:
    plan = _exact(
        value,
        "LureRecall plan",
        (
            "schema",
            "schema_version",
            "plan_id",
            "created_at",
            "system_id",
            "artifact_plan",
            "artifact_plan_sha256",
            "lineage",
            "lineage_sha256",
            "advisory",
            "advisory_sha256",
            "impact",
            "deployments",
            "probes",
            "standards",
            "limitations",
        ),
    )
    if plan["schema"] != PLAN_SCHEMA or plan["schema_version"] != 1:
        raise ValueError("unsupported LureRecall plan schema")
    _identifier(plan["plan_id"], "LureRecall plan id")
    _timestamp(plan["created_at"], "LureRecall plan created_at")
    _identifier(plan["system_id"], "LureRecall system id")
    artifact_plan = validate_artifact_plan(plan["artifact_plan"])
    lineage = validate_artifact_lineage(plan["lineage"], artifact_plan)
    validate_artifact_advisory(plan["advisory"], artifact_plan, lineage)
    bindings = (
        ("artifact_plan_sha256", artifact_plan),
        ("lineage_sha256", lineage),
        ("advisory_sha256", plan["advisory"]),
    )
    for field, source in bindings:
        _digest(plan[field], f"LureRecall {field}")
        if plan[field] != _sha256(_canonical(source)):
            raise ValueError(f"LureRecall {field} does not bind its embedded source")
    impact = _exact(
        plan["impact"],
        "LureRecall impact",
        (
            "actionable_component_ids",
            "affected_component_ids",
            "affected_root_artifact_count",
            "affected_workload_ids",
            "affected_node_ids",
        ),
    )
    for field in (
        "actionable_component_ids",
        "affected_component_ids",
        "affected_workload_ids",
        "affected_node_ids",
    ):
        values = _bounded_list(impact[field], f"LureRecall impact {field}", MAX_COMPONENTS)
        if values != sorted(values) or len(set(values)) != len(values):
            raise ValueError(f"LureRecall impact {field} must be sorted and unique")
        for item in values:
            _identifier(item, f"LureRecall impact {field} item")
    _integer(
        impact["affected_root_artifact_count"],
        "LureRecall affected root artifact count",
        1,
        MAX_COMPONENTS,
    )

    deployment_ids = set()
    for index, raw in enumerate(
        _bounded_list(plan["deployments"], "LureRecall deployments", MAX_DEPLOYMENTS)
    ):
        deployment = _exact(
            raw,
            f"LureRecall deployments[{index}]",
            (
                "deployment_id",
                "workload_principal_id",
                "spiffe_id",
                "node_id",
                "affected",
                "original_artifact_set_sha256",
                "recovered_artifact_set_sha256",
                "affected_artifact_ids",
                "trigger_component_ids",
                "impact_paths",
                "replacements",
            ),
        )
        deployment_id = _identifier(deployment["deployment_id"], "deployment id")
        if deployment_id in deployment_ids:
            raise ValueError("LureRecall contains duplicate deployment identifiers")
        deployment_ids.add(deployment_id)
        _identifier(deployment["workload_principal_id"], "deployment workload")
        if not isinstance(deployment["spiffe_id"], str):
            raise ValueError("deployment spiffe_id must be text")
        _identifier(deployment["node_id"], "deployment node")
        if not isinstance(deployment["affected"], bool):
            raise ValueError("deployment affected must be boolean")
        _digest(deployment["original_artifact_set_sha256"], "original artifact set")
        _digest(deployment["recovered_artifact_set_sha256"], "recovered artifact set")
        for field in ("affected_artifact_ids", "trigger_component_ids"):
            values = _bounded_list(
                deployment[field],
                f"deployment {field}",
                MAX_COMPONENTS,
                allow_empty=not deployment["affected"],
            )
            if values != sorted(values) or len(set(values)) != len(values):
                raise ValueError(f"deployment {field} must be sorted and unique")
            for item in values:
                _identifier(item, f"deployment {field} item")
        paths = _bounded_list(
            deployment["impact_paths"],
            "deployment impact paths",
            MAX_RELATIONSHIPS,
            allow_empty=not deployment["affected"],
        )
        for path in paths:
            path = _exact(
                path,
                "deployment impact path",
                ("root_component_id", "target_component_id", "component_ids"),
            )
            _identifier(path["root_component_id"], "impact root component")
            _identifier(path["target_component_id"], "impact target component")
            component_ids = _bounded_list(
                path["component_ids"], "impact path components", MAX_COMPONENTS
            )
            for item in component_ids:
                _identifier(item, "impact path component")
        replacement_values = _bounded_list(
            deployment["replacements"],
            "deployment replacements",
            MAX_COMPONENTS,
            allow_empty=not deployment["affected"],
        )
        for replacement in replacement_values:
            replacement = _exact(
                replacement,
                "deployment replacement",
                (
                    "workload_principal_id",
                    "artifact_id",
                    "replacement_sha256",
                    "provenance_statement_sha256",
                ),
            )
            _identifier(replacement["workload_principal_id"], "replacement workload")
            _identifier(replacement["artifact_id"], "replacement artifact")
            _digest(replacement["replacement_sha256"], "replacement digest")
            _digest(replacement["provenance_statement_sha256"], "replacement provenance")

    probe_ids = set()
    for index, raw in enumerate(_bounded_list(plan["probes"], "LureRecall probes", MAX_PROBES)):
        probe = _exact(
            raw,
            f"LureRecall probes[{index}]",
            (
                "probe_id",
                "deployment_id",
                "phase",
                "attempted_at_ms",
                "artifact_set_sha256",
                "expected_decision",
                "expected_reason",
            ),
        )
        probe_id = _identifier(probe["probe_id"], "LureRecall probe id")
        if probe_id in probe_ids:
            raise ValueError("LureRecall contains duplicate probe identifiers")
        probe_ids.add(probe_id)
        if probe["deployment_id"] not in deployment_ids:
            raise ValueError("LureRecall probe references an unknown deployment")
        _enum(probe["phase"], "LureRecall probe phase", PHASES)
        _integer(probe["attempted_at_ms"], "LureRecall probe time", 0, 259_200_000)
        _digest(probe["artifact_set_sha256"], "LureRecall probe artifact set")
        _enum(probe["expected_decision"], "LureRecall expected decision", DECISIONS)
        _enum(probe["expected_reason"], "LureRecall expected reason", REASONS)
    if plan["standards"] != [
        "cisa-vex-minimum-requirements-2023",
        "guac-dependency-graph-concepts",
        "nist-sp-800-61r3",
        "openvex-status-model",
    ]:
        raise ValueError("LureRecall standards declaration is invalid")
    if plan["limitations"] != PLAN_LIMITATIONS:
        raise ValueError("LureRecall plan limitations are invalid")
    return dict(plan)


def validate_recall_plan(value: Any) -> Dict[str, Any]:
    reviewed = _validate_recall_plan_shape(value)
    expected = compose_recall_plan(
        reviewed["artifact_plan"], reviewed["lineage"], reviewed["advisory"]
    )
    if reviewed != expected:
        raise ValueError("LureRecall plan does not independently recompile")
    return reviewed


def _implementation(value: Any) -> Dict[str, Any]:
    implementation = _exact(
        value, "LureRecall implementation", ("name", "version", "artifact_sha256")
    )
    _identifier(implementation["name"], "LureRecall implementation name")
    if (
        not isinstance(implementation["version"], str)
        or not 1 <= len(implementation["version"]) <= 64
    ):
        raise ValueError("LureRecall implementation version must be bounded text")
    _digest(implementation["artifact_sha256"], "LureRecall implementation digest")
    return dict(implementation)


def validate_recall_run(value: Any) -> Dict[str, Any]:
    run = _exact(
        value,
        "LureRecall run",
        (
            "schema",
            "schema_version",
            "run_id",
            "generated_at",
            "implementation",
            "plan_sha256",
            "advisory_observations",
            "response_observations",
            "limitations",
        ),
    )
    if run["schema"] != RUN_SCHEMA or run["schema_version"] != 1:
        raise ValueError("unsupported LureRecall run schema")
    _identifier(run["run_id"], "LureRecall run id")
    _timestamp(run["generated_at"], "LureRecall run generated_at")
    _implementation(run["implementation"])
    _digest(run["plan_sha256"], "LureRecall run plan digest")
    observation_ids = set()
    for index, raw in enumerate(
        _bounded_list(
            run["advisory_observations"],
            "LureRecall advisory observations",
            MAX_OBSERVATIONS,
            allow_empty=True,
        )
    ):
        observation = _exact(
            raw,
            f"LureRecall advisory observations[{index}]",
            (
                "observation_id",
                "node_id",
                "received_at_ms",
                "advisory_sha256",
                "disposition",
            ),
        )
        observation_id = _identifier(observation["observation_id"], "advisory observation id")
        if observation_id in observation_ids:
            raise ValueError("LureRecall run contains duplicate observation identifiers")
        observation_ids.add(observation_id)
        _identifier(observation["node_id"], "advisory observation node")
        _integer(observation["received_at_ms"], "advisory received time", 0, 259_200_000)
        _digest(observation["advisory_sha256"], "observed advisory digest")
        _enum(observation["disposition"], "advisory disposition", DISPOSITIONS)
    for index, raw in enumerate(
        _bounded_list(
            run["response_observations"],
            "LureRecall response observations",
            MAX_OBSERVATIONS,
            allow_empty=True,
        )
    ):
        observation = _exact(
            raw,
            f"LureRecall response observations[{index}]",
            (
                "observation_id",
                "probe_id",
                "decision",
                "reason_code",
                "observed_artifact_set_sha256",
            ),
        )
        observation_id = _identifier(observation["observation_id"], "response observation id")
        if observation_id in observation_ids:
            raise ValueError("LureRecall run contains duplicate observation identifiers")
        observation_ids.add(observation_id)
        _identifier(observation["probe_id"], "response probe id")
        decision = _enum(observation["decision"], "response decision", DECISIONS)
        _enum(observation["reason_code"], "response reason", REASONS)
        artifact_set = observation["observed_artifact_set_sha256"]
        if decision == "allow":
            _digest(artifact_set, "allowed response artifact set")
        elif artifact_set is not None:
            raise ValueError("blocked response must not claim an active artifact set")
    if run["limitations"] != RUN_LIMITATIONS:
        raise ValueError("LureRecall run limitations are invalid")
    return dict(run)


def reference_recall_run(
    plan: Mapping[str, Any],
    *,
    run_id: str = "lurerecall-reference-run",
    generated_at: Optional[str] = None,
    implementation_name: str = "reference-recall-controller",
    implementation_version: str = VERSION,
    implementation_artifact_sha256: Optional[str] = None,
) -> Dict[str, Any]:
    reviewed = validate_recall_plan(plan)
    digest = implementation_artifact_sha256 or _sha256(
        f"{implementation_name}:{implementation_version}".encode("utf-8")
    )
    advisory = reviewed["advisory"]
    delivery_delay = min(50, advisory["thresholds"]["quarantine_deadline_ms"])
    result = {
        "schema": RUN_SCHEMA,
        "schema_version": 1,
        "run_id": run_id,
        "generated_at": generated_at or _now(),
        "implementation": {
            "name": implementation_name,
            "version": implementation_version,
            "artifact_sha256": digest,
        },
        "plan_sha256": _sha256(_canonical(reviewed)),
        "advisory_observations": [
            {
                "observation_id": f"advisory-{index:05d}",
                "node_id": node_id,
                "received_at_ms": advisory["issued_at_ms"] + delivery_delay,
                "advisory_sha256": reviewed["advisory_sha256"],
                "disposition": "applied",
            }
            for index, node_id in enumerate(reviewed["impact"]["affected_node_ids"], start=1)
        ],
        "response_observations": [
            {
                "observation_id": f"response-{index:05d}",
                "probe_id": probe["probe_id"],
                "decision": probe["expected_decision"],
                "reason_code": probe["expected_reason"],
                "observed_artifact_set_sha256": (
                    probe["artifact_set_sha256"] if probe["expected_decision"] == "allow" else None
                ),
            }
            for index, probe in enumerate(reviewed["probes"], start=1)
        ],
        "limitations": list(RUN_LIMITATIONS),
    }
    return validate_recall_run(result)


def _finding(
    reason: str,
    *,
    subject_type: str,
    subject_id: str,
    phase: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "finding_id": "",
        "reason": reason,
        "subject_type": subject_type,
        "subject_id": subject_id,
        "phase": phase,
    }


def _percentile(values: Sequence[int], fraction: float) -> Optional[int]:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]


def _evaluation_value(
    plan: Mapping[str, Any], run: Mapping[str, Any], generated_at: str
) -> Dict[str, Any]:
    reviewed_plan = validate_recall_plan(plan)
    reviewed_run = validate_recall_run(run)
    _timestamp(generated_at, "LureRecall evaluation generated_at")
    findings: list[Dict[str, Any]] = []
    plan_digest = _sha256(_canonical(reviewed_plan))
    if reviewed_run["plan_sha256"] != plan_digest:
        findings.append(
            _finding(
                "plan_digest_mismatch",
                subject_type="run",
                subject_id=reviewed_run["run_id"],
            )
        )
    if _time(reviewed_run["generated_at"]) < _time(reviewed_plan["created_at"]):
        findings.append(
            _finding(
                "run_predates_plan",
                subject_type="run",
                subject_id=reviewed_run["run_id"],
            )
        )
    if _time(generated_at) < _time(reviewed_run["generated_at"]):
        findings.append(
            _finding(
                "evaluation_predates_run",
                subject_type="run",
                subject_id=reviewed_run["run_id"],
            )
        )

    advisory = reviewed_plan["advisory"]
    required_nodes = set(reviewed_plan["impact"]["affected_node_ids"])
    delivery_by_node: dict[str, list[Mapping[str, Any]]] = {}
    for observation in reviewed_run["advisory_observations"]:
        delivery_by_node.setdefault(observation["node_id"], []).append(observation)
    for node_id in sorted(set(delivery_by_node) - required_nodes):
        findings.append(
            _finding("advisory_delivery_unexpected", subject_type="node", subject_id=node_id)
        )
    delivery_delays: list[int] = []
    on_time_nodes = set()
    complete_nodes = set()
    for node_id in sorted(required_nodes):
        observations = delivery_by_node.get(node_id, [])
        if not observations:
            findings.append(
                _finding("advisory_delivery_missing", subject_type="node", subject_id=node_id)
            )
            continue
        if len(observations) != 1:
            findings.append(
                _finding("advisory_delivery_duplicate", subject_type="node", subject_id=node_id)
            )
        valid = [
            item
            for item in observations
            if item["disposition"] == "applied"
            and item["advisory_sha256"] == reviewed_plan["advisory_sha256"]
        ]
        if len(observations) != 1 or len(valid) != 1:
            findings.append(
                _finding("advisory_delivery_invalid", subject_type="node", subject_id=node_id)
            )
            continue
        complete_nodes.add(node_id)
        delay = valid[0]["received_at_ms"] - advisory["issued_at_ms"]
        if delay < 0:
            findings.append(
                _finding("advisory_received_before_issue", subject_type="node", subject_id=node_id)
            )
            continue
        delivery_delays.append(delay)
        if delay <= advisory["thresholds"]["quarantine_deadline_ms"]:
            on_time_nodes.add(node_id)
        else:
            findings.append(
                _finding("advisory_delivery_late", subject_type="node", subject_id=node_id)
            )

    expected_probes = {item["probe_id"]: item for item in reviewed_plan["probes"]}
    response_by_probe: dict[str, list[Mapping[str, Any]]] = {}
    for observation in reviewed_run["response_observations"]:
        response_by_probe.setdefault(observation["probe_id"], []).append(observation)
    for probe_id in sorted(set(response_by_probe) - set(expected_probes)):
        findings.append(
            _finding("response_probe_unexpected", subject_type="probe", subject_id=probe_id)
        )
    exact_probes: set[str] = set()
    for probe_id, probe in expected_probes.items():
        observations = response_by_probe.get(probe_id, [])
        if not observations:
            findings.append(
                _finding(
                    "response_probe_missing",
                    subject_type="probe",
                    subject_id=probe_id,
                    phase=probe["phase"],
                )
            )
            continue
        if len(observations) != 1:
            findings.append(
                _finding(
                    "response_probe_duplicate",
                    subject_type="probe",
                    subject_id=probe_id,
                    phase=probe["phase"],
                )
            )
            continue
        observation = observations[0]
        exact = True
        if observation["decision"] != probe["expected_decision"]:
            exact = False
            if (
                probe["phase"] == "post_quarantine_deadline"
                and probe["expected_decision"] == "block"
            ):
                reason = "compromised_artifact_allowed_post_deadline"
            elif (
                probe["phase"] == "post_recovery_deadline"
                and probe["expected_reason"] == "replacement_authorized"
            ):
                reason = "replacement_unavailable"
            elif probe["expected_reason"] == "unaffected_artifact_preserved":
                reason = "collateral_block"
            else:
                reason = "baseline_artifact_denied"
            findings.append(
                _finding(
                    reason,
                    subject_type="probe",
                    subject_id=probe_id,
                    phase=probe["phase"],
                )
            )
        if observation["reason_code"] != probe["expected_reason"]:
            exact = False
            findings.append(
                _finding(
                    "response_reason_mismatch",
                    subject_type="probe",
                    subject_id=probe_id,
                    phase=probe["phase"],
                )
            )
        expected_set = (
            probe["artifact_set_sha256"] if probe["expected_decision"] == "allow" else None
        )
        if observation["observed_artifact_set_sha256"] != expected_set:
            exact = False
            if (
                probe["phase"] == "post_recovery_deadline"
                and probe["expected_reason"] == "replacement_authorized"
            ):
                reason = "replacement_artifact_set_mismatch"
            elif probe["expected_reason"] == "unaffected_artifact_preserved":
                reason = "unaffected_artifact_set_mismatch"
            else:
                reason = "baseline_artifact_set_mismatch"
            findings.append(
                _finding(
                    reason,
                    subject_type="probe",
                    subject_id=probe_id,
                    phase=probe["phase"],
                )
            )
        if exact:
            exact_probes.add(probe_id)

    deployments = {item["deployment_id"]: item for item in reviewed_plan["deployments"]}
    probes_by_key = {
        (item["deployment_id"], item["phase"]): item for item in reviewed_plan["probes"]
    }

    def phase_success(deployment_id: str, phase: str) -> bool:
        return probes_by_key[(deployment_id, phase)]["probe_id"] in exact_probes

    affected = [item for item in deployments.values() if item["affected"]]
    unaffected = [item for item in deployments.values() if not item["affected"]]
    quarantine_passes = sum(
        phase_success(item["deployment_id"], "post_quarantine_deadline") for item in affected
    )
    recovery_passes = sum(
        phase_success(item["deployment_id"], "post_recovery_deadline") for item in affected
    )
    unaffected_probes = [
        probes_by_key[(item["deployment_id"], phase)]
        for item in unaffected
        for phase in ("post_quarantine_deadline", "post_recovery_deadline")
    ]
    unaffected_passes = sum(item["probe_id"] in exact_probes for item in unaffected_probes)
    all_pre = [
        probes_by_key[(item["deployment_id"], "pre_advisory")] for item in deployments.values()
    ]
    matrix_exact = set(response_by_probe) == set(expected_probes) and all(
        len(response_by_probe[probe_id]) == 1 for probe_id in expected_probes
    )
    reason_counts: dict[str, int] = {}
    for finding in findings:
        reason_counts[finding["reason"]] = reason_counts.get(finding["reason"], 0) + 1
    checks = [
        {
            "check_id": "plan_run_contract_bound",
            "status": "fail"
            if any(
                reason_counts.get(reason, 0)
                for reason in (
                    "evaluation_predates_run",
                    "plan_digest_mismatch",
                    "run_predates_plan",
                )
            )
            else "pass",
        },
        {
            "check_id": "advisory_delivery_complete",
            "status": "pass"
            if complete_nodes == required_nodes and set(delivery_by_node) == required_nodes
            else "fail",
        },
        {
            "check_id": "advisory_delivery_within_deadline",
            "status": "pass" if on_time_nodes == required_nodes else "fail",
        },
        {
            "check_id": "pre_advisory_baseline_preserved",
            "status": "pass"
            if all(item["probe_id"] in exact_probes for item in all_pre)
            else "fail",
        },
        {
            "check_id": "affected_artifacts_quarantined",
            "status": "pass" if quarantine_passes == len(affected) else "fail",
        },
        {
            "check_id": "exact_replacements_recovered",
            "status": "pass" if recovery_passes == len(affected) else "fail",
        },
        {
            "check_id": "unaffected_deployments_preserved",
            "status": "pass" if unaffected_passes == len(unaffected_probes) else "fail",
        },
        {
            "check_id": "response_observation_matrix_complete",
            "status": "pass" if matrix_exact else "fail",
        },
    ]
    if len(findings) > MAX_FINDINGS:
        raise ValueError("LureRecall evaluation findings exceed the bounded limit")
    for index, finding in enumerate(
        sorted(
            findings,
            key=lambda item: (
                item["reason"],
                item["subject_type"],
                item["subject_id"],
                item["phase"] or "",
            ),
        ),
        start=1,
    ):
        finding["finding_id"] = f"finding-{index:05d}"
    findings.sort(key=lambda item: item["finding_id"])
    verdict = "pass" if all(item["status"] == "pass" for item in checks) else "fail"
    denominator = len(required_nodes)
    result = {
        "schema": EVALUATION_SCHEMA,
        "schema_version": 1,
        "generated_at": generated_at,
        "implementation": {"name": "lurebench", "version": __version__},
        "plan": reviewed_plan,
        "plan_sha256": plan_digest,
        "run": reviewed_run,
        "run_sha256": _sha256(_canonical(reviewed_run)),
        "summary": {
            "actionable_component_count": len(reviewed_plan["impact"]["actionable_component_ids"]),
            "affected_component_count": len(reviewed_plan["impact"]["affected_component_ids"]),
            "affected_root_artifact_count": reviewed_plan["impact"]["affected_root_artifact_count"],
            "affected_workload_count": len(reviewed_plan["impact"]["affected_workload_ids"]),
            "affected_deployment_count": len(affected),
            "affected_node_count": len(required_nodes),
            "required_delivery_count": denominator,
            "on_time_delivery_count": len(on_time_nodes),
            "delivery_coverage_rate": len(complete_nodes) / denominator,
            "on_time_delivery_rate": len(on_time_nodes) / denominator,
            "p95_delivery_ms": _percentile(delivery_delays, 0.95),
            "maximum_delivery_ms": max(delivery_delays) if delivery_delays else None,
            "expected_probe_count": len(expected_probes),
            "observed_probe_count": len(reviewed_run["response_observations"]),
            "quarantine_recall": quarantine_passes / len(affected),
            "recovery_recall": recovery_passes / len(affected),
            "unaffected_preservation_rate": (
                unaffected_passes / len(unaffected_probes) if unaffected_probes else None
            ),
            "post_deadline_compromised_allow_count": reason_counts.get(
                "compromised_artifact_allowed_post_deadline", 0
            ),
            "wrong_replacement_count": reason_counts.get("replacement_artifact_set_mismatch", 0),
            "collateral_block_count": reason_counts.get("collateral_block", 0),
            "finding_count": len(findings),
            "verdict": verdict,
        },
        "checks": checks,
        "findings": findings,
        "limitations": list(EVALUATION_LIMITATIONS),
    }
    return result


def evaluate_recall_run(
    plan: Mapping[str, Any],
    run: Mapping[str, Any],
    *,
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    return _evaluation_value(plan, run, generated_at or _now())


def validate_recall_evaluation(value: Any) -> Dict[str, Any]:
    evaluation = _exact(
        value,
        "LureRecall evaluation",
        (
            "schema",
            "schema_version",
            "generated_at",
            "implementation",
            "plan",
            "plan_sha256",
            "run",
            "run_sha256",
            "summary",
            "checks",
            "findings",
            "limitations",
        ),
    )
    if evaluation["schema"] != EVALUATION_SCHEMA or evaluation["schema_version"] != 1:
        raise ValueError("unsupported LureRecall evaluation schema")
    implementation = _exact(
        evaluation["implementation"], "LureRecall evaluator", ("name", "version")
    )
    if implementation["name"] != "lurebench":
        raise ValueError("LureRecall evaluator implementation is unsupported")
    expected = _evaluation_value(evaluation["plan"], evaluation["run"], evaluation["generated_at"])
    expected["implementation"]["version"] = implementation["version"]
    if evaluation != expected:
        raise ValueError("LureRecall evaluation does not independently recompute")
    return dict(evaluation)


def _read(path: Path, label: str) -> Dict[str, Any]:
    if path.is_symlink():
        raise ValueError(f"refusing symbolic-link {label}: {path}")
    if not path.is_file():
        raise FileNotFoundError(path)
    if path.stat().st_size > MAX_BYTES:
        raise ValueError(f"{label} exceeds {MAX_BYTES} bytes")
    value = loads_strict_json(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _write(path: Path, value: Mapping[str, Any]) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(_canonical(value))
    except Exception:
        path.unlink(missing_ok=True)
        raise


def load_artifact_lineage(path: Path, artifact_plan: Mapping[str, Any]) -> Dict[str, Any]:
    return validate_artifact_lineage(_read(Path(path), "artifact lineage"), artifact_plan)


def load_artifact_advisory(
    path: Path, artifact_plan: Mapping[str, Any], lineage: Mapping[str, Any]
) -> Dict[str, Any]:
    return validate_artifact_advisory(
        _read(Path(path), "artifact advisory"), artifact_plan, lineage
    )


def load_recall_plan(path: Path) -> Dict[str, Any]:
    return validate_recall_plan(_read(Path(path), "LureRecall plan"))


def load_recall_run(path: Path) -> Dict[str, Any]:
    return validate_recall_run(_read(Path(path), "LureRecall run"))


def load_recall_evaluation(path: Path) -> Dict[str, Any]:
    return validate_recall_evaluation(_read(Path(path), "LureRecall evaluation"))


def write_recall_plan(path: Path, value: Mapping[str, Any]) -> None:
    _write(Path(path), validate_recall_plan(value))


def write_recall_run(path: Path, value: Mapping[str, Any]) -> None:
    _write(Path(path), validate_recall_run(value))


def write_recall_evaluation(path: Path, value: Mapping[str, Any]) -> None:
    _write(Path(path), validate_recall_evaluation(value))
