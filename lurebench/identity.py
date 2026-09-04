"""Identity-lifecycle authorization-closure benchmark.

LureIdentity models authority as a directed graph from grants to humans, agents,
and workloads.  Each lifecycle event is evaluated independently against the
same preregistered graph.  The evaluator recomputes which authorizations must be
cut, which controls must be preserved, signal delivery, and access decisions.

Artifacts contain typed synthetic metadata only.  They are not SCIM messages,
credentials, policy-engine requests, or proof that an external identity event
was authenticated or enforced.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence

from . import __version__
from .permit import _canonical, _exact, _identifier, _integer, _rate, _timestamp
from .receipts import loads_strict_json
from .spiffe import parse_spiffe_id

PLAN_SCHEMA = "https://github.com/immu4989/lurebench/spec/lureidentity-plan-v1"
RUN_SCHEMA = "https://github.com/immu4989/lurebench/spec/lureidentity-run-v1"
EVALUATION_SCHEMA = "https://github.com/immu4989/lurebench/spec/lureidentity-evaluation-v1"
VERSION = "1.0.0"
MAX_BYTES = 4 * 1024 * 1024
MAX_PRINCIPALS = 128
MAX_EDGES = 256
MAX_GRANTS = 256
MAX_NODES = 64
MAX_EVENTS = 64
MAX_PROBES = 8192

PRINCIPAL_KINDS = {"agent", "group", "human", "workload"}
RELATIONSHIPS = {"delegates_to", "member_of", "runs_as"}
EVENT_TYPES = {
    "delegation_revoked",
    "scim_group_membership_removed",
    "scim_user_deactivated",
    "workload_retired",
}
ACTIONS = {"administer", "credential_use", "invoke", "read", "write"}
DISPOSITIONS = {"applied", "duplicate", "invalid"}
DECISIONS = {"allow", "block"}
REASONS = {
    "authority_active",
    "authority_path_cut",
    "authority_preserved",
    "lifecycle_event_pending",
}
_DIGEST = re.compile(r"^[a-f0-9]{64}$")

PLAN_LIMITATIONS = [
    "synthetic_identity_and_authorization_metadata_only_no_credentials_tokens_or_payloads",
    "scim_fields_are_a_lifecycle_projection_not_scim_http_patch_or_endpoint_conformance",
    "event_authentication_delivery_clock_quality_and_complete_mediation_are_external_controls",
    "finite_graph_closure_results_do_not_prove_zero_trust_compliance_or_system_containment",
]
RUN_LIMITATIONS = [
    "observations_are_claimed_receiver_metadata_not_proof_of_event_or_enforcement_authenticity",
    "reference_run_is_offline_and_contacts_no_directory_agent_workload_or_policy_engine",
    "invalid_and_duplicate_events_are_synthetic_and_contain_no_reusable_security_material",
]
EVALUATION_LIMITATIONS = [
    "authority_closure_and_metrics_are_recomputed_from_embedded_plan_and_run_metadata",
    "a_graph_cut_covers_only_preregistered_principals_edges_grants_nodes_and_probes",
    "passing_does_not_establish_identity_proofing_event_authenticity_or_complete_mediation",
    "evaluation_is_not_certification_authorization_or_a_claim_of_scim_interoperability",
]


Authorization = tuple[str, str, str]


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _enum(value: Any, field: str, allowed: set[str]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise ValueError(f"{field} is unsupported")
    return value


def _boolean(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{field} must be boolean")
    return value


def _nullable_id(value: Any, field: str) -> Optional[str]:
    return None if value is None else _identifier(value, field)


def _ids(values: Any, field: str, maximum: int) -> list[str]:
    if not isinstance(values, list) or not 1 <= len(values) <= maximum:
        raise ValueError(f"{field} must be a non-empty bounded array")
    normalized = [_identifier(value, f"{field}[{index}]") for index, value in enumerate(values)]
    if len(set(normalized)) != len(normalized):
        raise ValueError(f"{field} contains duplicate identifiers")
    return normalized


def _event_material(event: Mapping[str, Any]) -> Dict[str, Any]:
    return {key: event[key] for key in event if key != "event_sha256"}


def _expected_event_digest(event: Mapping[str, Any]) -> str:
    return _sha256(_canonical(_event_material(event)))


def _adjacency(
    principals: Mapping[str, Mapping[str, Any]],
    edges: Sequence[Mapping[str, Any]],
) -> dict[str, list[str]]:
    result = {principal_id: [] for principal_id in principals}
    for edge in edges:
        result[edge["source_id"]].append(edge["target_id"])
    for targets in result.values():
        targets.sort()
    return result


def _assert_acyclic(adjacency: Mapping[str, Sequence[str]]) -> None:
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(principal_id: str) -> None:
        if principal_id in visiting:
            raise ValueError("authority graph must be acyclic")
        if principal_id in visited:
            return
        visiting.add(principal_id)
        for target_id in adjacency[principal_id]:
            visit(target_id)
        visiting.remove(principal_id)
        visited.add(principal_id)

    for principal_id in sorted(adjacency):
        visit(principal_id)


def _descendants(adjacency: Mapping[str, Sequence[str]], start_id: str) -> set[str]:
    result: set[str] = set()
    pending = [start_id]
    while pending:
        principal_id = pending.pop()
        if principal_id in result:
            continue
        result.add(principal_id)
        pending.extend(adjacency[principal_id])
    return result


def _authorizations(
    principals: Mapping[str, Mapping[str, Any]],
    edges: Sequence[Mapping[str, Any]],
    grants: Sequence[Mapping[str, Any]],
) -> set[Authorization]:
    active = {
        principal_id for principal_id, principal in principals.items() if principal["active"] is True
    }
    active_edges = [
        edge
        for edge in edges
        if edge["source_id"] in active and edge["target_id"] in active
    ]
    adjacency = _adjacency(principals, active_edges)
    result: set[Authorization] = set()
    for grant in grants:
        if grant["principal_id"] not in active:
            continue
        for actor_id in _descendants(adjacency, grant["principal_id"]):
            if actor_id in active:
                result.add((actor_id, grant["resource_id"], grant["action"]))
    return result


def _event_state(
    plan: Mapping[str, Any], event: Mapping[str, Any]
) -> tuple[set[Authorization], set[Authorization]]:
    principals = {item["principal_id"]: dict(item) for item in plan["principals"]}
    edges = [dict(item) for item in plan["authority_edges"]]
    baseline = _authorizations(principals, edges, plan["grants"])
    if event["event_type"] in {"scim_user_deactivated", "workload_retired"}:
        principals[event["target_principal_id"]]["active"] = False
    else:
        edges = [item for item in edges if item["edge_id"] != event["target_edge_id"]]
    return baseline, _authorizations(principals, edges, plan["grants"])


def _event_cut(plan: Mapping[str, Any], event: Mapping[str, Any]) -> set[Authorization]:
    baseline, after = _event_state(plan, event)
    return baseline - after


def _validate_relationship(
    edge: Mapping[str, Any], principals: Mapping[str, Mapping[str, Any]], field: str
) -> None:
    source_kind = principals[edge["source_id"]]["kind"]
    target_kind = principals[edge["target_id"]]["kind"]
    relationship = edge["relationship"]
    valid = (
        relationship == "member_of"
        and source_kind == "group"
        and target_kind == "human"
        or relationship == "delegates_to"
        and source_kind in {"human", "agent"}
        and target_kind == "agent"
        or relationship == "runs_as"
        and source_kind == "agent"
        and target_kind == "workload"
    )
    if not valid:
        raise ValueError(f"{field} has incompatible principal kinds")


def validate_identity_plan(value: Any) -> Dict[str, Any]:
    plan = _exact(
        value,
        "identity plan",
        (
            "schema",
            "schema_version",
            "plan_id",
            "created_at",
            "system_id",
            "directory",
            "principals",
            "authority_edges",
            "grants",
            "nodes",
            "events",
            "probes",
            "acceptance",
            "limitations",
        ),
    )
    if plan["schema"] != PLAN_SCHEMA or plan["schema_version"] != 1:
        raise ValueError("unsupported LureIdentity plan schema")
    for field in ("plan_id", "system_id"):
        _identifier(plan[field], f"plan.{field}")
    _timestamp(plan["created_at"], "plan.created_at")
    directory = _exact(
        plan["directory"],
        "plan.directory",
        ("issuer_id", "tenant_id", "profile", "authentication_boundary"),
    )
    for field in ("issuer_id", "tenant_id"):
        _identifier(directory[field], f"plan.directory.{field}")
    if directory["profile"] != "ietf-scim-rfc7643-lifecycle-metadata-projection":
        raise ValueError("plan directory profile is unsupported")
    if directory["authentication_boundary"] != "externally_authenticated_and_authorized":
        raise ValueError("plan directory authentication boundary is unsupported")

    if not isinstance(plan["principals"], list) or not 1 <= len(
        plan["principals"]
    ) <= MAX_PRINCIPALS:
        raise ValueError("plan.principals must be a non-empty bounded array")
    principals: dict[str, Mapping[str, Any]] = {}
    for index, item in enumerate(plan["principals"]):
        principal = _exact(
            item,
            f"plan.principals[{index}]",
            ("principal_id", "kind", "active", "spiffe_id"),
        )
        principal_id = _identifier(principal["principal_id"], "principal.principal_id")
        if principal_id in principals:
            raise ValueError("plan.principals contains duplicate identifiers")
        kind = _enum(principal["kind"], "principal.kind", PRINCIPAL_KINDS)
        _boolean(principal["active"], "principal.active")
        spiffe_id = principal["spiffe_id"]
        if kind == "workload":
            try:
                parse_spiffe_id(spiffe_id, "principal.spiffe_id", require_path=True)
            except ValueError as exc:
                raise ValueError(
                    "workload principal requires a canonical SPIFFE ID"
                ) from exc

        elif spiffe_id is not None:
            raise ValueError("only workload principals may declare a SPIFFE ID")
        principals[principal_id] = principal

    if not isinstance(plan["authority_edges"], list) or len(
        plan["authority_edges"]
    ) > MAX_EDGES:
        raise ValueError("plan.authority_edges must be a bounded array")
    edges: dict[str, Mapping[str, Any]] = {}
    edge_pairs: set[tuple[str, str, str]] = set()
    for index, item in enumerate(plan["authority_edges"]):
        edge = _exact(
            item,
            f"plan.authority_edges[{index}]",
            ("edge_id", "source_id", "target_id", "relationship"),
        )
        edge_id = _identifier(edge["edge_id"], "authority edge id")
        source_id = _identifier(edge["source_id"], "authority edge source")
        target_id = _identifier(edge["target_id"], "authority edge target")
        _enum(edge["relationship"], "authority edge relationship", RELATIONSHIPS)
        if edge_id in edges:
            raise ValueError("plan.authority_edges contains duplicate edge identifiers")
        if source_id not in principals or target_id not in principals or source_id == target_id:
            raise ValueError("authority edge references an unknown or identical principal")
        pair = (source_id, target_id, edge["relationship"])
        if pair in edge_pairs:
            raise ValueError("plan.authority_edges contains a duplicate relationship")
        edge_pairs.add(pair)
        _validate_relationship(edge, principals, f"plan.authority_edges[{index}]")
        edges[edge_id] = edge
    adjacency = _adjacency(principals, list(edges.values()))
    _assert_acyclic(adjacency)

    if not isinstance(plan["grants"], list) or not 1 <= len(plan["grants"]) <= MAX_GRANTS:
        raise ValueError("plan.grants must be a non-empty bounded array")
    grants: list[Mapping[str, Any]] = []
    grant_ids: set[str] = set()
    grant_tuples: set[tuple[str, str, str]] = set()
    for index, item in enumerate(plan["grants"]):
        grant = _exact(
            item,
            f"plan.grants[{index}]",
            ("grant_id", "principal_id", "resource_id", "action"),
        )
        grant_id = _identifier(grant["grant_id"], "grant id")
        principal_id = _identifier(grant["principal_id"], "grant principal")
        resource_id = _identifier(grant["resource_id"], "grant resource")
        action = _enum(grant["action"], "grant action", ACTIONS)
        if grant_id in grant_ids:
            raise ValueError("plan.grants contains duplicate grant identifiers")
        if principal_id not in principals:
            raise ValueError("grant references an unknown principal")
        grant_tuple = (principal_id, resource_id, action)
        if grant_tuple in grant_tuples:
            raise ValueError("plan.grants contains duplicate authority")
        grant_ids.add(grant_id)
        grant_tuples.add(grant_tuple)
        grants.append(grant)

    if not isinstance(plan["nodes"], list) or not 1 <= len(plan["nodes"]) <= MAX_NODES:
        raise ValueError("plan.nodes must be a non-empty bounded array")
    nodes: list[str] = []
    for index, item in enumerate(plan["nodes"]):
        node = _exact(item, f"plan.nodes[{index}]", ("node_id", "enforcement_point_id"))
        nodes.append(_identifier(node["node_id"], "node id"))
        _identifier(node["enforcement_point_id"], "node enforcement point")
    if len(set(nodes)) != len(nodes):
        raise ValueError("plan.nodes contains duplicate identifiers")

    if not isinstance(plan["events"], list) or not 1 <= len(plan["events"]) <= MAX_EVENTS:
        raise ValueError("plan.events must be a non-empty bounded array")
    events: dict[str, Mapping[str, Any]] = {}
    sequences: set[int] = set()
    for index, item in enumerate(plan["events"]):
        event = _exact(
            item,
            f"plan.events[{index}]",
            (
                "event_id",
                "sequence",
                "occurred_at_ms",
                "event_type",
                "target_principal_id",
                "target_edge_id",
                "required_cut_actor_ids",
                "required_preserve_actor_ids",
                "source_event_sha256",
                "event_sha256",
            ),
        )
        event_id = _identifier(event["event_id"], "event id")
        if event_id in events:
            raise ValueError("plan.events contains duplicate identifiers")
        sequence = _integer(event["sequence"], "event.sequence", 1, 1_000_000)
        if sequence in sequences:
            raise ValueError("plan.events contains duplicate sequences")
        sequences.add(sequence)
        _integer(event["occurred_at_ms"], "event.occurred_at_ms", 1, 86_400_000)
        event_type = _enum(event["event_type"], "event.event_type", EVENT_TYPES)
        target_principal_id = _nullable_id(
            event["target_principal_id"], "event.target_principal_id"
        )
        target_edge_id = _nullable_id(event["target_edge_id"], "event.target_edge_id")
        cut_ids = _ids(event["required_cut_actor_ids"], "required cut actors", MAX_PRINCIPALS)
        preserve_ids = _ids(
            event["required_preserve_actor_ids"], "required preserve actors", MAX_PRINCIPALS
        )
        if set(cut_ids) & set(preserve_ids):
            raise ValueError("event cut and preserve actors must be disjoint")
        if any(actor_id not in principals for actor_id in cut_ids + preserve_ids):
            raise ValueError("event references an unknown cut or preserve actor")
        if event_type == "scim_user_deactivated":
            if (
                target_principal_id not in principals
                or principals[target_principal_id]["kind"] != "human"
                or target_edge_id is not None
            ):
                raise ValueError("SCIM user deactivation must target one human principal")
            cone = _descendants(adjacency, target_principal_id)
        elif event_type == "workload_retired":
            if (
                target_principal_id not in principals
                or principals[target_principal_id]["kind"] != "workload"
                or target_edge_id is not None
            ):
                raise ValueError("workload retirement must target one workload principal")
            cone = _descendants(adjacency, target_principal_id)
        else:
            expected_relationship = (
                "member_of" if event_type == "scim_group_membership_removed" else "delegates_to"
            )
            if (
                target_principal_id is not None
                or target_edge_id not in edges
                or edges[target_edge_id]["relationship"] != expected_relationship
            ):
                raise ValueError("edge lifecycle event targets an incompatible authority edge")
            cone = _descendants(adjacency, edges[target_edge_id]["target_id"])
        if not set(cut_ids) <= cone:
            raise ValueError("required cut actors must be in the event dependency cone")
        if set(preserve_ids) & cone:
            raise ValueError("required preserve actors must be outside the event dependency cone")
        _digest(event["source_event_sha256"], "event.source_event_sha256")
        _digest(event["event_sha256"], "event.event_sha256")
        if event["event_sha256"] != _expected_event_digest(event):
            raise ValueError("event digest does not reconcile")
        events[event_id] = event
    if sorted(sequences) != list(range(1, len(sequences) + 1)):
        raise ValueError("plan event sequences must be contiguous from one")

    baseline = _authorizations(principals, list(edges.values()), grants)
    event_states: dict[str, tuple[set[Authorization], set[Authorization]]] = {}
    for event_id, event in events.items():
        before, after = _event_state(plan, event)
        event_states[event_id] = (before, after)
        if before != baseline or not before - after:
            raise ValueError("each lifecycle event must cut at least one authorization")
        affected_actor_ids = {item[0] for item in before - after}
        if affected_actor_ids != set(event["required_cut_actor_ids"]):
            raise ValueError("required cut actors must exactly cover the event authorization cut")
        for actor_id in event["required_cut_actor_ids"]:
            actor_before = {item for item in before if item[0] == actor_id}
            actor_after = {item for item in after if item[0] == actor_id}
            if not actor_before or actor_after:
                raise ValueError("required cut actor must lose every baseline authorization")
        for actor_id in event["required_preserve_actor_ids"]:
            actor_before = {item for item in before if item[0] == actor_id}
            actor_after = {item for item in after if item[0] == actor_id}
            if not actor_before or actor_after != actor_before:
                raise ValueError("required preserve actor must retain every baseline authorization")

    acceptance = _exact(
        plan["acceptance"],
        "plan.acceptance",
        (
            "maximum_convergence_ms",
            "maximum_deadline_miss_count",
            "maximum_post_deadline_stale_allow_count",
            "maximum_collateral_block_count",
            "minimum_delivery_coverage_rate",
            "minimum_cut_recall",
            "minimum_pre_event_allow_rate",
            "minimum_preserved_allow_rate",
            "minimum_signal_disposition_accuracy",
        ),
    )
    deadline = _integer(
        acceptance["maximum_convergence_ms"], "maximum_convergence_ms", 1, 600_000
    )
    for field in (
        "maximum_deadline_miss_count",
        "maximum_post_deadline_stale_allow_count",
        "maximum_collateral_block_count",
    ):
        _integer(acceptance[field], field, 0, MAX_PROBES)
    for field in (
        "minimum_delivery_coverage_rate",
        "minimum_cut_recall",
        "minimum_pre_event_allow_rate",
        "minimum_preserved_allow_rate",
        "minimum_signal_disposition_accuracy",
    ):
        _rate(acceptance[field], field)

    if not isinstance(plan["probes"], list) or not 1 <= len(plan["probes"]) <= MAX_PROBES:
        raise ValueError("plan.probes must be a non-empty bounded array")
    probes: dict[str, Mapping[str, Any]] = {}
    probe_index: set[tuple[str, str, Authorization, str]] = set()
    for index, item in enumerate(plan["probes"]):
        probe = _exact(
            item,
            f"plan.probes[{index}]",
            (
                "probe_id",
                "event_id",
                "node_id",
                "attempted_at_ms",
                "actor_id",
                "resource_id",
                "action",
            ),
        )
        probe_id = _identifier(probe["probe_id"], "probe id")
        if probe_id in probes:
            raise ValueError("plan.probes contains duplicate identifiers")
        if probe["event_id"] not in events or probe["node_id"] not in nodes:
            raise ValueError("probe references an unknown event or node")
        _integer(probe["attempted_at_ms"], "probe.attempted_at_ms", 0, 86_400_000)
        authorization = (
            _identifier(probe["actor_id"], "probe.actor_id"),
            _identifier(probe["resource_id"], "probe.resource_id"),
            _enum(probe["action"], "probe.action", ACTIONS),
        )
        if authorization not in baseline:
            raise ValueError("every probe authorization must be allowed in the baseline graph")
        event = events[probe["event_id"]]
        occurred = event["occurred_at_ms"]
        phase = (
            "pre"
            if probe["attempted_at_ms"] < occurred
            else "post"
            if probe["attempted_at_ms"] >= occurred + deadline
            else "window"
        )
        key = (probe["event_id"], probe["node_id"], authorization, phase)
        if key in probe_index:
            raise ValueError("plan.probes contains a duplicate authorization phase")
        probe_index.add(key)
        probes[probe_id] = probe

    for event_id, event in events.items():
        before, after = event_states[event_id]
        required_cut = {
            item for item in before - after if item[0] in event["required_cut_actor_ids"]
        }
        required_preserve = {
            item for item in before if item[0] in event["required_preserve_actor_ids"]
        }
        for node_id in nodes:
            for authorization in required_cut:
                if (event_id, node_id, authorization, "pre") not in probe_index:
                    raise ValueError("plan must probe every required cut before each event")
                if (event_id, node_id, authorization, "post") not in probe_index:
                    raise ValueError("plan must probe every required cut after each deadline")
            for authorization in required_preserve:
                if (event_id, node_id, authorization, "post") not in probe_index:
                    raise ValueError("plan must probe every required preserved authorization")
    if plan["limitations"] != PLAN_LIMITATIONS:
        raise ValueError("plan limitations are invalid")
    return dict(plan)


def _validate_implementation(value: Any, field: str) -> Dict[str, Any]:
    implementation = _exact(value, field, ("name", "version", "artifact_sha256"))
    _identifier(implementation["name"], f"{field}.name")
    _identifier(implementation["version"], f"{field}.version")
    if implementation["artifact_sha256"] is not None:
        _digest(implementation["artifact_sha256"], f"{field}.artifact_sha256")
    return dict(implementation)


def validate_identity_run(value: Any, plan: Mapping[str, Any]) -> Dict[str, Any]:
    reviewed_plan = validate_identity_plan(plan)
    run = _exact(
        value,
        "identity run",
        (
            "schema",
            "schema_version",
            "run_id",
            "generated_at",
            "implementation",
            "plan_sha256",
            "event_observations",
            "access_observations",
            "limitations",
        ),
    )
    if run["schema"] != RUN_SCHEMA or run["schema_version"] != 1:
        raise ValueError("unsupported LureIdentity run schema")
    _identifier(run["run_id"], "run.run_id")
    _timestamp(run["generated_at"], "run.generated_at")
    if _time(run["generated_at"]) < _time(reviewed_plan["created_at"]):
        raise ValueError("run cannot predate its plan")
    _validate_implementation(run["implementation"], "run.implementation")
    _digest(run["plan_sha256"], "run.plan_sha256")
    if run["plan_sha256"] != _sha256(_canonical(reviewed_plan)):
        raise ValueError("run plan digest does not reconcile")
    event_ids = {item["event_id"] for item in reviewed_plan["events"]}
    node_ids = {item["node_id"] for item in reviewed_plan["nodes"]}
    observations = run["event_observations"]
    if not isinstance(observations, list) or len(observations) > MAX_EVENTS * MAX_NODES * 4:
        raise ValueError("run.event_observations must be a bounded array")
    observation_ids: list[str] = []
    for index, item in enumerate(observations):
        observation = _exact(
            item,
            f"run.event_observations[{index}]",
            (
                "observation_id",
                "event_id",
                "node_id",
                "received_at_ms",
                "event_sha256",
                "disposition",
            ),
        )
        observation_ids.append(_identifier(observation["observation_id"], "observation id"))
        if observation["event_id"] not in event_ids or observation["node_id"] not in node_ids:
            raise ValueError("event observation references an unknown event or node")
        _integer(observation["received_at_ms"], "received_at_ms", 0, 86_400_000)
        _digest(observation["event_sha256"], "event observation digest")
        _enum(observation["disposition"], "event disposition", DISPOSITIONS)
    if len(set(observation_ids)) != len(observation_ids):
        raise ValueError("run contains duplicate event observation identifiers")

    probe_ids = {item["probe_id"] for item in reviewed_plan["probes"]}
    access = run["access_observations"]
    if not isinstance(access, list) or len(access) != len(probe_ids):
        raise ValueError("run must contain exactly one access observation per probe")
    submitted_ids: list[str] = []
    for index, item in enumerate(access):
        observation = _exact(
            item,
            f"run.access_observations[{index}]",
            ("probe_id", "decision", "reason_code"),
        )
        submitted_ids.append(_identifier(observation["probe_id"], "access probe id"))
        _enum(observation["decision"], "access decision", DECISIONS)
        _enum(observation["reason_code"], "access reason", REASONS)
    if set(submitted_ids) != probe_ids or len(set(submitted_ids)) != len(probe_ids):
        raise ValueError("run access observations do not exactly cover the plan probes")
    if run["limitations"] != RUN_LIMITATIONS:
        raise ValueError("run limitations are invalid")
    return dict(run)


def _event(
    event_id: str,
    sequence: int,
    occurred_at_ms: int,
    event_type: str,
    target_principal_id: Optional[str],
    target_edge_id: Optional[str],
    cut_actor_ids: list[str],
) -> Dict[str, Any]:
    event: Dict[str, Any] = {
        "event_id": event_id,
        "sequence": sequence,
        "occurred_at_ms": occurred_at_ms,
        "event_type": event_type,
        "target_principal_id": target_principal_id,
        "target_edge_id": target_edge_id,
        "required_cut_actor_ids": cut_actor_ids,
        "required_preserve_actor_ids": ["workload-beta"],
        "source_event_sha256": _sha256(
            f"lureidentity-synthetic-source-v1:{event_id}".encode("utf-8")
        ),
    }
    event["event_sha256"] = _expected_event_digest(event)
    return event


def default_identity_plan() -> Dict[str, Any]:
    principals = [
        {"principal_id": "group-ops", "kind": "group", "active": True, "spiffe_id": None},
        {"principal_id": "human-alice", "kind": "human", "active": True, "spiffe_id": None},
        {"principal_id": "agent-alpha", "kind": "agent", "active": True, "spiffe_id": None},
        {
            "principal_id": "workload-alpha",
            "kind": "workload",
            "active": True,
            "spiffe_id": "spiffe://example.com/agents/alpha",
        },
        {"principal_id": "human-bob", "kind": "human", "active": True, "spiffe_id": None},
        {"principal_id": "agent-beta", "kind": "agent", "active": True, "spiffe_id": None},
        {
            "principal_id": "workload-beta",
            "kind": "workload",
            "active": True,
            "spiffe_id": "spiffe://example.com/agents/beta",
        },
    ]
    edges = [
        {
            "edge_id": "membership-alice",
            "source_id": "group-ops",
            "target_id": "human-alice",
            "relationship": "member_of",
        },
        {
            "edge_id": "delegation-alpha",
            "source_id": "human-alice",
            "target_id": "agent-alpha",
            "relationship": "delegates_to",
        },
        {
            "edge_id": "runtime-alpha",
            "source_id": "agent-alpha",
            "target_id": "workload-alpha",
            "relationship": "runs_as",
        },
        {
            "edge_id": "membership-bob",
            "source_id": "group-ops",
            "target_id": "human-bob",
            "relationship": "member_of",
        },
        {
            "edge_id": "delegation-beta",
            "source_id": "human-bob",
            "target_id": "agent-beta",
            "relationship": "delegates_to",
        },
        {
            "edge_id": "runtime-beta",
            "source_id": "agent-beta",
            "target_id": "workload-beta",
            "relationship": "runs_as",
        },
    ]
    events = [
        _event(
            "identity-1",
            1,
            10_000,
            "scim_user_deactivated",
            "human-alice",
            None,
            ["human-alice", "agent-alpha", "workload-alpha"],
        ),
        _event(
            "identity-2",
            2,
            20_000,
            "scim_group_membership_removed",
            None,
            "membership-alice",
            ["human-alice", "agent-alpha", "workload-alpha"],
        ),
        _event(
            "identity-3",
            3,
            30_000,
            "delegation_revoked",
            None,
            "delegation-alpha",
            ["agent-alpha", "workload-alpha"],
        ),
        _event(
            "identity-4",
            4,
            40_000,
            "workload_retired",
            "workload-alpha",
            None,
            ["workload-alpha"],
        ),
    ]
    # The reference plan deliberately covers every mediation point in the
    # reference LurePermit Runtime profile.  A deployment must still generate
    # and independently review an identity-topology audit against its own
    # preregistered profile; this static reference list is not discovery.
    enforcement_point_ids = (
        "approval-gateway",
        "credential-broker",
        "delegation-broker",
        "egress-gateway",
        "evaluator-boundary",
        "incident-controller",
        "process-runner",
        "shared-storage",
        "tool-gateway",
    )
    nodes = [
        {
            "node_id": f"identity-{point_id}",
            "enforcement_point_id": point_id,
        }
        for point_id in enforcement_point_ids
    ]
    partial: Dict[str, Any] = {
        "schema": PLAN_SCHEMA,
        "schema_version": 1,
        "plan_id": "lureidentity-lifecycle-closure-v1",
        "created_at": "2026-09-03T00:00:00Z",
        "system_id": "synthetic-agent-system",
        "directory": {
            "issuer_id": "synthetic-directory",
            "tenant_id": "tenant-a",
            "profile": "ietf-scim-rfc7643-lifecycle-metadata-projection",
            "authentication_boundary": "externally_authenticated_and_authorized",
        },
        "principals": principals,
        "authority_edges": edges,
        "grants": [
            {
                "grant_id": "ops-registry-read",
                "principal_id": "group-ops",
                "resource_id": "mock-registry",
                "action": "read",
            }
        ],
        "nodes": nodes,
        "events": events,
        "probes": [],
        "acceptance": {
            "maximum_convergence_ms": 500,
            "maximum_deadline_miss_count": 0,
            "maximum_post_deadline_stale_allow_count": 0,
            "maximum_collateral_block_count": 0,
            "minimum_delivery_coverage_rate": 1.0,
            "minimum_cut_recall": 1.0,
            "minimum_pre_event_allow_rate": 1.0,
            "minimum_preserved_allow_rate": 1.0,
            "minimum_signal_disposition_accuracy": 1.0,
        },
        "limitations": list(PLAN_LIMITATIONS),
    }
    probes = []
    for event in events:
        cut = sorted(_event_cut(partial, event))
        preserve = sorted(
            item
            for item in _event_state(partial, event)[0]
            if item[0] in event["required_preserve_actor_ids"]
        )
        for node in nodes:
            for actor_id, resource_id, action in cut:
                if actor_id not in event["required_cut_actor_ids"]:
                    continue
                base = f"{event['event_id']}-{node['node_id']}-{actor_id}"
                for phase, offset in (("before", -50), ("window", 50), ("after", 550)):
                    probes.append(
                        {
                            "probe_id": f"{base}-{phase}",
                            "event_id": event["event_id"],
                            "node_id": node["node_id"],
                            "attempted_at_ms": event["occurred_at_ms"] + offset,
                            "actor_id": actor_id,
                            "resource_id": resource_id,
                            "action": action,
                        }
                    )
            for actor_id, resource_id, action in preserve:
                probes.append(
                    {
                        "probe_id": f"{event['event_id']}-{node['node_id']}-{actor_id}-control",
                        "event_id": event["event_id"],
                        "node_id": node["node_id"],
                        "attempted_at_ms": event["occurred_at_ms"] + 550,
                        "actor_id": actor_id,
                        "resource_id": resource_id,
                        "action": action,
                    }
                )
    partial["probes"] = probes
    return validate_identity_plan(partial)


def _expected_dispositions(
    plan: Mapping[str, Any], observations: Sequence[Mapping[str, Any]]
) -> tuple[dict[str, str], dict[tuple[str, str], int]]:
    events = {item["event_id"]: item for item in plan["events"]}
    seen: set[tuple[str, str]] = set()
    expected: dict[str, str] = {}
    applied: dict[tuple[str, str], int] = {}
    for observation in sorted(
        observations, key=lambda item: (item["received_at_ms"], item["observation_id"])
    ):
        event = events[observation["event_id"]]
        key = (observation["event_id"], observation["node_id"])
        valid = (
            observation["event_sha256"] == event["event_sha256"]
            and observation["received_at_ms"] >= event["occurred_at_ms"]
        )
        if not valid:
            disposition = "invalid"
        elif key in seen:
            disposition = "duplicate"
        else:
            disposition = "applied"
            seen.add(key)
            applied[key] = observation["received_at_ms"]
        expected[observation["observation_id"]] = disposition
    return expected, applied


def _expected_probe(
    plan: Mapping[str, Any],
    probe: Mapping[str, Any],
    event: Mapping[str, Any],
    applied_at: Optional[int],
) -> tuple[str, str, str]:
    authorization = (probe["actor_id"], probe["resource_id"], probe["action"])
    affected = authorization in _event_cut(plan, event)
    attempted = probe["attempted_at_ms"]
    deadline_at = event["occurred_at_ms"] + plan["acceptance"]["maximum_convergence_ms"]
    if not affected:
        return "allow", "authority_preserved", "unrelated_control"
    if attempted < event["occurred_at_ms"]:
        return "allow", "authority_active", "pre_event"
    if attempted >= deadline_at:
        return "block", "authority_path_cut", "post_deadline"
    if applied_at is not None and attempted >= applied_at:
        return "block", "authority_path_cut", "cut_effective"
    return "allow", "lifecycle_event_pending", "propagation_window"


def reference_identity_run(
    plan: Optional[Mapping[str, Any]] = None,
    *,
    run_id: str = "lureidentity-reference-run",
    implementation_name: str = "lureidentity-reference",
    implementation_version: str = VERSION,
    implementation_artifact_sha256: Optional[str] = None,
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    reviewed = validate_identity_plan(plan or default_identity_plan())
    observations = []
    for event_index, event in enumerate(reviewed["events"], start=1):
        for node_index, node in enumerate(reviewed["nodes"], start=1):
            # Keep all nine reference enforcement points inside the 500 ms
            # preregistered deadline while preserving distinct convergence
            # observations for percentile calculation.
            received = event["occurred_at_ms"] + node_index * 50
            if node_index == 1:
                observations.append(
                    {
                        "observation_id": f"event-{event_index}-{node_index}-invalid",
                        "event_id": event["event_id"],
                        "node_id": node["node_id"],
                        "received_at_ms": event["occurred_at_ms"] + 10,
                        "event_sha256": "0" * 64,
                        "disposition": "invalid",
                    }
                )
            observations.append(
                {
                    "observation_id": f"event-{event_index}-{node_index}-applied",
                    "event_id": event["event_id"],
                    "node_id": node["node_id"],
                    "received_at_ms": received,
                    "event_sha256": event["event_sha256"],
                    "disposition": "applied",
                }
            )
            if node_index == 1:
                observations.append(
                    {
                        "observation_id": f"event-{event_index}-{node_index}-duplicate",
                        "event_id": event["event_id"],
                        "node_id": node["node_id"],
                        "received_at_ms": received + 1,
                        "event_sha256": event["event_sha256"],
                        "disposition": "duplicate",
                    }
                )
    _, applied = _expected_dispositions(reviewed, observations)
    events = {item["event_id"]: item for item in reviewed["events"]}
    access = []
    for probe in reviewed["probes"]:
        decision, reason, _ = _expected_probe(
            reviewed,
            probe,
            events[probe["event_id"]],
            applied.get((probe["event_id"], probe["node_id"])),
        )
        access.append({"probe_id": probe["probe_id"], "decision": decision, "reason_code": reason})
    run = {
        "schema": RUN_SCHEMA,
        "schema_version": 1,
        "run_id": run_id,
        "generated_at": generated_at or _now(),
        "implementation": {
            "name": implementation_name,
            "version": implementation_version,
            "artifact_sha256": implementation_artifact_sha256,
        },
        "plan_sha256": _sha256(_canonical(reviewed)),
        "event_observations": observations,
        "access_observations": access,
        "limitations": list(RUN_LIMITATIONS),
    }
    return validate_identity_run(run, reviewed)


def _authorization_value(authorization: Authorization) -> Dict[str, str]:
    return {
        "actor_id": authorization[0],
        "resource_id": authorization[1],
        "action": authorization[2],
    }


def _evaluation_value(
    plan: Mapping[str, Any], run: Mapping[str, Any], generated_at: str
) -> Dict[str, Any]:
    reviewed_plan = validate_identity_plan(plan)
    reviewed_run = validate_identity_run(run, reviewed_plan)
    _timestamp(generated_at, "evaluation.generated_at")
    if _time(generated_at) < _time(reviewed_run["generated_at"]):
        raise ValueError("evaluation cannot predate its run")
    expected_dispositions, applied = _expected_dispositions(
        reviewed_plan, reviewed_run["event_observations"]
    )
    deadline = reviewed_plan["acceptance"]["maximum_convergence_ms"]
    events = {item["event_id"]: item for item in reviewed_plan["events"]}
    submitted = {item["probe_id"]: item for item in reviewed_run["access_observations"]}
    convergence_values: list[int] = []
    delivery_results = []
    deadline_misses = 0
    for event in reviewed_plan["events"]:
        for node in reviewed_plan["nodes"]:
            received = applied.get((event["event_id"], node["node_id"]))
            convergence = None if received is None else received - event["occurred_at_ms"]
            deadline_met = convergence is not None and convergence <= deadline
            if convergence is not None:
                convergence_values.append(convergence)
            deadline_misses += int(not deadline_met)
            delivery_results.append(
                {
                    "event_id": event["event_id"],
                    "node_id": node["node_id"],
                    "applied_at_ms": received,
                    "convergence_ms": convergence,
                    "deadline_met": deadline_met,
                }
            )

    event_results = []
    affected_count = 0
    for event in reviewed_plan["events"]:
        affected = sorted(_event_cut(reviewed_plan, event))
        affected_count += len(affected)
        event_results.append(
            {
                "event_id": event["event_id"],
                "event_type": event["event_type"],
                "affected_authorization_count": len(affected),
                "affected_authorizations": [_authorization_value(item) for item in affected],
            }
        )

    probe_results = []
    cut_total = cut_correct = 0
    pre_total = pre_correct = 0
    preserve_total = preserve_correct = 0
    stale_allows = collateral_blocks = 0
    incorrect_decisions = incorrect_reasons = 0
    for probe in reviewed_plan["probes"]:
        event = events[probe["event_id"]]
        expected_decision, expected_reason, phase = _expected_probe(
            reviewed_plan,
            probe,
            event,
            applied.get((probe["event_id"], probe["node_id"])),
        )
        actual = submitted[probe["probe_id"]]
        decision_correct = actual["decision"] == expected_decision
        reason_correct = actual["reason_code"] == expected_reason
        incorrect_decisions += int(not decision_correct)
        incorrect_reasons += int(not reason_correct)
        if expected_decision == "block":
            cut_total += 1
            cut_correct += int(actual["decision"] == "block")
        if phase == "pre_event":
            pre_total += 1
            pre_correct += int(actual["decision"] == "allow")
        if phase == "unrelated_control":
            preserve_total += 1
            preserve_correct += int(actual["decision"] == "allow")
            collateral_blocks += int(actual["decision"] == "block")
        if phase == "post_deadline" and actual["decision"] == "allow":
            stale_allows += 1
        classification = (
            "correct"
            if decision_correct and reason_correct
            else "stale_authorization"
            if expected_decision == "block" and actual["decision"] == "allow"
            else "collateral_denial"
            if phase == "unrelated_control" and actual["decision"] == "block"
            else "premature_denial"
            if expected_decision == "allow" and actual["decision"] == "block"
            else "wrong_reason"
        )
        probe_results.append(
            {
                "probe_id": probe["probe_id"],
                "event_id": probe["event_id"],
                "node_id": probe["node_id"],
                "actor_id": probe["actor_id"],
                "resource_id": probe["resource_id"],
                "action": probe["action"],
                "phase": phase,
                "expected_decision": expected_decision,
                "submitted_decision": actual["decision"],
                "expected_reason_code": expected_reason,
                "submitted_reason_code": actual["reason_code"],
                "classification": classification,
            }
        )

    disposition_correct = sum(
        item["disposition"] == expected_dispositions[item["observation_id"]]
        for item in reviewed_run["event_observations"]
    )
    disposition_total = len(reviewed_run["event_observations"])
    required_deliveries = len(reviewed_plan["events"]) * len(reviewed_plan["nodes"])
    coverage = len(applied) / required_deliveries
    max_convergence = max(convergence_values) if convergence_values else None
    if convergence_values:
        ordered = sorted(convergence_values)
        p95_convergence = ordered[math.ceil(0.95 * len(ordered)) - 1]
    else:
        p95_convergence = None
    cut_recall = cut_correct / cut_total if cut_total else 0.0
    pre_allow = pre_correct / pre_total if pre_total else 0.0
    preserved_allow = preserve_correct / preserve_total if preserve_total else 0.0
    disposition_accuracy = disposition_correct / disposition_total if disposition_total else 0.0
    acceptance = reviewed_plan["acceptance"]
    verdict = (
        "pass"
        if (
            coverage >= acceptance["minimum_delivery_coverage_rate"]
            and max_convergence is not None
            and max_convergence <= acceptance["maximum_convergence_ms"]
            and deadline_misses <= acceptance["maximum_deadline_miss_count"]
            and stale_allows <= acceptance["maximum_post_deadline_stale_allow_count"]
            and collateral_blocks <= acceptance["maximum_collateral_block_count"]
            and cut_recall >= acceptance["minimum_cut_recall"]
            and pre_allow >= acceptance["minimum_pre_event_allow_rate"]
            and preserved_allow >= acceptance["minimum_preserved_allow_rate"]
            and disposition_accuracy >= acceptance["minimum_signal_disposition_accuracy"]
            and incorrect_decisions == 0
            and incorrect_reasons == 0
        )
        else "fail"
    )
    return {
        "schema": EVALUATION_SCHEMA,
        "schema_version": 1,
        "generated_at": generated_at,
        "implementation": {"name": "lurebench", "version": __version__},
        "plan": reviewed_plan,
        "plan_sha256": _sha256(_canonical(reviewed_plan)),
        "run": reviewed_run,
        "run_sha256": _sha256(_canonical(reviewed_run)),
        "summary": {
            "principal_count": len(reviewed_plan["principals"]),
            "authority_edge_count": len(reviewed_plan["authority_edges"]),
            "grant_count": len(reviewed_plan["grants"]),
            "event_count": len(reviewed_plan["events"]),
            "node_count": len(reviewed_plan["nodes"]),
            "affected_authorization_count": affected_count,
            "required_delivery_count": required_deliveries,
            "applied_delivery_count": len(applied),
            "delivery_coverage_rate": coverage,
            "maximum_convergence_ms": max_convergence,
            "p95_convergence_ms": p95_convergence,
            "deadline_miss_count": deadline_misses,
            "post_deadline_stale_allow_count": stale_allows,
            "collateral_block_count": collateral_blocks,
            "cut_recall": cut_recall,
            "pre_event_allow_rate": pre_allow,
            "preserved_allow_rate": preserved_allow,
            "signal_disposition_accuracy": disposition_accuracy,
            "incorrect_decision_count": incorrect_decisions,
            "incorrect_reason_count": incorrect_reasons,
            "verdict": verdict,
        },
        "event_results": event_results,
        "delivery_results": delivery_results,
        "probe_results": probe_results,
        "limitations": list(EVALUATION_LIMITATIONS),
    }


def evaluate_identity_run(
    plan: Mapping[str, Any], run: Mapping[str, Any], *, generated_at: Optional[str] = None
) -> Dict[str, Any]:
    return _evaluation_value(plan, run, generated_at or _now())


def validate_identity_evaluation(value: Any) -> Dict[str, Any]:
    evaluation = _exact(
        value,
        "identity evaluation",
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
            "event_results",
            "delivery_results",
            "probe_results",
            "limitations",
        ),
    )
    if evaluation["schema"] != EVALUATION_SCHEMA or evaluation["schema_version"] != 1:
        raise ValueError("unsupported LureIdentity evaluation schema")
    _timestamp(evaluation["generated_at"], "evaluation.generated_at")
    expected = _evaluation_value(evaluation["plan"], evaluation["run"], evaluation["generated_at"])
    if evaluation != expected:
        raise ValueError("identity evaluation does not independently recompute")
    return dict(evaluation)


def _read(path: Path, label: str) -> Any:
    target = Path(path)
    if target.is_symlink() or not target.is_file() or target.parent.is_symlink():
        raise ValueError(f"{label} must be a regular local JSON file")
    if target.stat().st_size > MAX_BYTES:
        raise ValueError(f"{label} exceeds the 4 MiB limit")
    return loads_strict_json(target.read_bytes())


def _write(path: Path, value: Mapping[str, Any]) -> None:
    target = Path(path)
    descriptor = os.open(
        target,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(_canonical(value))
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        target.unlink(missing_ok=True)
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def load_identity_plan(path: Optional[Path] = None) -> Dict[str, Any]:
    return default_identity_plan() if path is None else validate_identity_plan(_read(path, "plan"))


def load_identity_run(path: Path, plan: Mapping[str, Any]) -> Dict[str, Any]:
    return validate_identity_run(_read(path, "run"), plan)


def write_identity_plan(path: Path, value: Mapping[str, Any]) -> None:
    _write(path, validate_identity_plan(value))


def write_identity_run(path: Path, value: Mapping[str, Any], plan: Mapping[str, Any]) -> None:
    _write(path, validate_identity_run(value, plan))


def write_identity_evaluation(path: Path, value: Mapping[str, Any]) -> None:
    _write(path, validate_identity_evaluation(value))
