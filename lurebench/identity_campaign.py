"""Compile reviewed identity lifecycle campaigns into exhaustive benchmark plans.

The compiler treats the campaign as preregistered metadata.  It derives graph
cuts and unrelated availability controls itself, expands them over every
declared enforcement node, and then submits the result to the ordinary
LureIdentity plan validator.  It does not discover production topology or
authenticate lifecycle events.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Mapping

from .identity import (
    ACTIONS,
    EVENT_TYPES,
    MAX_EDGES,
    MAX_EVENTS,
    MAX_GRANTS,
    MAX_NODES,
    MAX_PRINCIPALS,
    MAX_PROBES,
    PLAN_LIMITATIONS,
    PLAN_SCHEMA,
    PRINCIPAL_KINDS,
    RELATIONSHIPS,
    Authorization,
    _adjacency,
    _assert_acyclic,
    _authorizations,
    _boolean,
    _descendants,
    _digest,
    _enum,
    _event_state,
    _expected_event_digest,
    _nullable_id,
    _read,
    _validate_relationship,
    validate_identity_plan,
)
from .permit import _exact, _identifier, _integer, _rate, _timestamp
from .spiffe import parse_spiffe_id

CAMPAIGN_SCHEMA = "https://github.com/immu4989/lurebench/spec/lureidentity-campaign-v1"
CAMPAIGN_LIMITATIONS = [
    "synthetic_projected_identity_metadata_only_no_credentials_tokens_or_raw_directory_payloads",
    "campaign_composition_derives_graph_cuts_and_controls_but_does_not_discover_topology",
    "every_unchanged_baseline_actor_outside_each_event_cone_is_used_as_a_collateral_control",
    "composition_generates_probes_but_does_not_deliver_events_or_execute_access_requests",
    "finite_declared_graph_coverage_does_not_prove_complete_mediation_compliance_or_containment",
]


def _validate_directory(value: Any) -> Dict[str, Any]:
    directory = _exact(
        value,
        "campaign.directory",
        ("issuer_id", "tenant_id", "profile", "authentication_boundary"),
    )
    _identifier(directory["issuer_id"], "campaign.directory.issuer_id")
    _identifier(directory["tenant_id"], "campaign.directory.tenant_id")
    if (
        directory["profile"] != "ietf-scim-rfc7643-lifecycle-metadata-projection"
        or directory["authentication_boundary"]
        != "externally_authenticated_and_authorized"
    ):
        raise ValueError("campaign directory contract is unsupported")
    return dict(directory)


def _validate_graph(campaign: Mapping[str, Any]) -> tuple[
    dict[str, Mapping[str, Any]],
    list[Mapping[str, Any]],
    list[Mapping[str, Any]],
    list[Mapping[str, Any]],
]:
    raw_principals = campaign["principals"]
    if not isinstance(raw_principals, list) or not 1 <= len(raw_principals) <= MAX_PRINCIPALS:
        raise ValueError("campaign.principals must be a non-empty bounded array")
    principals: dict[str, Mapping[str, Any]] = {}
    for index, item in enumerate(raw_principals):
        principal = _exact(
            item,
            f"campaign.principals[{index}]",
            ("principal_id", "kind", "active", "spiffe_id"),
        )
        principal_id = _identifier(principal["principal_id"], "campaign principal id")
        if principal_id in principals:
            raise ValueError("campaign contains duplicate principal identifiers")
        kind = _enum(principal["kind"], "campaign principal kind", PRINCIPAL_KINDS)
        _boolean(principal["active"], "campaign principal active")
        if kind == "workload":
            parse_spiffe_id(principal["spiffe_id"], "campaign workload SPIFFE ID", require_path=True)
        elif principal["spiffe_id"] is not None:
            raise ValueError("only workload principals may declare a SPIFFE ID")
        principals[principal_id] = principal

    raw_edges = campaign["authority_edges"]
    if not isinstance(raw_edges, list) or len(raw_edges) > MAX_EDGES:
        raise ValueError("campaign.authority_edges must be a bounded array")
    edges: list[Mapping[str, Any]] = []
    edge_ids: set[str] = set()
    edge_tuples: set[tuple[str, str, str]] = set()
    for index, item in enumerate(raw_edges):
        edge = _exact(
            item,
            f"campaign.authority_edges[{index}]",
            ("edge_id", "source_id", "target_id", "relationship"),
        )
        edge_id = _identifier(edge["edge_id"], "campaign authority edge id")
        source_id = _identifier(edge["source_id"], "campaign authority edge source")
        target_id = _identifier(edge["target_id"], "campaign authority edge target")
        relationship = _enum(
            edge["relationship"], "campaign authority edge relationship", RELATIONSHIPS
        )
        if edge_id in edge_ids:
            raise ValueError("campaign contains duplicate authority edge identifiers")
        if source_id not in principals or target_id not in principals or source_id == target_id:
            raise ValueError("campaign authority edge references an unknown or identical principal")
        edge_tuple = (source_id, target_id, relationship)
        if edge_tuple in edge_tuples:
            raise ValueError("campaign contains a duplicate authority relationship")
        _validate_relationship(edge, principals, f"campaign.authority_edges[{index}]")
        edge_ids.add(edge_id)
        edge_tuples.add(edge_tuple)
        edges.append(edge)
    _assert_acyclic(_adjacency(principals, edges))

    raw_grants = campaign["grants"]
    if not isinstance(raw_grants, list) or not 1 <= len(raw_grants) <= MAX_GRANTS:
        raise ValueError("campaign.grants must be a non-empty bounded array")
    grants: list[Mapping[str, Any]] = []
    grant_ids: set[str] = set()
    grant_tuples: set[tuple[str, str, str]] = set()
    for index, item in enumerate(raw_grants):
        grant = _exact(
            item,
            f"campaign.grants[{index}]",
            ("grant_id", "principal_id", "resource_id", "action"),
        )
        grant_id = _identifier(grant["grant_id"], "campaign grant id")
        principal_id = _identifier(grant["principal_id"], "campaign grant principal")
        resource_id = _identifier(grant["resource_id"], "campaign grant resource")
        action = _enum(grant["action"], "campaign grant action", ACTIONS)
        if grant_id in grant_ids:
            raise ValueError("campaign contains duplicate grant identifiers")
        if principal_id not in principals:
            raise ValueError("campaign grant references an unknown principal")
        grant_tuple = (principal_id, resource_id, action)
        if grant_tuple in grant_tuples:
            raise ValueError("campaign contains duplicate grant authority")
        grant_ids.add(grant_id)
        grant_tuples.add(grant_tuple)
        grants.append(grant)

    raw_nodes = campaign["nodes"]
    if not isinstance(raw_nodes, list) or not 1 <= len(raw_nodes) <= MAX_NODES:
        raise ValueError("campaign.nodes must be a non-empty bounded array")
    nodes: list[Mapping[str, Any]] = []
    node_ids: set[str] = set()
    for index, item in enumerate(raw_nodes):
        node = _exact(
            item,
            f"campaign.nodes[{index}]",
            ("node_id", "enforcement_point_id"),
        )
        node_id = _identifier(node["node_id"], "campaign node id")
        _identifier(node["enforcement_point_id"], "campaign enforcement point id")
        if node_id in node_ids:
            raise ValueError("campaign contains duplicate node identifiers")
        node_ids.add(node_id)
        nodes.append(node)
    return principals, edges, grants, nodes


def _event_cone(
    event: Mapping[str, Any],
    principals: Mapping[str, Mapping[str, Any]],
    edges: Mapping[str, Mapping[str, Any]],
    adjacency: Mapping[str, list[str]],
) -> set[str]:
    event_type = event["event_type"]
    target_principal_id = event["target_principal_id"]
    target_edge_id = event["target_edge_id"]
    if event_type == "scim_user_deactivated":
        if (
            target_principal_id not in principals
            or principals[target_principal_id]["kind"] != "human"
            or target_edge_id is not None
        ):
            raise ValueError("SCIM user deactivation must target one human principal")
        return _descendants(adjacency, target_principal_id)
    if event_type == "workload_retired":
        if (
            target_principal_id not in principals
            or principals[target_principal_id]["kind"] != "workload"
            or target_edge_id is not None
        ):
            raise ValueError("workload retirement must target one workload principal")
        return _descendants(adjacency, target_principal_id)
    expected_relationship = (
        "member_of" if event_type == "scim_group_membership_removed" else "delegates_to"
    )
    if (
        target_principal_id is not None
        or target_edge_id not in edges
        or edges[target_edge_id]["relationship"] != expected_relationship
    ):
        raise ValueError("edge lifecycle event targets an incompatible authority edge")
    return _descendants(adjacency, edges[target_edge_id]["target_id"])


def _validate_events(
    campaign: Mapping[str, Any],
    principals: Mapping[str, Mapping[str, Any]],
    edge_list: list[Mapping[str, Any]],
) -> list[Mapping[str, Any]]:
    raw_events = campaign["events"]
    if not isinstance(raw_events, list) or not 1 <= len(raw_events) <= MAX_EVENTS:
        raise ValueError("campaign.events must be a non-empty bounded array")
    edges = {edge["edge_id"]: edge for edge in edge_list}
    adjacency = _adjacency(principals, edge_list)
    events: list[Mapping[str, Any]] = []
    event_ids: set[str] = set()
    occurred_values: list[int] = []
    for index, item in enumerate(raw_events):
        event = _exact(
            item,
            f"campaign.events[{index}]",
            (
                "event_id",
                "occurred_at_ms",
                "event_type",
                "target_principal_id",
                "target_edge_id",
                "source_event_sha256",
            ),
        )
        event_id = _identifier(event["event_id"], "campaign event id")
        if event_id in event_ids:
            raise ValueError("campaign contains duplicate event identifiers")
        event_ids.add(event_id)
        occurred_values.append(
            _integer(event["occurred_at_ms"], "campaign event occurrence", 1, 86_400_000)
        )
        _enum(event["event_type"], "campaign event type", EVENT_TYPES)
        _nullable_id(event["target_principal_id"], "campaign event target principal")
        _nullable_id(event["target_edge_id"], "campaign event target edge")
        _digest(event["source_event_sha256"], "campaign source event digest")
        _event_cone(event, principals, edges, adjacency)
        events.append(event)
    if occurred_values != sorted(set(occurred_values)):
        raise ValueError("campaign event occurrence times must increase strictly")
    return events


def _validate_acceptance(value: Any) -> Dict[str, Any]:
    acceptance = _exact(
        value,
        "campaign.acceptance",
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
    _integer(acceptance["maximum_convergence_ms"], "maximum_convergence_ms", 1, 600_000)
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
    return dict(acceptance)


def _validate_schedule(value: Any, *, deadline: int) -> Dict[str, Any]:
    schedule = _exact(
        value,
        "campaign.probe_schedule",
        ("pre_event_offset_ms", "propagation_probe_offset_ms", "post_deadline_offset_ms"),
    )
    _integer(schedule["pre_event_offset_ms"], "pre_event_offset_ms", 1, 600_000)
    propagation = _integer(
        schedule["propagation_probe_offset_ms"],
        "propagation_probe_offset_ms",
        1,
        600_000,
    )
    _integer(schedule["post_deadline_offset_ms"], "post_deadline_offset_ms", 1, 600_000)
    if propagation >= deadline:
        raise ValueError("propagation probe offset must be shorter than the convergence deadline")
    return dict(schedule)


def _validate_campaign_shape(value: Any) -> tuple[
    Dict[str, Any],
    dict[str, Mapping[str, Any]],
    list[Mapping[str, Any]],
    list[Mapping[str, Any]],
    list[Mapping[str, Any]],
    list[Mapping[str, Any]],
]:
    campaign = _exact(
        value,
        "identity campaign",
        (
            "schema",
            "schema_version",
            "campaign_id",
            "created_at",
            "system_id",
            "directory",
            "principals",
            "authority_edges",
            "grants",
            "nodes",
            "events",
            "acceptance",
            "probe_schedule",
            "limitations",
        ),
    )
    if campaign["schema"] != CAMPAIGN_SCHEMA or campaign["schema_version"] != 1:
        raise ValueError("unsupported LureIdentity campaign schema")
    _identifier(campaign["campaign_id"], "campaign.campaign_id")
    _timestamp(campaign["created_at"], "campaign.created_at")
    _identifier(campaign["system_id"], "campaign.system_id")
    _validate_directory(campaign["directory"])
    principals, edges, grants, nodes = _validate_graph(campaign)
    events = _validate_events(campaign, principals, edges)
    acceptance = _validate_acceptance(campaign["acceptance"])
    _validate_schedule(
        campaign["probe_schedule"], deadline=acceptance["maximum_convergence_ms"]
    )
    if campaign["limitations"] != CAMPAIGN_LIMITATIONS:
        raise ValueError("campaign limitations are invalid")
    return dict(campaign), principals, edges, grants, nodes, events


def _actor_authorizations(
    authorizations: set[Authorization], actor_id: str
) -> set[Authorization]:
    return {authorization for authorization in authorizations if authorization[0] == actor_id}


def compose_identity_plan(value: Mapping[str, Any]) -> Dict[str, Any]:
    """Derive an exhaustive, bounded LureIdentity plan from a campaign."""

    campaign, principals, edges, grants, nodes, source_events = _validate_campaign_shape(value)
    baseline = _authorizations(principals, edges, grants)
    if not baseline:
        raise ValueError("campaign graph must produce at least one baseline authorization")
    adjacency = _adjacency(principals, edges)
    edge_map = {edge["edge_id"]: edge for edge in edges}
    deadline = campaign["acceptance"]["maximum_convergence_ms"]
    schedule = campaign["probe_schedule"]
    first_event_at = source_events[0]["occurred_at_ms"]
    if schedule["pre_event_offset_ms"] > first_event_at:
        raise ValueError("pre-event probe offset cannot precede the campaign clock origin")

    partial: Dict[str, Any] = {
        "schema": PLAN_SCHEMA,
        "schema_version": 1,
        "plan_id": campaign["campaign_id"],
        "created_at": campaign["created_at"],
        "system_id": campaign["system_id"],
        "directory": dict(campaign["directory"]),
        "principals": [dict(item) for item in campaign["principals"]],
        "authority_edges": [dict(item) for item in campaign["authority_edges"]],
        "grants": [dict(item) for item in campaign["grants"]],
        "nodes": [dict(item) for item in campaign["nodes"]],
        "events": [],
        "probes": [],
        "acceptance": dict(campaign["acceptance"]),
        "limitations": list(PLAN_LIMITATIONS),
    }

    derived: list[tuple[Dict[str, Any], list[Authorization], list[Authorization]]] = []
    projected_probe_count = 0
    for event_index, source_event in enumerate(source_events, start=1):
        event: Dict[str, Any] = {
            **dict(source_event),
            "sequence": event_index,
            "required_cut_actor_ids": ["temporary"],
            "required_preserve_actor_ids": ["temporary"],
        }
        before, after = _event_state(partial, event)
        cut = sorted(before - after)
        if not cut:
            raise ValueError("every campaign lifecycle event must cut at least one authorization")
        cut_actor_ids = sorted({authorization[0] for authorization in cut})
        for actor_id in cut_actor_ids:
            if _actor_authorizations(after, actor_id):
                raise ValueError(
                    "campaign event only partially cuts a required actor; "
                    "LureIdentity requires complete actor deauthorization"
                )
        cone = _event_cone(source_event, principals, edge_map, adjacency)
        baseline_actor_ids = sorted({authorization[0] for authorization in before})
        preserve_actor_ids = [
            actor_id
            for actor_id in baseline_actor_ids
            if actor_id not in cone
            and _actor_authorizations(after, actor_id)
            == _actor_authorizations(before, actor_id)
        ]
        if not preserve_actor_ids:
            raise ValueError(
                "campaign event has no unaffected authorized actor outside its dependency cone"
            )
        preserve = sorted(
            authorization
            for authorization in before
            if authorization[0] in preserve_actor_ids
        )
        event["required_cut_actor_ids"] = cut_actor_ids
        event["required_preserve_actor_ids"] = preserve_actor_ids
        event["event_sha256"] = _expected_event_digest(event)
        partial["events"].append(event)
        derived.append((event, cut, preserve))
        projected_probe_count += len(nodes) * (3 * len(cut) + len(preserve))
    if projected_probe_count > MAX_PROBES:
        raise ValueError(
            "campaign graph, events, and topology exceed the bounded probe budget "
            f"({projected_probe_count} > {MAX_PROBES})"
        )

    probes = []
    for event_index, (event, cut, preserve) in enumerate(derived, start=1):
        occurred = event["occurred_at_ms"]
        phase_times = {
            "pre": occurred - schedule["pre_event_offset_ms"],
            "window": occurred + schedule["propagation_probe_offset_ms"],
            "post": occurred + deadline + schedule["post_deadline_offset_ms"],
        }
        if phase_times["post"] > 86_400_000:
            raise ValueError("campaign probe schedule exceeds the 24-hour relative window")
        for node_index, node in enumerate(nodes, start=1):
            for authorization_index, (actor_id, resource_id, action) in enumerate(cut, start=1):
                for phase in ("pre", "window", "post"):
                    probes.append(
                        {
                            "probe_id": (
                                f"e{event_index:03d}-n{node_index:03d}-"
                                f"c{authorization_index:04d}-{phase}"
                            ),
                            "event_id": event["event_id"],
                            "node_id": node["node_id"],
                            "attempted_at_ms": phase_times[phase],
                            "actor_id": actor_id,
                            "resource_id": resource_id,
                            "action": action,
                        }
                    )
            for authorization_index, (actor_id, resource_id, action) in enumerate(
                preserve, start=1
            ):
                probes.append(
                    {
                        "probe_id": (
                            f"e{event_index:03d}-n{node_index:03d}-"
                            f"p{authorization_index:04d}-post"
                        ),
                        "event_id": event["event_id"],
                        "node_id": node["node_id"],
                        "attempted_at_ms": phase_times["post"],
                        "actor_id": actor_id,
                        "resource_id": resource_id,
                        "action": action,
                    }
                )
    if len(probes) != projected_probe_count:
        raise RuntimeError("identity campaign probe count did not reconcile")
    partial["probes"] = probes
    return validate_identity_plan(partial)


def validate_identity_campaign(value: Any) -> Dict[str, Any]:
    campaign, *_ = _validate_campaign_shape(value)
    compose_identity_plan(campaign)
    return campaign


def load_identity_campaign(path: Path) -> Dict[str, Any]:
    return validate_identity_campaign(_read(Path(path), "identity campaign"))
