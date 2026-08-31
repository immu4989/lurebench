"""Compose preregistered LureRevoke plans from projected events and topology."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Mapping

from .permit import _exact, _identifier, _integer, _rate, _timestamp
from .revocation import (
    MAX_EVENTS,
    MAX_NODES,
    MAX_PROBES,
    PLAN_LIMITATIONS,
    PLAN_SCHEMA,
    _read,
    validate_revocation_plan,
)

CAMPAIGN_SCHEMA = "https://github.com/immu4989/lurebench/spec/lurerevoke-campaign/v1"
CAMPAIGN_LIMITATIONS = [
    "events_must_already_be_privacy_projected_and_digest_bound_no_sets_tokens_or_raw_subjects",
    "campaign_composition_generates_probes_but_does_not_deliver_signals_or_execute_access",
    "topology_and_acceptance_require_independent_review_before_collecting_observations",
    "all_probe_phases_cover_every_declared_node_but_not_undeclared_paths",
    "campaign_results_do_not_prove_complete_paths_authenticity_interoperability_or_compliance",
]


def _validate_campaign_shape(value: Any) -> Dict[str, Any]:
    campaign = _exact(
        value,
        "revocation campaign",
        (
            "schema",
            "schema_version",
            "campaign_id",
            "created_at",
            "system_id",
            "stream",
            "nodes",
            "events",
            "acceptance",
            "probe_schedule",
            "limitations",
        ),
    )
    if campaign["schema"] != CAMPAIGN_SCHEMA or campaign["schema_version"] != 1:
        raise ValueError("unsupported LureRevoke campaign schema")
    _identifier(campaign["campaign_id"], "campaign.campaign_id")
    _timestamp(campaign["created_at"], "campaign.created_at")
    _identifier(campaign["system_id"], "campaign.system_id")
    stream = _exact(
        campaign["stream"],
        "campaign.stream",
        (
            "transmitter_id",
            "receiver_audience_id",
            "stream_id",
            "profile",
            "authentication_boundary",
        ),
    )
    for field in ("transmitter_id", "receiver_audience_id", "stream_id"):
        _identifier(stream[field], f"campaign.stream.{field}")
    if (
        stream["profile"] != "openid-caep-1.0-final-metadata-projection"
        or stream["authentication_boundary"] != "externally_verified_set_metadata"
    ):
        raise ValueError("campaign stream contract is unsupported")
    if not isinstance(campaign["nodes"], list) or not 1 <= len(campaign["nodes"]) <= MAX_NODES:
        raise ValueError("campaign.nodes must be a non-empty bounded array")
    node_ids = []
    for index, item in enumerate(campaign["nodes"]):
        node = _exact(item, f"campaign.nodes[{index}]", ("node_id", "mediation_point_id"))
        node_ids.append(_identifier(node["node_id"], f"campaign.nodes[{index}].node_id"))
        _identifier(node["mediation_point_id"], f"campaign.nodes[{index}].mediation_point_id")
    if len(set(node_ids)) != len(node_ids):
        raise ValueError("campaign contains duplicate node identifiers")
    if not isinstance(campaign["events"], list) or not 1 <= len(campaign["events"]) <= MAX_EVENTS:
        raise ValueError("campaign.events must be a non-empty bounded array")
    for index, event in enumerate(campaign["events"]):
        _exact(
            event,
            f"campaign.events[{index}]",
            (
                "event_id",
                "sequence",
                "occurred_at_ms",
                "event_type",
                "subject",
                "attenuation_reason",
                "signal_sha256",
            ),
        )
    acceptance = _exact(
        campaign["acceptance"],
        "campaign.acceptance",
        (
            "maximum_convergence_ms",
            "maximum_deadline_miss_count",
            "maximum_post_deadline_allow_count",
            "maximum_collateral_block_count",
            "minimum_delivery_coverage_rate",
            "minimum_revoked_block_recall",
            "minimum_pre_event_allow_rate",
            "minimum_signal_disposition_accuracy",
        ),
    )
    deadline = _integer(acceptance["maximum_convergence_ms"], "maximum_convergence_ms", 1, 600_000)
    for field in (
        "maximum_deadline_miss_count",
        "maximum_post_deadline_allow_count",
        "maximum_collateral_block_count",
    ):
        _integer(acceptance[field], field, 0, 4096)
    for field in (
        "minimum_delivery_coverage_rate",
        "minimum_revoked_block_recall",
        "minimum_pre_event_allow_rate",
        "minimum_signal_disposition_accuracy",
    ):
        _rate(acceptance[field], field)
    schedule = _exact(
        campaign["probe_schedule"],
        "campaign.probe_schedule",
        (
            "pre_event_offset_ms",
            "propagation_probe_offset_ms",
            "post_deadline_offset_ms",
            "include_unrelated_subject",
        ),
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
    if schedule["include_unrelated_subject"] is not True:
        raise ValueError("campaigns must include unrelated-subject availability probes")
    if campaign["limitations"] != CAMPAIGN_LIMITATIONS:
        raise ValueError("campaign limitations are invalid")
    return dict(campaign)


def compose_revocation_plan(value: Mapping[str, Any]) -> Dict[str, Any]:
    campaign = _validate_campaign_shape(value)
    deadline = campaign["acceptance"]["maximum_convergence_ms"]
    schedule = campaign["probe_schedule"]
    occurred_values = [event["occurred_at_ms"] for event in campaign["events"]]
    if any(
        isinstance(item, bool) or not isinstance(item, int) for item in occurred_values
    ) or occurred_values != sorted(set(occurred_values)):
        raise ValueError("campaign event occurrence times must increase strictly")
    subject_ids = []
    for event in campaign["events"]:
        subject = event.get("subject")
        if (
            not isinstance(subject, dict)
            or set(subject) != {"format", "id"}
            or subject.get("format") != "opaque"
        ):
            raise ValueError("campaign event subject must be an opaque identifier")
        subject_ids.append(_identifier(subject.get("id"), "campaign event subject id"))
    if len(set(subject_ids)) != len(subject_ids):
        raise ValueError("campaign events must use distinct opaque subjects")
    probe_count = len(campaign["events"]) * 4 * len(campaign["nodes"])
    if probe_count > MAX_PROBES:
        raise ValueError("campaign topology and event count exceed the bounded probe budget")

    probes = []
    for event_index, event in enumerate(campaign["events"], start=1):
        occurred = event["occurred_at_ms"]
        after = occurred + deadline + schedule["post_deadline_offset_ms"]
        grace = occurred + schedule["propagation_probe_offset_ms"]
        if after > 86_400_000:
            raise ValueError("campaign probe schedule exceeds the 24-hour relative window")
        unrelated_subject = f"unrelated-{event_index}"
        if unrelated_subject in subject_ids:
            raise ValueError("campaign subject collides with a reserved availability control")
        for node_index, node in enumerate(campaign["nodes"], start=1):
            probes.extend(
                [
                    {
                        "probe_id": f"event-{event_index}-node-{node_index}-before",
                        "event_id": event["event_id"],
                        "node_id": node["node_id"],
                        "attempted_at_ms": max(0, occurred - schedule["pre_event_offset_ms"]),
                        "subject_id": event["subject"]["id"],
                    },
                    {
                        "probe_id": f"event-{event_index}-node-{node_index}-propagation",
                        "event_id": event["event_id"],
                        "node_id": node["node_id"],
                        "attempted_at_ms": grace,
                        "subject_id": event["subject"]["id"],
                    },
                    {
                        "probe_id": f"event-{event_index}-node-{node_index}-after",
                        "event_id": event["event_id"],
                        "node_id": node["node_id"],
                        "attempted_at_ms": after,
                        "subject_id": event["subject"]["id"],
                    },
                    {
                        "probe_id": f"event-{event_index}-node-{node_index}-unrelated",
                        "event_id": event["event_id"],
                        "node_id": node["node_id"],
                        "attempted_at_ms": after,
                        "subject_id": unrelated_subject,
                    },
                ]
            )
    return validate_revocation_plan(
        {
            "schema": PLAN_SCHEMA,
            "schema_version": 1,
            "plan_id": campaign["campaign_id"],
            "created_at": campaign["created_at"],
            "system_id": campaign["system_id"],
            "stream": dict(campaign["stream"]),
            "nodes": [dict(item) for item in campaign["nodes"]],
            "events": [dict(item) for item in campaign["events"]],
            "probes": probes,
            "acceptance": dict(campaign["acceptance"]),
            "limitations": list(PLAN_LIMITATIONS),
        }
    )


def validate_revocation_campaign(value: Any) -> Dict[str, Any]:
    campaign = _validate_campaign_shape(value)
    compose_revocation_plan(campaign)
    return campaign


def load_revocation_campaign(path: Path) -> Dict[str, Any]:
    return validate_revocation_campaign(_read(Path(path), "revocation campaign"))
