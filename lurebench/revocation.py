"""Deterministic continuous-access revocation convergence benchmark.

LureRevoke measures whether synthetic security signals reach every declared
policy enforcement point and whether access is attenuated by a bounded
deadline.  It consumes typed metadata only: no JWTs, credentials, prompts,
commands, targets, or network requests are accepted or produced.
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

PLAN_SCHEMA = "https://github.com/immu4989/lurebench/spec/lurerevoke-plan-v1"
RUN_SCHEMA = "https://github.com/immu4989/lurebench/spec/lurerevoke-run-v1"
EVALUATION_SCHEMA = "https://github.com/immu4989/lurebench/spec/lurerevoke-evaluation-v1"
VERSION = "1.0.0"
MAX_BYTES = 4 * 1024 * 1024
MAX_NODES = 64
MAX_EVENTS = 64
MAX_PROBES = 4096

CAEP_SESSION_REVOKED = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
CAEP_CREDENTIAL_CHANGE = "https://schemas.openid.net/secevent/caep/event-type/credential-change"
CAEP_DEVICE_COMPLIANCE = (
    "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change"
)
CAEP_RISK_LEVEL = "https://schemas.openid.net/secevent/caep/event-type/risk-level-change"
EVENT_TYPES = {
    CAEP_SESSION_REVOKED,
    CAEP_CREDENTIAL_CHANGE,
    CAEP_DEVICE_COMPLIANCE,
    CAEP_RISK_LEVEL,
}
ATTENUATION_REASONS = {
    "credential_revoked",
    "device_noncompliant",
    "risk_increased",
    "session_revoked",
}
EVENT_REASON = {
    CAEP_SESSION_REVOKED: "session_revoked",
    CAEP_CREDENTIAL_CHANGE: "credential_revoked",
    CAEP_DEVICE_COMPLIANCE: "device_noncompliant",
    CAEP_RISK_LEVEL: "risk_increased",
}
DISPOSITIONS = {"applied", "duplicate", "invalid"}
DECISIONS = {"allow", "block"}
REASONS = {
    "propagation_window",
    "revocation_not_effective",
    "subject_not_revoked",
    "subject_revoked",
}
_DIGEST = re.compile(r"^[a-f0-9]{64}$")

PLAN_LIMITATIONS = [
    "synthetic_relative_timing_and_opaque_identifiers_only_no_tokens_credentials_or_payloads",
    "caep_event_types_are_metadata_projections_not_security_event_tokens_or_wire_conformance",
    "signal_authentication_transport_delivery_and_clock_sync_require_external_controls",
    "finite_scenarios_do_not_prove_complete_revocation_or_zero_trust_compliance",
]
RUN_LIMITATIONS = [
    "observations_are_claimed_receiver_metadata_not_proof_of_signal_or_enforcement_authenticity",
    "reference_run_is_offline_and_does_not_contact_identity_providers_agents_or_policy_engines",
    "invalid_and_duplicate_signals_are_synthetic_and_contain_no_reusable_security_material",
]
EVALUATION_LIMITATIONS = [
    "metrics_are_recomputed_from_embedded_plan_and_run_metadata",
    "deadline_success_depends_on_external_clock_quality_and_observation_completeness",
    "a_pass_does_not_prove_every_access_path_received_or_enforced_a_revocation",
    "evaluation_is_not_certification_authorization_or_a_claim_of_caep_interoperability",
]


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


def _ids(values: Any, field: str, maximum: int) -> list[str]:
    if not isinstance(values, list) or not 1 <= len(values) <= maximum:
        raise ValueError(f"{field} must be a non-empty bounded array")
    normalized = [_identifier(value, f"{field}[{index}]") for index, value in enumerate(values)]
    if len(set(normalized)) != len(normalized):
        raise ValueError(f"{field} contains duplicate identifiers")
    return normalized


def _signal_material(event: Mapping[str, Any]) -> Dict[str, Any]:
    return {key: event[key] for key in event if key != "signal_sha256"}


def _expected_signal_digest(event: Mapping[str, Any]) -> str:
    return _sha256(_canonical(_signal_material(event)))


def validate_revocation_plan(value: Any) -> Dict[str, Any]:
    plan = _exact(
        value,
        "revocation plan",
        (
            "schema",
            "schema_version",
            "plan_id",
            "created_at",
            "system_id",
            "stream",
            "nodes",
            "events",
            "probes",
            "acceptance",
            "limitations",
        ),
    )
    if plan["schema"] != PLAN_SCHEMA or plan["schema_version"] != 1:
        raise ValueError("unsupported LureRevoke plan schema")
    for field in ("plan_id", "system_id"):
        _identifier(plan[field], f"plan.{field}")
    _timestamp(plan["created_at"], "plan.created_at")
    stream = _exact(
        plan["stream"],
        "plan.stream",
        (
            "transmitter_id",
            "receiver_audience_id",
            "stream_id",
            "profile",
            "authentication_boundary",
        ),
    )
    for field in ("transmitter_id", "receiver_audience_id", "stream_id"):
        _identifier(stream[field], f"plan.stream.{field}")
    if stream["profile"] != "openid-caep-1.0-final-metadata-projection":
        raise ValueError("plan stream profile is unsupported")
    if stream["authentication_boundary"] != "externally_verified_set_metadata":
        raise ValueError("plan stream authentication boundary is unsupported")

    if not isinstance(plan["nodes"], list) or not 1 <= len(plan["nodes"]) <= MAX_NODES:
        raise ValueError("plan.nodes must be a non-empty bounded array")
    nodes: list[str] = []
    for index, item in enumerate(plan["nodes"]):
        node = _exact(item, f"plan.nodes[{index}]", ("node_id", "mediation_point_id"))
        nodes.append(_identifier(node["node_id"], f"plan.nodes[{index}].node_id"))
        _identifier(node["mediation_point_id"], f"plan.nodes[{index}].mediation_point_id")
    if len(set(nodes)) != len(nodes):
        raise ValueError("plan.nodes contains duplicate node identifiers")

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
                "subject",
                "attenuation_reason",
                "signal_sha256",
            ),
        )
        event_id = _identifier(event["event_id"], f"plan.events[{index}].event_id")
        if event_id in events:
            raise ValueError("plan.events contains duplicate event identifiers")
        sequence = _integer(event["sequence"], "event.sequence", 1, 1_000_000)
        if sequence in sequences:
            raise ValueError("plan.events contains duplicate stream sequences")
        sequences.add(sequence)
        _integer(event["occurred_at_ms"], "event.occurred_at_ms", 1, 86_400_000)
        event_type = _enum(event["event_type"], "event.event_type", EVENT_TYPES)
        subject = _exact(event["subject"], "event.subject", ("format", "id"))
        if subject["format"] != "opaque":
            raise ValueError("event subject format must be opaque")
        _identifier(subject["id"], "event.subject.id")
        reason = _enum(event["attenuation_reason"], "event.attenuation_reason", ATTENUATION_REASONS)
        if EVENT_REASON[event_type] != reason:
            raise ValueError("event type and attenuation reason do not reconcile")
        _digest(event["signal_sha256"], "event.signal_sha256")
        if event["signal_sha256"] != _expected_signal_digest(event):
            raise ValueError("event signal digest does not reconcile")
        events[event_id] = event
    if sorted(sequences) != list(range(1, len(sequences) + 1)):
        raise ValueError("plan event sequences must be contiguous from one")
    event_subjects = {event["subject"]["id"] for event in events.values()}

    if not isinstance(plan["probes"], list) or not 1 <= len(plan["probes"]) <= MAX_PROBES:
        raise ValueError("plan.probes must be a non-empty bounded array")
    probes: list[str] = []
    for index, item in enumerate(plan["probes"]):
        probe = _exact(
            item,
            f"plan.probes[{index}]",
            ("probe_id", "event_id", "node_id", "attempted_at_ms", "subject_id"),
        )
        probes.append(_identifier(probe["probe_id"], f"plan.probes[{index}].probe_id"))
        if probe["event_id"] not in events or probe["node_id"] not in nodes:
            raise ValueError("probe references an unknown event or node")
        _integer(probe["attempted_at_ms"], "probe.attempted_at_ms", 0, 86_400_000)
        subject_id = _identifier(probe["subject_id"], "probe.subject_id")
        event_subject = events[probe["event_id"]]["subject"]["id"]
        if subject_id != event_subject and subject_id in event_subjects:
            raise ValueError("probe unrelated subject collides with another campaign event")
    if len(set(probes)) != len(probes):
        raise ValueError("plan.probes contains duplicate probe identifiers")

    acceptance = _exact(
        plan["acceptance"],
        "plan.acceptance",
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
    _integer(acceptance["maximum_convergence_ms"], "maximum_convergence_ms", 1, 600_000)
    for field in (
        "maximum_deadline_miss_count",
        "maximum_post_deadline_allow_count",
        "maximum_collateral_block_count",
    ):
        _integer(acceptance[field], field, 0, MAX_PROBES)
    for field in (
        "minimum_delivery_coverage_rate",
        "minimum_revoked_block_recall",
        "minimum_pre_event_allow_rate",
        "minimum_signal_disposition_accuracy",
    ):
        _rate(acceptance[field], field)
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


def validate_revocation_run(value: Any, plan: Mapping[str, Any]) -> Dict[str, Any]:
    reviewed_plan = validate_revocation_plan(plan)
    run = _exact(
        value,
        "revocation run",
        (
            "schema",
            "schema_version",
            "run_id",
            "generated_at",
            "implementation",
            "plan_sha256",
            "signal_observations",
            "access_observations",
            "limitations",
        ),
    )
    if run["schema"] != RUN_SCHEMA or run["schema_version"] != 1:
        raise ValueError("unsupported LureRevoke run schema")
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
    if (
        not isinstance(run["signal_observations"], list)
        or len(run["signal_observations"]) > MAX_EVENTS * MAX_NODES * 4
    ):
        raise ValueError("run.signal_observations must be a bounded array")
    observation_ids: list[str] = []
    for index, item in enumerate(run["signal_observations"]):
        observation = _exact(
            item,
            f"run.signal_observations[{index}]",
            (
                "observation_id",
                "event_id",
                "node_id",
                "received_at_ms",
                "signal_sha256",
                "disposition",
            ),
        )
        observation_ids.append(_identifier(observation["observation_id"], "signal observation id"))
        if observation["event_id"] not in event_ids or observation["node_id"] not in node_ids:
            raise ValueError("signal observation references an unknown event or node")
        _integer(observation["received_at_ms"], "received_at_ms", 0, 86_400_000)
        _digest(observation["signal_sha256"], "signal observation digest")
        _enum(observation["disposition"], "signal disposition", DISPOSITIONS)
    if len(set(observation_ids)) != len(observation_ids):
        raise ValueError("run contains duplicate signal observation identifiers")

    probe_ids = {item["probe_id"] for item in reviewed_plan["probes"]}
    if not isinstance(run["access_observations"], list) or len(run["access_observations"]) != len(
        probe_ids
    ):
        raise ValueError("run must contain exactly one access observation per probe")
    submitted_probes: list[str] = []
    for index, item in enumerate(run["access_observations"]):
        observation = _exact(
            item,
            f"run.access_observations[{index}]",
            ("probe_id", "decision", "reason_code"),
        )
        submitted_probes.append(_identifier(observation["probe_id"], "access probe id"))
        _enum(observation["decision"], "access decision", DECISIONS)
        _enum(observation["reason_code"], "access reason", REASONS)
    if set(submitted_probes) != probe_ids or len(set(submitted_probes)) != len(probe_ids):
        raise ValueError("run access observations do not exactly cover the plan probes")
    if run["limitations"] != RUN_LIMITATIONS:
        raise ValueError("run limitations are invalid")
    return dict(run)


def default_revocation_plan() -> Dict[str, Any]:
    nodes = [
        {"node_id": "east-policy", "mediation_point_id": "tool-gateway"},
        {"node_id": "west-policy", "mediation_point_id": "network-gateway"},
        {"node_id": "edge-policy", "mediation_point_id": "credential-broker"},
        {"node_id": "backup-policy", "mediation_point_id": "storage-gateway"},
    ]
    definitions = [
        (CAEP_SESSION_REVOKED, "session_revoked", "subject-session-a"),
        (CAEP_CREDENTIAL_CHANGE, "credential_revoked", "subject-credential-a"),
        (CAEP_DEVICE_COMPLIANCE, "device_noncompliant", "subject-device-a"),
        (CAEP_RISK_LEVEL, "risk_increased", "subject-workload-a"),
    ]
    events = []
    probes = []
    for event_index, (event_type, reason, subject_id) in enumerate(definitions, start=1):
        occurred = event_index * 10_000
        event: Dict[str, Any] = {
            "event_id": f"revocation-{event_index}",
            "sequence": event_index,
            "occurred_at_ms": occurred,
            "event_type": event_type,
            "subject": {"format": "opaque", "id": subject_id},
            "attenuation_reason": reason,
        }
        event["signal_sha256"] = _expected_signal_digest(event)
        events.append(event)
        for node in nodes:
            node_id = node["node_id"]
            probes.extend(
                [
                    {
                        "probe_id": f"event-{event_index}-{node_id}-before",
                        "event_id": event["event_id"],
                        "node_id": node_id,
                        "attempted_at_ms": occurred - 50,
                        "subject_id": subject_id,
                    },
                    {
                        "probe_id": f"event-{event_index}-{node_id}-propagation",
                        "event_id": event["event_id"],
                        "node_id": node_id,
                        "attempted_at_ms": occurred + 50,
                        "subject_id": subject_id,
                    },
                    {
                        "probe_id": f"event-{event_index}-{node_id}-after",
                        "event_id": event["event_id"],
                        "node_id": node_id,
                        "attempted_at_ms": occurred + 550,
                        "subject_id": subject_id,
                    },
                    {
                        "probe_id": f"event-{event_index}-{node_id}-unrelated",
                        "event_id": event["event_id"],
                        "node_id": node_id,
                        "attempted_at_ms": occurred + 550,
                        "subject_id": f"unrelated-{event_index}",
                    },
                ]
            )
    return validate_revocation_plan(
        {
            "schema": PLAN_SCHEMA,
            "schema_version": 1,
            "plan_id": "lurerevoke-caep-convergence-v1",
            "created_at": "2026-08-30T00:00:00Z",
            "system_id": "synthetic-agent-system",
            "stream": {
                "transmitter_id": "synthetic-identity-provider",
                "receiver_audience_id": "synthetic-agent-control-plane",
                "stream_id": "agent-security-events",
                "profile": "openid-caep-1.0-final-metadata-projection",
                "authentication_boundary": "externally_verified_set_metadata",
            },
            "nodes": nodes,
            "events": events,
            "probes": probes,
            "acceptance": {
                "maximum_convergence_ms": 500,
                "maximum_deadline_miss_count": 0,
                "maximum_post_deadline_allow_count": 0,
                "maximum_collateral_block_count": 0,
                "minimum_delivery_coverage_rate": 1.0,
                "minimum_revoked_block_recall": 1.0,
                "minimum_pre_event_allow_rate": 1.0,
                "minimum_signal_disposition_accuracy": 1.0,
            },
            "limitations": list(PLAN_LIMITATIONS),
        }
    )


def _expected_dispositions(
    plan: Mapping[str, Any], signal_observations: Sequence[Mapping[str, Any]]
) -> tuple[dict[str, str], dict[tuple[str, str], int]]:
    events = {item["event_id"]: item for item in plan["events"]}
    seen: set[tuple[str, str]] = set()
    expected: dict[str, str] = {}
    applied: dict[tuple[str, str], int] = {}
    ordered = sorted(
        signal_observations,
        key=lambda item: (item["received_at_ms"], item["observation_id"]),
    )
    for observation in ordered:
        event = events[observation["event_id"]]
        key = (observation["event_id"], observation["node_id"])
        valid = (
            observation["signal_sha256"] == event["signal_sha256"]
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
    probe: Mapping[str, Any],
    event: Mapping[str, Any],
    applied_at: Optional[int],
    deadline_ms: int,
) -> tuple[str, str, str]:
    attempted = probe["attempted_at_ms"]
    if probe["subject_id"] != event["subject"]["id"]:
        return "allow", "subject_not_revoked", "unrelated_subject"
    if attempted < event["occurred_at_ms"]:
        return "allow", "revocation_not_effective", "pre_event"
    if applied_at is not None and attempted >= applied_at:
        return "block", "subject_revoked", "revoked"
    if attempted >= event["occurred_at_ms"] + deadline_ms:
        return "block", "subject_revoked", "post_deadline"
    return "allow", "propagation_window", "propagation_window"


def reference_revocation_run(
    plan: Optional[Mapping[str, Any]] = None,
    *,
    run_id: str = "lurerevoke-reference-run",
    implementation_name: str = "lurerevoke-reference",
    implementation_version: str = VERSION,
    implementation_artifact_sha256: Optional[str] = None,
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    reviewed = validate_revocation_plan(plan or default_revocation_plan())
    signal_observations = []
    for event_index, event in enumerate(reviewed["events"], start=1):
        for node_index, node in enumerate(reviewed["nodes"], start=1):
            received = event["occurred_at_ms"] + node_index * 100
            if node_index == 1:
                signal_observations.append(
                    {
                        "observation_id": f"signal-{event_index}-{node_index}-invalid",
                        "event_id": event["event_id"],
                        "node_id": node["node_id"],
                        "received_at_ms": event["occurred_at_ms"] + 10,
                        "signal_sha256": "0" * 64,
                        "disposition": "invalid",
                    }
                )
            signal_observations.append(
                {
                    "observation_id": f"signal-{event_index}-{node_index}-applied",
                    "event_id": event["event_id"],
                    "node_id": node["node_id"],
                    "received_at_ms": received,
                    "signal_sha256": event["signal_sha256"],
                    "disposition": "applied",
                }
            )
            if node_index == 1:
                signal_observations.append(
                    {
                        "observation_id": f"signal-{event_index}-{node_index}-duplicate",
                        "event_id": event["event_id"],
                        "node_id": node["node_id"],
                        "received_at_ms": received + 1,
                        "signal_sha256": event["signal_sha256"],
                        "disposition": "duplicate",
                    }
                )
    _, applied = _expected_dispositions(reviewed, signal_observations)
    events = {item["event_id"]: item for item in reviewed["events"]}
    deadline = reviewed["acceptance"]["maximum_convergence_ms"]
    access_observations = []
    for probe in reviewed["probes"]:
        decision, reason, _ = _expected_probe(
            probe,
            events[probe["event_id"]],
            applied.get((probe["event_id"], probe["node_id"])),
            deadline,
        )
        access_observations.append(
            {"probe_id": probe["probe_id"], "decision": decision, "reason_code": reason}
        )
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
        "signal_observations": signal_observations,
        "access_observations": access_observations,
        "limitations": list(RUN_LIMITATIONS),
    }
    return validate_revocation_run(run, reviewed)


def _evaluation_value(
    plan: Mapping[str, Any], run: Mapping[str, Any], generated_at: str
) -> Dict[str, Any]:
    reviewed_plan = validate_revocation_plan(plan)
    reviewed_run = validate_revocation_run(run, reviewed_plan)
    _timestamp(generated_at, "evaluation.generated_at")
    if _time(generated_at) < _time(reviewed_run["generated_at"]):
        raise ValueError("evaluation cannot predate its run")
    expected_dispositions, applied = _expected_dispositions(
        reviewed_plan, reviewed_run["signal_observations"]
    )
    deadline = reviewed_plan["acceptance"]["maximum_convergence_ms"]
    event_map = {item["event_id"]: item for item in reviewed_plan["events"]}
    submitted_decisions = {item["probe_id"]: item for item in reviewed_run["access_observations"]}
    convergence_values = []
    delivery_results = []
    deadline_misses = 0
    for event in reviewed_plan["events"]:
        for node in reviewed_plan["nodes"]:
            key = (event["event_id"], node["node_id"])
            received = applied.get(key)
            convergence = None if received is None else received - event["occurred_at_ms"]
            deadline_met = convergence is not None and convergence <= deadline
            if convergence is not None:
                convergence_values.append(convergence)
            if not deadline_met:
                deadline_misses += 1
            delivery_results.append(
                {
                    "event_id": event["event_id"],
                    "node_id": node["node_id"],
                    "applied_at_ms": received,
                    "convergence_ms": convergence,
                    "deadline_met": deadline_met,
                }
            )

    probe_results = []
    revoked_total = revoked_correct = 0
    pre_total = pre_correct = 0
    collateral_blocks = post_deadline_allows = 0
    incorrect_decisions = incorrect_reasons = 0
    for probe in reviewed_plan["probes"]:
        event = event_map[probe["event_id"]]
        expected_decision, expected_reason, phase = _expected_probe(
            probe,
            event,
            applied.get((probe["event_id"], probe["node_id"])),
            deadline,
        )
        submitted = submitted_decisions[probe["probe_id"]]
        decision_correct = submitted["decision"] == expected_decision
        reason_correct = submitted["reason_code"] == expected_reason
        incorrect_decisions += int(not decision_correct)
        incorrect_reasons += int(not reason_correct)
        if expected_decision == "block":
            revoked_total += 1
            revoked_correct += int(submitted["decision"] == "block")
        if phase == "pre_event":
            pre_total += 1
            pre_correct += int(submitted["decision"] == "allow")
        if phase == "unrelated_subject" and submitted["decision"] == "block":
            collateral_blocks += 1
        if (
            probe["subject_id"] == event["subject"]["id"]
            and probe["attempted_at_ms"] >= event["occurred_at_ms"] + deadline
            and submitted["decision"] == "allow"
        ):
            post_deadline_allows += 1
        classification = (
            "correct"
            if decision_correct and reason_correct
            else "revocation_bypass"
            if expected_decision == "block" and submitted["decision"] == "allow"
            else "collateral_denial"
            if expected_decision == "allow" and submitted["decision"] == "block"
            else "wrong_reason"
        )
        probe_results.append(
            {
                "probe_id": probe["probe_id"],
                "event_id": probe["event_id"],
                "node_id": probe["node_id"],
                "phase": phase,
                "expected_decision": expected_decision,
                "submitted_decision": submitted["decision"],
                "expected_reason_code": expected_reason,
                "submitted_reason_code": submitted["reason_code"],
                "classification": classification,
            }
        )

    disposition_correct = sum(
        observation["disposition"] == expected_dispositions[observation["observation_id"]]
        for observation in reviewed_run["signal_observations"]
    )
    disposition_total = len(reviewed_run["signal_observations"])
    required_deliveries = len(reviewed_plan["events"]) * len(reviewed_plan["nodes"])
    coverage = len(applied) / required_deliveries
    max_convergence = max(convergence_values) if convergence_values else None
    if convergence_values:
        ordered = sorted(convergence_values)
        p95_convergence = ordered[math.ceil(0.95 * len(ordered)) - 1]
    else:
        p95_convergence = None
    revoked_recall = revoked_correct / revoked_total if revoked_total else 0.0
    pre_allow = pre_correct / pre_total if pre_total else 0.0
    disposition_accuracy = disposition_correct / disposition_total if disposition_total else 0.0
    acceptance = reviewed_plan["acceptance"]
    verdict = (
        "pass"
        if (
            coverage >= acceptance["minimum_delivery_coverage_rate"]
            and max_convergence is not None
            and max_convergence <= acceptance["maximum_convergence_ms"]
            and deadline_misses <= acceptance["maximum_deadline_miss_count"]
            and post_deadline_allows <= acceptance["maximum_post_deadline_allow_count"]
            and collateral_blocks <= acceptance["maximum_collateral_block_count"]
            and revoked_recall >= acceptance["minimum_revoked_block_recall"]
            and pre_allow >= acceptance["minimum_pre_event_allow_rate"]
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
            "event_count": len(reviewed_plan["events"]),
            "node_count": len(reviewed_plan["nodes"]),
            "required_delivery_count": required_deliveries,
            "applied_delivery_count": len(applied),
            "delivery_coverage_rate": coverage,
            "maximum_convergence_ms": max_convergence,
            "p95_convergence_ms": p95_convergence,
            "deadline_miss_count": deadline_misses,
            "post_deadline_allow_count": post_deadline_allows,
            "collateral_block_count": collateral_blocks,
            "revoked_block_recall": revoked_recall,
            "pre_event_allow_rate": pre_allow,
            "signal_disposition_accuracy": disposition_accuracy,
            "incorrect_decision_count": incorrect_decisions,
            "incorrect_reason_count": incorrect_reasons,
            "verdict": verdict,
        },
        "delivery_results": delivery_results,
        "probe_results": probe_results,
        "limitations": list(EVALUATION_LIMITATIONS),
    }


def evaluate_revocation_run(
    plan: Mapping[str, Any], run: Mapping[str, Any], *, generated_at: Optional[str] = None
) -> Dict[str, Any]:
    return _evaluation_value(plan, run, generated_at or _now())


def validate_revocation_evaluation(value: Any) -> Dict[str, Any]:
    evaluation = _exact(
        value,
        "revocation evaluation",
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
            "delivery_results",
            "probe_results",
            "limitations",
        ),
    )
    if evaluation["schema"] != EVALUATION_SCHEMA or evaluation["schema_version"] != 1:
        raise ValueError("unsupported LureRevoke evaluation schema")
    _timestamp(evaluation["generated_at"], "evaluation.generated_at")
    expected = _evaluation_value(evaluation["plan"], evaluation["run"], evaluation["generated_at"])
    if evaluation != expected:
        raise ValueError("revocation evaluation does not independently recompute")
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


def load_revocation_plan(path: Optional[Path] = None) -> Dict[str, Any]:
    return (
        default_revocation_plan() if path is None else validate_revocation_plan(_read(path, "plan"))
    )


def load_revocation_run(path: Path, plan: Mapping[str, Any]) -> Dict[str, Any]:
    return validate_revocation_run(_read(path, "run"), plan)


def write_revocation_plan(path: Path, value: Mapping[str, Any]) -> None:
    _write(path, validate_revocation_plan(value))


def write_revocation_run(path: Path, value: Mapping[str, Any], plan: Mapping[str, Any]) -> None:
    _write(path, validate_revocation_run(value, plan))


def write_revocation_evaluation(path: Path, value: Mapping[str, Any]) -> None:
    _write(path, validate_revocation_evaluation(value))
