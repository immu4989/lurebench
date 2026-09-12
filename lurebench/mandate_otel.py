"""Body-free OpenTelemetry log projection into LureMandate transactions.

This module consumes a strict JSON projection of the stable OpenTelemetry Logs
Data Model. It is deliberately not a general OTLP decoder or an OpenTelemetry
semantic-conventions conformance implementation.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from . import __version__
from .mandate import (
    DECISIONS,
    MAX_APPROVALS,
    MAX_TRANSACTIONS,
    OUTCOME_STATES,
    REASON_CODES,
    RUN_SCHEMA,
    _digest,
    _instant,
    _load,
    _sha256,
    _validate_approval,
    _validate_intent,
    _write,
    validate_mandate_plan,
    validate_mandate_run,
)
from .mandate import LIMITATIONS as RUN_LIMITATIONS
from .mandate import PRIVACY as RUN_PRIVACY
from .permit import _canonical, _exact, _identifier, _integer, _timestamp

OTEL_EXPORT_SCHEMA = "https://github.com/immu4989/lurebench/spec/luremandate-otel-log-export/v1"
OTEL_PROJECTION_SCHEMA = "https://github.com/immu4989/lurebench/spec/luremandate-otel-projection/v1"
INTENT_EVENT = "org.lurebench.luremandate.intent_proposed"
APPROVAL_EVENT = "org.lurebench.luremandate.approval_recorded"
DECISION_EVENT = "org.lurebench.luremandate.decision_recorded"
OUTCOME_EVENT = "org.lurebench.luremandate.outcome_recorded"
MAX_RECORDS = MAX_TRANSACTIONS * (MAX_APPROVALS + 3)
MAX_UNIX_NANO = 9_223_372_036_854_775_807
_TRACE_ID = re.compile(r"^[a-f0-9]{32}$")
_SPAN_ID = re.compile(r"^[a-f0-9]{16}$")

EXPORT_LIMITATIONS = [
    "strict_body_free_projection_of_the_opentelemetry_log_data_model_not_raw_otlp",
    "custom_lurebench_event_names_and_attributes_are_not_opentelemetry_semantic_conventions",
    "timestamps_resource_identity_and_attributes_require_external_instrumentation_assurance",
    "only_opaque_identifiers_spiffe_ids_digests_decisions_and_bounded_impact_units_are_accepted",
]
PROJECTION_LIMITATIONS = [
    "projection_rejects_log_body_unknown_attributes_free_text_prompts_commands_payloads_credentials_hosts_urls_and_customer_content",
    "benchmark_timing_uses_origin_clock_timestamp_not_collector_observed_timestamp",
    "each_transaction_requires_one_trace_with_exact_intent_decision_outcome_and_approval_coverage",
    "trace_context_correlates_records_but_does_not_authenticate_or_prove_causality",
    "projection_does_not_prove_telemetry_completeness_clock_sync_delivery_approver_identity_or_enforcement",
    "projection_is_not_otlp_or_opentelemetry_semantic_conventions_conformance",
]
PRIVACY = {
    "body_accepted": False,
    "instrumentation_scope_accepted": False,
    "free_text_or_transaction_content_accepted": False,
    "tokens_credentials_prompts_commands_payloads_hosts_urls_or_customer_content_accepted": False,
    "opaque_identifiers_spiffe_ids_digests_decisions_and_bounded_impact_units_only": True,
}
CLOCK_BOUNDARY = {
    "benchmark_time_field": "Timestamp",
    "collector_time_field": "ObservedTimestamp",
    "observed_timestamp_used_for_benchmark_timing": False,
    "timestamp_resolution": "microsecond_aligned_unix_nanoseconds",
    "event_timestamp_binding": "exact_declared_luremandate_lifecycle_time",
    "external_clock_assurance_required": True,
}

_TX = "luremandate.transaction.id"
_SEQUENCE = "luremandate.transaction.sequence"
_INTENT_KEYS = (
    _TX,
    _SEQUENCE,
    "luremandate.intent.id",
    "luremandate.intent.proposed_at",
    "luremandate.tenant.id",
    "luremandate.run.id",
    "luremandate.agent.id",
    "luremandate.workload.spiffe_id",
    "luremandate.requester.id",
    "luremandate.policy.id",
    "luremandate.action",
    "luremandate.resource.id",
    "luremandate.impact_units",
    "luremandate.intent.nonce",
    "luremandate.intent.sha256",
)
_APPROVAL_KEYS = (
    _TX,
    "luremandate.approval.id",
    "luremandate.approver.id",
    "luremandate.approver.role",
    "luremandate.approval.decision",
    "luremandate.intent.sha256",
    "luremandate.approval.issued_at",
    "luremandate.approval.expires_at",
    "luremandate.approval.nonce",
)
_DECISION_KEYS = (
    _TX,
    "luremandate.decision.id",
    "luremandate.decision.decided_at",
    "luremandate.decision.value",
    "luremandate.decision.reason_code",
)
_OUTCOME_KEYS = (
    _TX,
    "luremandate.outcome.state",
    "luremandate.outcome.observed_at",
    "luremandate.sensor.id",
)


def _unix_nano(value: Any, field: str) -> int:
    instant = _instant(value, field)
    delta = instant - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86_400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1_000


def _context_id(value: Any, field: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None or set(value) == {"0"}:
        raise ValueError(f"{field} must be a nonzero lowercase hexadecimal identifier")
    return value


def _receiver(value: Any) -> Dict[str, Any]:
    receiver = _exact(
        value,
        "OpenTelemetry receiver",
        ("name", "instance_id", "version", "artifact_sha256"),
    )
    for name in ("name", "instance_id", "version"):
        _identifier(receiver[name], f"receiver.{name}")
    if receiver["artifact_sha256"] is not None:
        _digest(receiver["artifact_sha256"], "receiver.artifact_sha256")
    return dict(receiver)


def _resource(value: Any, receiver: Mapping[str, Any], field: str) -> None:
    resource = _exact(
        value,
        field,
        ("service.name", "service.instance.id", "service.version"),
    )
    if resource != {
        "service.name": receiver["name"],
        "service.instance.id": receiver["instance_id"],
        "service.version": receiver["version"],
    }:
        raise ValueError("OpenTelemetry resource differs from the declared receiver")


def _intent_from_attributes(value: Any, field: str) -> tuple[str, int, Dict[str, Any], str]:
    attributes = _exact(value, field, _INTENT_KEYS)
    transaction_id = _identifier(attributes[_TX], f"{field}.{_TX}")
    sequence = _integer(attributes[_SEQUENCE], f"{field}.{_SEQUENCE}", 1, MAX_TRANSACTIONS)
    intent = _validate_intent(
        {
            "intent_id": attributes["luremandate.intent.id"],
            "proposed_at": attributes["luremandate.intent.proposed_at"],
            "tenant_id": attributes["luremandate.tenant.id"],
            "run_id": attributes["luremandate.run.id"],
            "agent_id": attributes["luremandate.agent.id"],
            "workload_spiffe_id": attributes["luremandate.workload.spiffe_id"],
            "requester_id": attributes["luremandate.requester.id"],
            "policy_id": attributes["luremandate.policy.id"],
            "action": attributes["luremandate.action"],
            "resource_id": attributes["luremandate.resource.id"],
            "impact_units": attributes["luremandate.impact_units"],
            "intent_nonce": attributes["luremandate.intent.nonce"],
        },
        f"{field}.intent",
    )
    digest = _digest(attributes["luremandate.intent.sha256"], f"{field}.intent_sha256")
    if digest != _sha256(_canonical(intent)):
        raise ValueError("OpenTelemetry intent digest does not match its exact attributes")
    return transaction_id, sequence, intent, digest


def _approval_from_attributes(value: Any, field: str) -> tuple[str, Dict[str, Any]]:
    attributes = _exact(value, field, _APPROVAL_KEYS)
    transaction_id = _identifier(attributes[_TX], f"{field}.{_TX}")
    approval = _validate_approval(
        {
            "approval_id": attributes["luremandate.approval.id"],
            "approver_id": attributes["luremandate.approver.id"],
            "approver_role": attributes["luremandate.approver.role"],
            "decision": attributes["luremandate.approval.decision"],
            "intent_sha256": attributes["luremandate.intent.sha256"],
            "issued_at": attributes["luremandate.approval.issued_at"],
            "expires_at": attributes["luremandate.approval.expires_at"],
            "nonce": attributes["luremandate.approval.nonce"],
        },
        f"{field}.approval",
    )
    return transaction_id, approval


def _decision_from_attributes(value: Any, field: str) -> tuple[str, Dict[str, Any]]:
    attributes = _exact(value, field, _DECISION_KEYS)
    transaction_id = _identifier(attributes[_TX], f"{field}.{_TX}")
    decision = {
        "decision_id": _identifier(attributes["luremandate.decision.id"], f"{field}.decision_id"),
        "decided_at": _timestamp(
            attributes["luremandate.decision.decided_at"], f"{field}.decided_at"
        ),
        "decision": attributes["luremandate.decision.value"],
        "reason_code": attributes["luremandate.decision.reason_code"],
    }
    if decision["decision"] not in DECISIONS or decision["reason_code"] not in REASON_CODES:
        raise ValueError("OpenTelemetry authority decision or reason code is unsupported")
    return transaction_id, decision


def _outcome_from_attributes(value: Any, field: str) -> tuple[str, Dict[str, Any]]:
    attributes = _exact(value, field, _OUTCOME_KEYS)
    transaction_id = _identifier(attributes[_TX], f"{field}.{_TX}")
    state = attributes["luremandate.outcome.state"]
    if state not in OUTCOME_STATES:
        raise ValueError("OpenTelemetry outcome state is unsupported")
    observed_at = attributes["luremandate.outcome.observed_at"]
    sensor_id = attributes["luremandate.sensor.id"]
    if state in {"effect_observed", "no_effect_observed"}:
        _timestamp(observed_at, f"{field}.observed_at")
        _identifier(sensor_id, f"{field}.sensor_id")
    elif observed_at is not None or sensor_id is not None:
        raise ValueError("unobserved OpenTelemetry outcomes cannot claim sensor metadata")
    return transaction_id, {"state": state, "observed_at": observed_at, "sensor_id": sensor_id}


def _record_value(
    *,
    timestamp: str,
    observed_offset_ms: int,
    trace_id: str,
    span_id: str,
    event_name: str,
    receiver: Mapping[str, Any],
    attributes: Mapping[str, Any],
) -> Dict[str, Any]:
    return {
        "Timestamp": _unix_nano(timestamp, "reference event timestamp"),
        "ObservedTimestamp": _unix_nano(timestamp, "reference event timestamp")
        + observed_offset_ms * 1_000_000,
        "TraceId": trace_id,
        "SpanId": span_id,
        "EventName": event_name,
        "Resource": {
            "service.name": receiver["name"],
            "service.instance.id": receiver["instance_id"],
            "service.version": receiver["version"],
        },
        "Attributes": dict(attributes),
    }


def reference_mandate_otel_export(
    plan_value: Mapping[str, Any],
    run_value: Mapping[str, Any],
    *,
    export_id: str = "luremandate-otel-conformance-1",
    service_instance_id: str = "authority-gateway-instance-1",
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Encode a valid run as a deterministic body-free OpenTelemetry reference export."""

    plan = validate_mandate_plan(plan_value)
    run = validate_mandate_run(run_value, plan)
    _identifier(export_id, "OpenTelemetry export_id")
    _identifier(service_instance_id, "OpenTelemetry service_instance_id")
    generated_at = generated_at or (
        _instant(run["completed_at"], "completed_at") + timedelta(seconds=1)
    ).isoformat().replace("+00:00", "Z")
    if _instant(generated_at, "generated_at") <= _instant(run["completed_at"], "completed_at"):
        raise ValueError("OpenTelemetry export must be generated after run completion")
    receiver = {
        "name": run["engine"]["engine_id"],
        "instance_id": service_instance_id,
        "version": run["engine"]["engine_version"],
        "artifact_sha256": run["engine"]["engine_artifact_sha256"],
    }
    records = []
    record_number = 0
    for transaction in run["transactions"]:
        transaction_id = transaction["transaction_id"]
        trace_id = hashlib.sha256(transaction_id.encode()).hexdigest()[:32]

        def append(
            event_name: str,
            timestamp: str,
            attributes: Mapping[str, Any],
            *,
            bound_transaction_id: str = transaction_id,
            bound_trace_id: str = trace_id,
        ) -> None:
            nonlocal record_number
            record_number += 1
            span_seed = f"{bound_transaction_id}:{event_name}:{record_number}"
            span_id = hashlib.sha256(span_seed.encode()).hexdigest()[:16]
            records.append(
                _record_value(
                    timestamp=timestamp,
                    observed_offset_ms=1,
                    trace_id=bound_trace_id,
                    span_id=span_id,
                    event_name=event_name,
                    receiver=receiver,
                    attributes=attributes,
                )
            )

        intent = transaction["intent"]
        append(
            INTENT_EVENT,
            intent["proposed_at"],
            {
                _TX: transaction["transaction_id"],
                _SEQUENCE: transaction["sequence"],
                "luremandate.intent.id": intent["intent_id"],
                "luremandate.intent.proposed_at": intent["proposed_at"],
                "luremandate.tenant.id": intent["tenant_id"],
                "luremandate.run.id": intent["run_id"],
                "luremandate.agent.id": intent["agent_id"],
                "luremandate.workload.spiffe_id": intent["workload_spiffe_id"],
                "luremandate.requester.id": intent["requester_id"],
                "luremandate.policy.id": intent["policy_id"],
                "luremandate.action": intent["action"],
                "luremandate.resource.id": intent["resource_id"],
                "luremandate.impact_units": intent["impact_units"],
                "luremandate.intent.nonce": intent["intent_nonce"],
                "luremandate.intent.sha256": transaction["intent_sha256"],
            },
        )
        for approval in transaction["approvals"]:
            append(
                APPROVAL_EVENT,
                approval["issued_at"],
                {
                    _TX: transaction["transaction_id"],
                    "luremandate.approval.id": approval["approval_id"],
                    "luremandate.approver.id": approval["approver_id"],
                    "luremandate.approver.role": approval["approver_role"],
                    "luremandate.approval.decision": approval["decision"],
                    "luremandate.intent.sha256": approval["intent_sha256"],
                    "luremandate.approval.issued_at": approval["issued_at"],
                    "luremandate.approval.expires_at": approval["expires_at"],
                    "luremandate.approval.nonce": approval["nonce"],
                },
            )
        decision = transaction["decision"]
        append(
            DECISION_EVENT,
            decision["decided_at"],
            {
                _TX: transaction["transaction_id"],
                "luremandate.decision.id": decision["decision_id"],
                "luremandate.decision.decided_at": decision["decided_at"],
                "luremandate.decision.value": decision["decision"],
                "luremandate.decision.reason_code": decision["reason_code"],
            },
        )
        outcome = transaction["outcome"]
        append(
            OUTCOME_EVENT,
            outcome["observed_at"] or decision["decided_at"],
            {
                _TX: transaction["transaction_id"],
                "luremandate.outcome.state": outcome["state"],
                "luremandate.outcome.observed_at": outcome["observed_at"],
                "luremandate.sensor.id": outcome["sensor_id"],
            },
        )
    return validate_mandate_otel_log_export(
        {
            "schema": OTEL_EXPORT_SCHEMA,
            "schema_version": 1,
            "export_id": export_id,
            "generated_at": generated_at,
            "time_origin_unix_nano": _unix_nano(run["started_at"], "started_at"),
            "campaign_id": run["campaign_id"],
            "plan_sha256": run["plan_sha256"],
            "run_id": run["run_id"],
            "started_at": run["started_at"],
            "completed_at": run["completed_at"],
            "receiver": receiver,
            "records": records,
            "privacy": dict(PRIVACY),
            "limitations": list(EXPORT_LIMITATIONS),
        },
        plan,
    )


def _grouped_records(export: Mapping[str, Any]) -> Dict[str, Dict[str, Any]]:
    receiver = export["receiver"]
    generated_nano = _unix_nano(export["generated_at"], "generated_at")
    origin = export["time_origin_unix_nano"]
    groups: Dict[str, Dict[str, Any]] = {}
    trace_transactions: Dict[str, str] = {}
    transaction_traces: Dict[str, str] = {}
    contexts: set[tuple[str, str]] = set()
    for index, item in enumerate(export["records"]):
        record = _exact(
            item,
            f"records[{index}]",
            (
                "Timestamp",
                "ObservedTimestamp",
                "TraceId",
                "SpanId",
                "EventName",
                "Resource",
                "Attributes",
            ),
        )
        timestamp = _integer(record["Timestamp"], "Timestamp", 1, MAX_UNIX_NANO)
        observed = _integer(record["ObservedTimestamp"], "ObservedTimestamp", 1, MAX_UNIX_NANO)
        if timestamp < origin or timestamp > generated_nano or observed > generated_nano:
            raise ValueError("OpenTelemetry record falls outside the declared export window")
        if timestamp % 1_000 or observed % 1_000:
            raise ValueError("OpenTelemetry timestamps must be microsecond aligned")
        trace_id = _context_id(record["TraceId"], "TraceId", _TRACE_ID)
        span_id = _context_id(record["SpanId"], "SpanId", _SPAN_ID)
        if (trace_id, span_id) in contexts:
            raise ValueError("OpenTelemetry export contains duplicate trace/span context")
        contexts.add((trace_id, span_id))
        _resource(record["Resource"], receiver, f"records[{index}].Resource")
        event_name = record["EventName"]
        if event_name == INTENT_EVENT:
            transaction_id, sequence, intent, digest = _intent_from_attributes(
                record["Attributes"], f"records[{index}].Attributes"
            )
            event = {"sequence": sequence, "intent": intent, "intent_sha256": digest}
            expected_timestamp = intent["proposed_at"]
        elif event_name == APPROVAL_EVENT:
            transaction_id, approval = _approval_from_attributes(
                record["Attributes"], f"records[{index}].Attributes"
            )
            event = approval
            expected_timestamp = approval["issued_at"]
        elif event_name == DECISION_EVENT:
            transaction_id, decision = _decision_from_attributes(
                record["Attributes"], f"records[{index}].Attributes"
            )
            event = decision
            expected_timestamp = decision["decided_at"]
        elif event_name == OUTCOME_EVENT:
            transaction_id, outcome = _outcome_from_attributes(
                record["Attributes"], f"records[{index}].Attributes"
            )
            event = outcome
            expected_timestamp = outcome["observed_at"]
        else:
            raise ValueError("OpenTelemetry event name is unsupported")
        prior_transaction = trace_transactions.setdefault(trace_id, transaction_id)
        prior_trace = transaction_traces.setdefault(transaction_id, trace_id)
        if prior_transaction != transaction_id or prior_trace != trace_id:
            raise ValueError("each transaction must bind to exactly one OpenTelemetry trace")
        group = groups.setdefault(
            transaction_id, {"intent": [], "approval": [], "decision": [], "outcome": []}
        )
        kind = {
            INTENT_EVENT: "intent",
            APPROVAL_EVENT: "approval",
            DECISION_EVENT: "decision",
            OUTCOME_EVENT: "outcome",
        }[event_name]
        group[kind].append((event, timestamp))
        if expected_timestamp is not None and timestamp != _unix_nano(
            expected_timestamp, f"{event_name} declared time"
        ):
            raise ValueError("OpenTelemetry Timestamp differs from the declared lifecycle time")
    for transaction_id, group in groups.items():
        if len(group["intent"]) != 1 or len(group["decision"]) != 1 or len(group["outcome"]) != 1:
            raise ValueError(
                f"transaction {transaction_id} must have exactly one intent, decision, and outcome"
            )
        outcome, outcome_timestamp = group["outcome"][0]
        decision = group["decision"][0][0]
        if outcome["observed_at"] is None and outcome_timestamp != _unix_nano(
            decision["decided_at"], "decision time"
        ):
            raise ValueError("unobserved outcome timestamp must equal its decision time")
    return groups


def validate_mandate_otel_log_export(value: Any, plan_value: Mapping[str, Any]) -> Dict[str, Any]:
    plan = validate_mandate_plan(plan_value)
    export = _exact(
        value,
        "OpenTelemetry LureMandate log export",
        (
            "schema",
            "schema_version",
            "export_id",
            "generated_at",
            "time_origin_unix_nano",
            "campaign_id",
            "plan_sha256",
            "run_id",
            "started_at",
            "completed_at",
            "receiver",
            "records",
            "privacy",
            "limitations",
        ),
    )
    if export["schema"] != OTEL_EXPORT_SCHEMA or export["schema_version"] != 1:
        raise ValueError("unsupported LureMandate OpenTelemetry export schema")
    for name in ("export_id", "campaign_id", "run_id"):
        _identifier(export[name], f"OpenTelemetry export.{name}")
    _timestamp(export["generated_at"], "generated_at")
    started = _instant(export["started_at"], "started_at")
    completed = _instant(export["completed_at"], "completed_at")
    generated = _instant(export["generated_at"], "generated_at")
    if (
        started <= _instant(plan["created_at"], "plan.created_at")
        or not started <= completed < generated
    ):
        raise ValueError("OpenTelemetry export has an invalid run or generation window")
    origin = _integer(export["time_origin_unix_nano"], "time_origin_unix_nano", 1, MAX_UNIX_NANO)
    if origin != _unix_nano(export["started_at"], "started_at"):
        raise ValueError("OpenTelemetry time origin must exactly equal run start")
    expected_plan_digest = _sha256(_canonical(plan))
    if (
        export["campaign_id"] != plan["campaign_id"]
        or _digest(export["plan_sha256"], "plan_sha256") != expected_plan_digest
    ):
        raise ValueError("OpenTelemetry export does not bind the supplied plan")
    _receiver(export["receiver"])
    records = export["records"]
    if not isinstance(records, list) or not 1 <= len(records) <= MAX_RECORDS:
        raise ValueError("OpenTelemetry records must be a nonempty bounded array")
    if export["privacy"] != PRIVACY or export["limitations"] != EXPORT_LIMITATIONS:
        raise ValueError("OpenTelemetry privacy or limitations are incomplete")
    groups = _grouped_records(export)
    if not 1 <= len(groups) <= MAX_TRANSACTIONS:
        raise ValueError("OpenTelemetry transaction count is unsupported")
    return dict(export)


def _projection_value(
    plan_value: Mapping[str, Any], export_value: Mapping[str, Any]
) -> Dict[str, Any]:
    plan = validate_mandate_plan(plan_value)
    export = validate_mandate_otel_log_export(export_value, plan)
    groups = _grouped_records(export)
    transactions = []
    for transaction_id, group in groups.items():
        intent_record = group["intent"][0][0]
        approvals = sorted(
            (item[0] for item in group["approval"]), key=lambda item: item["approval_id"]
        )
        transactions.append(
            {
                "transaction_id": transaction_id,
                "sequence": intent_record["sequence"],
                "intent": intent_record["intent"],
                "intent_sha256": intent_record["intent_sha256"],
                "approvals": approvals,
                "decision": group["decision"][0][0],
                "outcome": group["outcome"][0][0],
            }
        )
    transactions.sort(key=lambda item: item["sequence"])
    receiver = export["receiver"]
    run = validate_mandate_run(
        {
            "schema": RUN_SCHEMA,
            "schema_version": 1,
            "run_id": export["run_id"],
            "campaign_id": export["campaign_id"],
            "plan_sha256": export["plan_sha256"],
            "started_at": export["started_at"],
            "completed_at": export["completed_at"],
            "engine": {
                "engine_id": receiver["name"],
                "engine_version": receiver["version"],
                "engine_artifact_sha256": receiver["artifact_sha256"],
            },
            "transactions": transactions,
            "privacy": dict(RUN_PRIVACY),
            "limitations": list(RUN_LIMITATIONS),
        },
        plan,
    )
    return {
        "schema": OTEL_PROJECTION_SCHEMA,
        "schema_version": 1,
        "generated_at": export["generated_at"],
        "implementation": {"name": "lurebench", "version": __version__},
        "inputs": {
            "mandate_plan": plan,
            "mandate_plan_sha256": _sha256(_canonical(plan)),
            "otel_log_export": export,
            "otel_log_export_sha256": _sha256(_canonical(export)),
        },
        "run": run,
        "run_sha256": _sha256(_canonical(run)),
        "clock_boundary": dict(CLOCK_BOUNDARY),
        "privacy": dict(PRIVACY),
        "limitations": list(PROJECTION_LIMITATIONS),
    }


def project_mandate_otel_run(
    plan_value: Mapping[str, Any], export_value: Mapping[str, Any]
) -> Dict[str, Any]:
    return _projection_value(plan_value, export_value)


def validate_mandate_otel_projection(value: Any) -> Dict[str, Any]:
    projection = _exact(
        value,
        "OpenTelemetry LureMandate projection",
        (
            "schema",
            "schema_version",
            "generated_at",
            "implementation",
            "inputs",
            "run",
            "run_sha256",
            "clock_boundary",
            "privacy",
            "limitations",
        ),
    )
    if projection["schema"] != OTEL_PROJECTION_SCHEMA or projection["schema_version"] != 1:
        raise ValueError("unsupported LureMandate OpenTelemetry projection schema")
    inputs = projection["inputs"]
    if not isinstance(inputs, dict):
        raise ValueError("OpenTelemetry LureMandate projection inputs must be an object")
    expected = _projection_value(
        inputs.get("mandate_plan"),
        inputs.get("otel_log_export"),
    )
    if projection != expected:
        raise ValueError("OpenTelemetry LureMandate projection does not independently recompute")
    return dict(projection)


def load_mandate_otel_log_export(path: Path, plan_value: Mapping[str, Any]) -> Dict[str, Any]:
    return validate_mandate_otel_log_export(
        _load(Path(path), "OpenTelemetry LureMandate log export"), plan_value
    )


def load_mandate_otel_projection(path: Path) -> Dict[str, Any]:
    return validate_mandate_otel_projection(
        _load(Path(path), "OpenTelemetry LureMandate projection")
    )


def write_mandate_otel_export(
    path: Path, export: Mapping[str, Any], plan: Mapping[str, Any]
) -> None:
    _write(Path(path), validate_mandate_otel_log_export(export, plan))


def write_mandate_otel_projection_and_run(
    projection_path: Path, run_path: Path, projection: Mapping[str, Any]
) -> None:
    reviewed = validate_mandate_otel_projection(projection)
    first, second = Path(projection_path), Path(run_path)
    if first == second:
        raise ValueError("LureMandate projection and run outputs must be different files")
    if first.exists() or first.is_symlink() or second.exists() or second.is_symlink():
        raise FileExistsError("LureMandate OpenTelemetry outputs must both be new files")
    _write(first, reviewed)
    try:
        _write(second, reviewed["run"])
    except Exception:
        first.unlink(missing_ok=True)
        raise
