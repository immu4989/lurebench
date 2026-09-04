"""Body-free OpenTelemetry log projection into LureIdentity observations.

This consumes a strict JSON projection of the stable OpenTelemetry Logs Data
Model. It is deliberately not a general OTLP decoder or a semantic-conventions
conformance claim.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Mapping

from . import __version__
from .identity import (
    DECISIONS,
    DISPOSITIONS,
    MAX_EVENTS,
    MAX_NODES,
    MAX_PROBES,
    REASONS,
    RUN_LIMITATIONS,
    RUN_SCHEMA,
    _digest,
    _read,
    _sha256,
    _time,
    _validate_implementation,
    _write,
    validate_identity_plan,
    validate_identity_run,
)
from .permit import _canonical, _exact, _identifier, _integer, _timestamp

OTEL_EXPORT_SCHEMA = "https://github.com/immu4989/lurebench/spec/lureidentity-otel-log-export/v1"
OTEL_PROJECTION_SCHEMA = (
    "https://github.com/immu4989/lurebench/spec/lureidentity-otel-projection/v1"
)
LIFECYCLE_EVENT = "org.lurebench.lureidentity.lifecycle_event_observed"
ACCESS_EVENT = "org.lurebench.lureidentity.access_decided"
MAX_RECORDS = MAX_EVENTS * MAX_NODES * 4 + MAX_PROBES
MAX_UNIX_NANO = 9_223_372_036_854_775_807
_TRACE_ID = re.compile(r"^[a-f0-9]{32}$")
_SPAN_ID = re.compile(r"^[a-f0-9]{16}$")

EXPORT_LIMITATIONS = [
    "strict_body_free_projection_of_the_opentelemetry_log_data_model_not_raw_otlp",
    "custom_lurebench_event_names_and_attributes_are_not_opentelemetry_semantic_conventions",
    "timestamps_service_identity_and_attributes_require_external_instrumentation_assurance",
    "only_opaque_plan_identifiers_digests_decisions_and_reason_codes_are_accepted",
]
PROJECTION_LIMITATIONS = [
    "projection_rejects_log_body_unknown_attributes_raw_directory_or_subject_ids_and_secrets",
    "benchmark_timing_uses_origin_clock_timestamp_not_collector_observed_timestamp",
    "access_event_timestamp_must_equal_the_preregistered_probe_attempt_time",
    "trace_context_correlates_records_but_does_not_authenticate_or_prove_causality",
    "projection_does_not_prove_telemetry_completeness_clock_sync_delivery_or_enforcement",
    "projection_is_not_otlp_or_opentelemetry_semantic_conventions_conformance",
]
PRIVACY = {
    "body_accepted": False,
    "raw_directory_or_subject_identifiers_accepted": False,
    "spiffe_ids_accepted_in_records": False,
    "tokens_credentials_prompts_payloads_or_targets_accepted": False,
    "opaque_plan_identifiers_and_digests_only": True,
}
CLOCK_BOUNDARY = {
    "benchmark_time_field": "Timestamp",
    "collector_time_field": "ObservedTimestamp",
    "observed_timestamp_used_for_benchmark_timing": False,
    "timestamp_resolution": "millisecond_aligned_relative_to_time_origin_unix_nano",
    "access_timestamp_binding": "exact_preregistered_probe_attempt_time",
    "external_clock_assurance_required": True,
}


def _hex_id(value: Any, field: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None or set(value) == {"0"}:
        raise ValueError(f"{field} must be a nonzero lowercase hexadecimal identifier")
    return value


def _relative_ms(timestamp: Any, origin: int, field: str) -> int:
    reviewed = _integer(timestamp, field, 1, MAX_UNIX_NANO)
    delta = reviewed - origin
    if delta < 0 or delta % 1_000_000:
        raise ValueError(f"{field} must be millisecond-aligned at or after the declared origin")
    return _integer(delta // 1_000_000, f"{field} relative milliseconds", 0, 86_400_000)


def _unix_nano(value: str) -> int:
    instant = _time(value).astimezone(timezone.utc)
    delta = instant - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86_400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1_000


def validate_identity_otel_log_export(
    value: Any, plan: Mapping[str, Any]
) -> Dict[str, Any]:
    reviewed_plan = validate_identity_plan(plan)
    export = _exact(
        value,
        "OpenTelemetry identity log export",
        (
            "schema",
            "schema_version",
            "export_id",
            "generated_at",
            "time_origin_unix_nano",
            "receiver",
            "records",
            "limitations",
        ),
    )
    if export["schema"] != OTEL_EXPORT_SCHEMA or export["schema_version"] != 1:
        raise ValueError("unsupported LureIdentity OpenTelemetry export schema")
    _identifier(export["export_id"], "otel export.export_id")
    _timestamp(export["generated_at"], "otel export.generated_at")
    if _time(export["generated_at"]) < _time(reviewed_plan["created_at"]):
        raise ValueError("OpenTelemetry export cannot predate its identity plan")
    origin = _integer(
        export["time_origin_unix_nano"],
        "otel export.time_origin_unix_nano",
        1,
        MAX_UNIX_NANO,
    )
    generated_nano = _unix_nano(export["generated_at"])
    if origin > generated_nano:
        raise ValueError("OpenTelemetry time origin cannot follow export generation")
    receiver = _validate_implementation(export["receiver"], "otel export.receiver")
    records = export["records"]
    if not isinstance(records, list) or not 1 <= len(records) <= MAX_RECORDS:
        raise ValueError("OpenTelemetry export records must be a nonempty bounded array")
    events = {item["event_id"]: item for item in reviewed_plan["events"]}
    nodes = {item["node_id"]: item for item in reviewed_plan["nodes"]}
    probes = {item["probe_id"]: item for item in reviewed_plan["probes"]}
    contexts: set[tuple[str, str]] = set()
    for index, item in enumerate(records):
        record = _exact(
            item,
            f"otel export.records[{index}]",
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
        timestamp = _integer(
            record["Timestamp"], f"records[{index}].Timestamp", 1, MAX_UNIX_NANO
        )
        relative_ms = _relative_ms(timestamp, origin, f"records[{index}].Timestamp")
        observed = _integer(
            record["ObservedTimestamp"],
            f"records[{index}].ObservedTimestamp",
            1,
            MAX_UNIX_NANO,
        )
        if timestamp > generated_nano or observed > generated_nano:
            raise ValueError("OpenTelemetry record cannot follow export generation")
        trace_id = _hex_id(record["TraceId"], f"records[{index}].TraceId", _TRACE_ID)
        span_id = _hex_id(record["SpanId"], f"records[{index}].SpanId", _SPAN_ID)
        if (trace_id, span_id) in contexts:
            raise ValueError("OpenTelemetry export contains duplicate trace/span context")
        contexts.add((trace_id, span_id))
        resource = _exact(
            record["Resource"],
            f"records[{index}].Resource",
            ("service.name", "service.instance.id", "service.version"),
        )
        if (
            resource["service.name"] != receiver["name"]
            or resource["service.version"] != receiver["version"]
        ):
            raise ValueError("OpenTelemetry resource differs from the declared receiver")
        node_id = _identifier(
            resource["service.instance.id"], f"records[{index}].service.instance.id"
        )
        attributes = record["Attributes"]
        if record["EventName"] == LIFECYCLE_EVENT:
            event_observation = _exact(
                attributes,
                f"records[{index}].Attributes",
                ("observation_id", "event_id", "node_id", "event_sha256", "disposition"),
            )
            _identifier(event_observation["observation_id"], "lifecycle observation id")
            if (
                event_observation["event_id"] not in events
                or event_observation["node_id"] not in nodes
            ):
                raise ValueError("OpenTelemetry lifecycle record references an unknown event or node")
            if event_observation["node_id"] != node_id:
                raise ValueError("OpenTelemetry lifecycle node differs from its service instance")
            _digest(event_observation["event_sha256"], "lifecycle event digest")
            if event_observation["disposition"] not in DISPOSITIONS:
                raise ValueError("OpenTelemetry lifecycle disposition is unsupported")
        elif record["EventName"] == ACCESS_EVENT:
            access = _exact(
                attributes,
                f"records[{index}].Attributes",
                ("probe_id", "decision", "reason_code"),
            )
            if access["probe_id"] not in probes:
                raise ValueError("OpenTelemetry access record references an unknown probe")
            probe = probes[access["probe_id"]]
            if probe["node_id"] != node_id:
                raise ValueError("OpenTelemetry access probe differs from its service instance")
            if relative_ms != probe["attempted_at_ms"]:
                raise ValueError("OpenTelemetry access timestamp differs from its planned probe")
            if access["decision"] not in DECISIONS or access["reason_code"] not in REASONS:
                raise ValueError("OpenTelemetry access decision or reason is unsupported")
        else:
            raise ValueError("OpenTelemetry record event name is unsupported")
    if export["limitations"] != EXPORT_LIMITATIONS:
        raise ValueError("OpenTelemetry export limitations are invalid")
    return dict(export)


def _projection_value(
    plan: Mapping[str, Any], export: Mapping[str, Any], *, run_id: str
) -> Dict[str, Any]:
    reviewed_plan = validate_identity_plan(plan)
    reviewed_export = validate_identity_otel_log_export(export, reviewed_plan)
    _identifier(run_id, "OpenTelemetry identity projection run_id")
    origin = reviewed_export["time_origin_unix_nano"]
    event_order = {
        item["event_id"]: index for index, item in enumerate(reviewed_plan["events"])
    }
    node_order = {
        item["node_id"]: index for index, item in enumerate(reviewed_plan["nodes"])
    }
    probe_order = {
        item["probe_id"]: index for index, item in enumerate(reviewed_plan["probes"])
    }
    lifecycle_records = sorted(
        (
            item
            for item in reviewed_export["records"]
            if item["EventName"] == LIFECYCLE_EVENT
        ),
        key=lambda item: (
            event_order[item["Attributes"]["event_id"]],
            node_order[item["Attributes"]["node_id"]],
            item["Timestamp"],
            item["Attributes"]["observation_id"],
            item["TraceId"],
            item["SpanId"],
        ),
    )
    access_records = sorted(
        (item for item in reviewed_export["records"] if item["EventName"] == ACCESS_EVENT),
        key=lambda item: (
            probe_order[item["Attributes"]["probe_id"]],
            item["TraceId"],
            item["SpanId"],
        ),
    )
    event_observations = []
    access_observations = []
    for record in lifecycle_records:
        attributes = record["Attributes"]
        event_observations.append(
            {
                "observation_id": attributes["observation_id"],
                "event_id": attributes["event_id"],
                "node_id": attributes["node_id"],
                "received_at_ms": _relative_ms(record["Timestamp"], origin, "Timestamp"),
                "event_sha256": attributes["event_sha256"],
                "disposition": attributes["disposition"],
            }
        )
    for record in access_records:
        attributes = record["Attributes"]
        access_observations.append(
            {
                "probe_id": attributes["probe_id"],
                "decision": attributes["decision"],
                "reason_code": attributes["reason_code"],
            }
        )
    run = validate_identity_run(
        {
            "schema": RUN_SCHEMA,
            "schema_version": 1,
            "run_id": run_id,
            "generated_at": reviewed_export["generated_at"],
            "implementation": dict(reviewed_export["receiver"]),
            "plan_sha256": _sha256(_canonical(reviewed_plan)),
            "event_observations": event_observations,
            "access_observations": access_observations,
            "limitations": list(RUN_LIMITATIONS),
        },
        reviewed_plan,
    )
    return {
        "schema": OTEL_PROJECTION_SCHEMA,
        "schema_version": 1,
        "generated_at": reviewed_export["generated_at"],
        "implementation": {"name": "lurebench", "version": __version__},
        "inputs": {
            "identity_plan": reviewed_plan,
            "identity_plan_sha256": _sha256(_canonical(reviewed_plan)),
            "otel_log_export": reviewed_export,
            "otel_log_export_sha256": _sha256(_canonical(reviewed_export)),
        },
        "run": run,
        "run_sha256": _sha256(_canonical(run)),
        "clock_boundary": dict(CLOCK_BOUNDARY),
        "privacy": dict(PRIVACY),
        "limitations": list(PROJECTION_LIMITATIONS),
    }


def project_identity_otel_run(
    plan: Mapping[str, Any], export: Mapping[str, Any], *, run_id: str
) -> Dict[str, Any]:
    return _projection_value(plan, export, run_id=run_id)


def validate_identity_otel_projection(value: Any) -> Dict[str, Any]:
    projection = _exact(
        value,
        "OpenTelemetry identity projection",
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
        raise ValueError("unsupported LureIdentity OpenTelemetry projection schema")
    inputs = projection["inputs"]
    if not isinstance(inputs, dict) or not isinstance(projection["run"], dict):
        raise ValueError("OpenTelemetry identity projection inputs and run must be objects")
    expected = _projection_value(
        inputs.get("identity_plan"),
        inputs.get("otel_log_export"),
        run_id=projection["run"].get("run_id"),
    )
    if projection != expected:
        raise ValueError("OpenTelemetry identity projection does not independently recompute")
    return dict(projection)


def load_identity_otel_log_export(
    path: Path, plan: Mapping[str, Any]
) -> Dict[str, Any]:
    return validate_identity_otel_log_export(
        _read(Path(path), "OpenTelemetry identity log export"), plan
    )


def load_identity_otel_projection(path: Path) -> Dict[str, Any]:
    return validate_identity_otel_projection(
        _read(Path(path), "OpenTelemetry identity projection")
    )


def write_identity_otel_projection_and_run(
    projection_path: Path,
    run_path: Path,
    projection: Mapping[str, Any],
) -> None:
    reviewed = validate_identity_otel_projection(projection)
    first = Path(projection_path)
    second = Path(run_path)
    if first == second:
        raise ValueError("identity projection and run outputs must be different files")
    if first.exists() or first.is_symlink() or second.exists() or second.is_symlink():
        raise FileExistsError("OpenTelemetry identity projection outputs must both be new files")
    _write(first, reviewed)
    try:
        _write(second, reviewed["run"])
    except Exception:
        first.unlink(missing_ok=True)
        raise
