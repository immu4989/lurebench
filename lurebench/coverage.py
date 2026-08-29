"""LureCoverage: safe evidence that boundary telemetry is observable end to end.

LureCoverage does not execute actions.  It emits typed, payload-free canary
descriptors for an operator-controlled test harness, then scores returned sensor
acknowledgements for loss, duplication, ordering, latency, and lineage.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence

from .boundary import _ACTIONS, _RESOURCES
from .receipts import loads_strict_json

MANIFEST_SCHEMA = "https://github.com/immu4989/lurebench/spec/agent-coverage-manifest/v1"
CANARY_SCHEMA = "https://github.com/immu4989/lurebench/spec/agent-coverage-canaries/v1"
OBSERVATION_SCHEMA = "https://github.com/immu4989/lurebench/spec/agent-coverage-observations/v1"
REPORT_SCHEMA = "https://github.com/immu4989/lurebench/spec/agent-coverage-evaluation/v1"
MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
MAX_ROUTES = 256
MAX_PROBES = 4096

_ID = re.compile(r"^[a-z0-9]+(?:[a-z0-9._-]*[a-z0-9])?$")
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_LIMITATIONS = [
    "canaries_are_typed_metadata_and_do_not_execute_agent_actions",
    "coverage_applies_only_to_declared_routes_sensors_and_capture_window",
    "sensor_acknowledgements_are_operator_supplied_and_must_be_independently_trusted",
    "passing_does_not_prove_semantic_correctness_of_non_canary_production_events",
    "results_are_measurement_evidence_not_containment_compliance_or_authorization",
]


def _exact(value: Any, field: str, keys: Sequence[str]) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError(f"{field} must contain exactly: {', '.join(sorted(keys))}")
    return value


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 96 or _ID.fullmatch(value) is None:
        raise ValueError(f"{field} must be a bounded lowercase identifier")
    return value


def _integer(value: Any, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{field} must be an integer between {minimum} and {maximum}")
    return value


def _rate(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} must be a probability")
    result = float(value)
    if not math.isfinite(result) or not 0 <= result <= 1:
        raise ValueError(f"{field} must be finite and between zero and one")
    return result


def _timestamp(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be an ISO 8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a UTC offset")
    return value


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
        + "\n"
    ).encode("utf-8")


def _read(path: Path) -> bytes:
    target = Path(path)
    if target.is_symlink() or not target.is_file():
        raise ValueError(f"{target} must be a regular local JSON file")
    if target.stat().st_size > MAX_ARTIFACT_BYTES:
        raise ValueError(f"{target.name} exceeds the 2 MiB limit")
    return target.read_bytes()


def _write_new(path: Path, value: Mapping[str, Any]) -> None:
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


def validate_coverage_manifest(value: Any) -> Dict[str, Any]:
    manifest = _exact(
        value,
        "manifest",
        (
            "schema",
            "schema_version",
            "manifest_id",
            "manifest_version",
            "system_id",
            "routes",
            "acceptance",
            "limitations",
        ),
    )
    if manifest["schema"] != MANIFEST_SCHEMA or manifest["schema_version"] != 1:
        raise ValueError("unsupported LureCoverage manifest schema")
    _identifier(manifest["manifest_id"], "manifest.manifest_id")
    _identifier(manifest["manifest_version"], "manifest.manifest_version")
    _identifier(manifest["system_id"], "manifest.system_id")
    routes = manifest["routes"]
    if not isinstance(routes, list) or not 1 <= len(routes) <= MAX_ROUTES:
        raise ValueError("manifest.routes must be a non-empty bounded array")
    normalized_routes = []
    route_ids = set()
    for index, raw_route in enumerate(routes):
        field = f"manifest.routes[{index}]"
        route = _exact(
            raw_route,
            field,
            (
                "route_id",
                "action",
                "resource_class",
                "enforcement_point_id",
                "sensor_id",
                "required",
                "max_delivery_delay_ms",
            ),
        )
        route_id = _identifier(route["route_id"], f"{field}.route_id")
        if route_id in route_ids:
            raise ValueError("manifest contains a duplicate route_id")
        route_ids.add(route_id)
        if route["action"] not in _ACTIONS or route["resource_class"] not in _RESOURCES:
            raise ValueError(f"{field} contains an unsupported action or resource class")
        _identifier(route["enforcement_point_id"], f"{field}.enforcement_point_id")
        _identifier(route["sensor_id"], f"{field}.sensor_id")
        if not isinstance(route["required"], bool):
            raise ValueError(f"{field}.required must be boolean")
        _integer(route["max_delivery_delay_ms"], f"{field}.max_delivery_delay_ms", 1, 86_400_000)
        normalized_routes.append(dict(route))
    if not any(route["required"] for route in normalized_routes):
        raise ValueError("manifest must contain at least one required route")
    acceptance = _exact(
        manifest["acceptance"],
        "manifest.acceptance",
        (
            "minimum_route_coverage",
            "minimum_probe_delivery_rate",
            "maximum_duplicate_rate",
            "maximum_out_of_order_rate",
            "minimum_lineage_continuity",
            "maximum_delivery_delay_ms",
        ),
    )
    normalized_acceptance = {
        key: _rate(acceptance[key], f"manifest.acceptance.{key}")
        for key in (
            "minimum_route_coverage",
            "minimum_probe_delivery_rate",
            "maximum_duplicate_rate",
            "maximum_out_of_order_rate",
            "minimum_lineage_continuity",
        )
    }
    normalized_acceptance["maximum_delivery_delay_ms"] = _integer(
        acceptance["maximum_delivery_delay_ms"],
        "manifest.acceptance.maximum_delivery_delay_ms",
        1,
        86_400_000,
    )
    if manifest["limitations"] != _LIMITATIONS:
        raise ValueError("manifest limitations are not the LureCoverage v1 boundary")
    return {
        **dict(manifest),
        "routes": normalized_routes,
        "acceptance": normalized_acceptance,
        "limitations": list(_LIMITATIONS),
    }


def load_coverage_manifest(path: Path) -> tuple[Dict[str, Any], str]:
    raw = _read(path)
    return validate_coverage_manifest(loads_strict_json(raw)), _sha256(raw)


def build_coverage_canaries(
    manifest_path: Path,
    *,
    replicates: int = 1,
    created_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Create deterministic, action-free canary descriptors for every route."""

    manifest, manifest_sha = load_coverage_manifest(manifest_path)
    _integer(replicates, "replicates", 1, 32)
    probes = []
    sequence = 0
    for route in manifest["routes"]:
        for replicate in range(1, replicates + 1):
            sequence += 1
            seed = f"{manifest_sha}:{route['route_id']}:{replicate}".encode("utf-8")
            probes.append(
                {
                    "probe_id": f"probe-{hashlib.sha256(seed).hexdigest()[:24]}",
                    "emitted_sequence": sequence,
                    "route_id": route["route_id"],
                    "action": route["action"],
                    "resource_class": route["resource_class"],
                    "enforcement_point_id": route["enforcement_point_id"],
                    "expected_sensor_id": route["sensor_id"],
                    "executes_action": False,
                }
            )
    artifact = {
        "schema": CANARY_SCHEMA,
        "schema_version": 1,
        "created_at": created_at or _now(),
        "manifest_sha256": manifest_sha,
        "replicates_per_route": replicates,
        "probes": probes,
    }
    return validate_coverage_canaries(artifact, manifest=manifest, manifest_sha=manifest_sha)


def validate_coverage_canaries(
    value: Any,
    *,
    manifest: Mapping[str, Any],
    manifest_sha: str,
) -> Dict[str, Any]:
    artifact = _exact(
        value,
        "canaries",
        (
            "schema",
            "schema_version",
            "created_at",
            "manifest_sha256",
            "replicates_per_route",
            "probes",
        ),
    )
    if artifact["schema"] != CANARY_SCHEMA or artifact["schema_version"] != 1:
        raise ValueError("unsupported LureCoverage canary schema")
    _timestamp(artifact["created_at"], "canaries.created_at")
    if artifact["manifest_sha256"] != manifest_sha:
        raise ValueError("canaries do not bind the supplied manifest bytes")
    replicates = _integer(artifact["replicates_per_route"], "canaries.replicates_per_route", 1, 32)
    probes = artifact["probes"]
    expected_count = len(manifest["routes"]) * replicates
    if not isinstance(probes, list) or len(probes) != expected_count or len(probes) > MAX_PROBES:
        raise ValueError("canary count does not match routes times replicates")
    route_map = {route["route_id"]: route for route in manifest["routes"]}
    seen = set()
    route_counts = {route_id: 0 for route_id in route_map}
    normalized = []
    for index, raw_probe in enumerate(probes):
        field = f"canaries.probes[{index}]"
        probe = _exact(
            raw_probe,
            field,
            (
                "probe_id",
                "emitted_sequence",
                "route_id",
                "action",
                "resource_class",
                "enforcement_point_id",
                "expected_sensor_id",
                "executes_action",
            ),
        )
        probe_id = _identifier(probe["probe_id"], f"{field}.probe_id")
        if probe_id in seen:
            raise ValueError("canaries contain a duplicate probe_id")
        seen.add(probe_id)
        if probe["emitted_sequence"] != index + 1:
            raise ValueError("canary emitted_sequence must be contiguous and ordered")
        route_id = _identifier(probe["route_id"], f"{field}.route_id")
        if route_id not in route_map:
            raise ValueError(f"{field} references an unknown route")
        route = route_map[route_id]
        expected = {
            "action": route["action"],
            "resource_class": route["resource_class"],
            "enforcement_point_id": route["enforcement_point_id"],
            "expected_sensor_id": route["sensor_id"],
        }
        if any(probe[key] != expected_value for key, expected_value in expected.items()):
            raise ValueError(f"{field} does not reproduce its manifest route")
        if probe["executes_action"] is not False:
            raise ValueError("LureCoverage canaries must declare executes_action=false")
        route_counts[route_id] += 1
        normalized.append(dict(probe))
    if any(count != replicates for count in route_counts.values()):
        raise ValueError("each route must have exactly replicates_per_route canaries")
    return {**dict(artifact), "probes": normalized}


def _load_canaries(path: Path, manifest: Mapping[str, Any], manifest_sha: str) -> Dict[str, Any]:
    return validate_coverage_canaries(
        loads_strict_json(_read(path)), manifest=manifest, manifest_sha=manifest_sha
    )


def _load_observations(path: Path, manifest_sha: str) -> Dict[str, Any]:
    artifact = _exact(
        loads_strict_json(_read(path)),
        "observations",
        ("schema", "schema_version", "captured_at", "manifest_sha256", "observations"),
    )
    if artifact["schema"] != OBSERVATION_SCHEMA or artifact["schema_version"] != 1:
        raise ValueError("unsupported LureCoverage observation schema")
    _timestamp(artifact["captured_at"], "observations.captured_at")
    if artifact["manifest_sha256"] != manifest_sha:
        raise ValueError("observations do not bind the supplied manifest bytes")
    items = artifact["observations"]
    if not isinstance(items, list) or len(items) > MAX_PROBES:
        raise ValueError("observations must be a bounded array")
    seen = set()
    normalized = []
    for index, raw_item in enumerate(items):
        field = f"observations.observations[{index}]"
        item = _exact(
            raw_item,
            field,
            (
                "probe_id",
                "sensor_id",
                "observed_sequence",
                "copies",
                "lineage_contiguous",
                "delivery_delay_ms",
            ),
        )
        probe_id = _identifier(item["probe_id"], f"{field}.probe_id")
        if probe_id in seen:
            raise ValueError("observations contain a duplicate probe_id")
        seen.add(probe_id)
        _identifier(item["sensor_id"], f"{field}.sensor_id")
        _integer(item["observed_sequence"], f"{field}.observed_sequence", 1, MAX_PROBES * 32)
        _integer(item["copies"], f"{field}.copies", 1, 1024)
        if not isinstance(item["lineage_contiguous"], bool):
            raise ValueError(f"{field}.lineage_contiguous must be boolean")
        _integer(item["delivery_delay_ms"], f"{field}.delivery_delay_ms", 0, 86_400_000)
        normalized.append(dict(item))
    return {**dict(artifact), "observations": normalized}


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


def evaluate_coverage(
    manifest_path: Path,
    canaries_path: Path,
    observations_path: Path,
    *,
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    manifest, manifest_sha = load_coverage_manifest(manifest_path)
    canary_raw = _read(canaries_path)
    canaries = validate_coverage_canaries(
        loads_strict_json(canary_raw), manifest=manifest, manifest_sha=manifest_sha
    )
    observations = _load_observations(observations_path, manifest_sha)
    route_map = {route["route_id"]: route for route in manifest["routes"]}
    probe_map = {probe["probe_id"]: probe for probe in canaries["probes"]}
    observed_map = {item["probe_id"]: item for item in observations["observations"]}
    unknown = sorted(set(observed_map) - set(probe_map))
    if unknown:
        raise ValueError(f"observations reference unknown probes: {', '.join(unknown[:3])}")

    results = []
    previous_observed: dict[str, int] = {}
    delivered = duplicates = out_of_order = lineage_ok = 0
    observed_delays = []
    route_passes: dict[str, list[bool]] = {route_id: [] for route_id in route_map}
    for probe in canaries["probes"]:
        route = route_map[probe["route_id"]]
        observed = observed_map.get(probe["probe_id"])
        is_delivered = observed is not None and observed["sensor_id"] == route["sensor_id"]
        duplicate = bool(is_delivered and observed["copies"] > 1)
        ordering_failure = False
        if is_delivered:
            prior = previous_observed.get(route["route_id"])
            ordering_failure = prior is not None and observed["observed_sequence"] <= prior
            previous_observed[route["route_id"]] = observed["observed_sequence"]
            delivered += 1
            duplicates += duplicate
            out_of_order += ordering_failure
            lineage_ok += observed["lineage_contiguous"]
            observed_delays.append(observed["delivery_delay_ms"])
        delay = observed["delivery_delay_ms"] if is_delivered else None
        copies = observed["copies"] if is_delivered else 0
        lineage = observed["lineage_contiguous"] if is_delivered else False
        passed = bool(
            is_delivered
            and not duplicate
            and not ordering_failure
            and lineage
            and delay is not None
            and delay <= route["max_delivery_delay_ms"]
        )
        route_passes[route["route_id"]].append(passed)
        results.append(
            {
                "probe_id": probe["probe_id"],
                "route_id": route["route_id"],
                "required": route["required"],
                "emitted_sequence": probe["emitted_sequence"],
                "observed_sequence": observed["observed_sequence"] if is_delivered else None,
                "delivered": is_delivered,
                "copies": copies,
                "out_of_order": ordering_failure,
                "lineage_contiguous": lineage,
                "delivery_delay_ms": delay,
                "allowed_delivery_delay_ms": route["max_delivery_delay_ms"],
                "passed": passed,
            }
        )

    required_routes = [route for route in manifest["routes"] if route["required"]]
    covered_required_routes = sum(all(route_passes[route["route_id"]]) for route in required_routes)
    total = len(results)
    summary = {
        "total_routes": len(manifest["routes"]),
        "required_routes": len(required_routes),
        "covered_required_routes": covered_required_routes,
        "total_probes": total,
        "delivered_probes": delivered,
        "missing_probes": total - delivered,
        "duplicate_probes": duplicates,
        "out_of_order_probes": out_of_order,
        "lineage_contiguous_probes": lineage_ok,
        "route_coverage": _ratio(covered_required_routes, len(required_routes)),
        "probe_delivery_rate": _ratio(delivered, total),
        "duplicate_rate": _ratio(duplicates, total),
        "out_of_order_rate": _ratio(out_of_order, delivered),
        "lineage_continuity": _ratio(lineage_ok, delivered),
        "maximum_delivery_delay_ms": max(observed_delays) if observed_delays else None,
    }
    acceptance = manifest["acceptance"]
    summary["verdict"] = (
        "pass"
        if (
            summary["route_coverage"] >= acceptance["minimum_route_coverage"]
            and summary["probe_delivery_rate"] >= acceptance["minimum_probe_delivery_rate"]
            and summary["duplicate_rate"] <= acceptance["maximum_duplicate_rate"]
            and summary["out_of_order_rate"] <= acceptance["maximum_out_of_order_rate"]
            and summary["lineage_continuity"] >= acceptance["minimum_lineage_continuity"]
            and summary["maximum_delivery_delay_ms"] is not None
            and summary["maximum_delivery_delay_ms"] <= acceptance["maximum_delivery_delay_ms"]
        )
        else "fail"
    )
    report = {
        "schema": REPORT_SCHEMA,
        "schema_version": 1,
        "generated_at": generated_at or _now(),
        "manifest": {
            "manifest_id": manifest["manifest_id"],
            "manifest_version": manifest["manifest_version"],
            "manifest_sha256": manifest_sha,
        },
        "canaries_sha256": _sha256(canary_raw),
        "acceptance": dict(acceptance),
        "results": results,
        "summary": summary,
        "limitations": list(_LIMITATIONS),
    }
    return validate_coverage_evaluation(report)


def validate_coverage_evaluation(value: Any) -> Dict[str, Any]:
    report = _exact(
        value,
        "report",
        (
            "schema",
            "schema_version",
            "generated_at",
            "manifest",
            "canaries_sha256",
            "acceptance",
            "results",
            "summary",
            "limitations",
        ),
    )
    if report["schema"] != REPORT_SCHEMA or report["schema_version"] != 1:
        raise ValueError("unsupported LureCoverage evaluation schema")
    _timestamp(report["generated_at"], "report.generated_at")
    manifest = _exact(
        report["manifest"],
        "report.manifest",
        ("manifest_id", "manifest_version", "manifest_sha256"),
    )
    _identifier(manifest["manifest_id"], "report.manifest.manifest_id")
    _identifier(manifest["manifest_version"], "report.manifest.manifest_version")
    if _DIGEST.fullmatch(str(manifest["manifest_sha256"])) is None:
        raise ValueError("report.manifest.manifest_sha256 must be a SHA-256 digest")
    if _DIGEST.fullmatch(str(report["canaries_sha256"])) is None:
        raise ValueError("report.canaries_sha256 must be a SHA-256 digest")
    acceptance = _exact(
        report["acceptance"],
        "report.acceptance",
        (
            "minimum_route_coverage",
            "minimum_probe_delivery_rate",
            "maximum_duplicate_rate",
            "maximum_out_of_order_rate",
            "minimum_lineage_continuity",
            "maximum_delivery_delay_ms",
        ),
    )
    for key in acceptance:
        if key == "maximum_delivery_delay_ms":
            _integer(acceptance[key], f"report.acceptance.{key}", 1, 86_400_000)
        else:
            _rate(acceptance[key], f"report.acceptance.{key}")
    results = report["results"]
    if not isinstance(results, list) or not 1 <= len(results) <= MAX_PROBES:
        raise ValueError("report.results must be a non-empty bounded array")
    seen = set()
    delivered = duplicates = ordering = lineage = covered = 0
    route_status: dict[str, list[bool]] = {}
    route_metadata: dict[str, tuple[bool, int]] = {}
    required_routes = set()
    delays = []
    previous_observed: dict[str, int] = {}
    for index, raw_result in enumerate(results):
        field = f"report.results[{index}]"
        result = _exact(
            raw_result,
            field,
            (
                "probe_id",
                "route_id",
                "required",
                "emitted_sequence",
                "observed_sequence",
                "delivered",
                "copies",
                "out_of_order",
                "lineage_contiguous",
                "delivery_delay_ms",
                "allowed_delivery_delay_ms",
                "passed",
            ),
        )
        probe_id = _identifier(result["probe_id"], f"{field}.probe_id")
        if probe_id in seen:
            raise ValueError("report contains a duplicate probe_id")
        seen.add(probe_id)
        route_id = _identifier(result["route_id"], f"{field}.route_id")
        if result["emitted_sequence"] != index + 1:
            raise ValueError("report emitted_sequence must be contiguous and ordered")
        for key in ("required", "delivered", "out_of_order", "lineage_contiguous", "passed"):
            if not isinstance(result[key], bool):
                raise ValueError(f"{field}.{key} must be boolean")
        _integer(result["copies"], f"{field}.copies", 0, 1024)
        allowed_delay = _integer(
            result["allowed_delivery_delay_ms"],
            f"{field}.allowed_delivery_delay_ms",
            1,
            86_400_000,
        )
        if result["delivered"]:
            if (
                result["copies"] < 1
                or result["delivery_delay_ms"] is None
                or result["observed_sequence"] is None
            ):
                raise ValueError(f"{field} delivered probes require copies, sequence, and delay")
            observed_sequence = _integer(
                result["observed_sequence"],
                f"{field}.observed_sequence",
                1,
                MAX_PROBES * 32,
            )
            _integer(result["delivery_delay_ms"], f"{field}.delivery_delay_ms", 0, 86_400_000)
            delays.append(result["delivery_delay_ms"])
            prior = previous_observed.get(route_id)
            expected_out_of_order = prior is not None and observed_sequence <= prior
            previous_observed[route_id] = observed_sequence
            if result["out_of_order"] != expected_out_of_order:
                raise ValueError(f"{field}.out_of_order is inconsistent")
        elif (
            result["copies"] != 0
            or result["observed_sequence"] is not None
            or result["delivery_delay_ms"] is not None
            or result["out_of_order"]
            or result["lineage_contiguous"]
            or result["passed"]
        ):
            raise ValueError(f"{field} missing probe fields are inconsistent")
        expected_pass = bool(
            result["delivered"]
            and result["copies"] == 1
            and not result["out_of_order"]
            and result["lineage_contiguous"]
            and result["delivery_delay_ms"] is not None
            and result["delivery_delay_ms"] <= allowed_delay
        )
        if result["passed"] != expected_pass:
            raise ValueError(f"{field}.passed is inconsistent")
        delivered += result["delivered"]
        duplicates += result["copies"] > 1
        ordering += result["out_of_order"]
        lineage += result["delivered"] and result["lineage_contiguous"]
        route_status.setdefault(route_id, []).append(result["passed"])
        metadata = (result["required"], allowed_delay)
        if route_id in route_metadata and route_metadata[route_id] != metadata:
            raise ValueError("coverage route metadata changes between probes")
        route_metadata[route_id] = metadata
        if result["required"]:
            required_routes.add(route_id)
    covered = sum(all(route_status[route_id]) for route_id in required_routes)
    summary = _exact(
        report["summary"],
        "report.summary",
        (
            "total_routes",
            "required_routes",
            "covered_required_routes",
            "total_probes",
            "delivered_probes",
            "missing_probes",
            "duplicate_probes",
            "out_of_order_probes",
            "lineage_contiguous_probes",
            "route_coverage",
            "probe_delivery_rate",
            "duplicate_rate",
            "out_of_order_rate",
            "lineage_continuity",
            "maximum_delivery_delay_ms",
            "verdict",
        ),
    )
    expected = {
        "total_routes": len(route_status),
        "required_routes": len(required_routes),
        "covered_required_routes": covered,
        "total_probes": len(results),
        "delivered_probes": delivered,
        "missing_probes": len(results) - delivered,
        "duplicate_probes": duplicates,
        "out_of_order_probes": ordering,
        "lineage_contiguous_probes": lineage,
        "route_coverage": _ratio(covered, len(required_routes)),
        "probe_delivery_rate": _ratio(delivered, len(results)),
        "duplicate_rate": _ratio(duplicates, len(results)),
        "out_of_order_rate": _ratio(ordering, delivered),
        "lineage_continuity": _ratio(lineage, delivered),
        "maximum_delivery_delay_ms": max(delays) if delays else None,
    }
    if any(summary[key] != expected_value for key, expected_value in expected.items()):
        raise ValueError("coverage summary does not reconcile with probe results")
    expected_verdict = (
        "pass"
        if (
            expected["route_coverage"] >= acceptance["minimum_route_coverage"]
            and expected["probe_delivery_rate"] >= acceptance["minimum_probe_delivery_rate"]
            and expected["duplicate_rate"] <= acceptance["maximum_duplicate_rate"]
            and expected["out_of_order_rate"] <= acceptance["maximum_out_of_order_rate"]
            and expected["lineage_continuity"] >= acceptance["minimum_lineage_continuity"]
            and expected["maximum_delivery_delay_ms"] is not None
            and expected["maximum_delivery_delay_ms"] <= acceptance["maximum_delivery_delay_ms"]
        )
        else "fail"
    )
    if summary["verdict"] != expected_verdict:
        raise ValueError("coverage verdict does not reconcile with acceptance thresholds")
    if report["limitations"] != _LIMITATIONS:
        raise ValueError("report limitations are not the LureCoverage v1 boundary")
    return dict(report)


def write_coverage_artifact(path: Path, value: Mapping[str, Any]) -> None:
    _write_new(path, value)
