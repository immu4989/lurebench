"""Cross-check LureRevoke nodes against the declared LurePermit runtime surface."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from . import __version__
from .permit import _canonical, _exact, _timestamp
from .revocation import _now, _sha256, _time, _write, validate_revocation_plan
from .runtime import validate_runtime_profile

TOPOLOGY_AUDIT_SCHEMA = (
    "https://github.com/immu4989/lurebench/spec/lurerevoke-topology-audit/v1"
)
TOPOLOGY_LIMITATIONS = [
    "audit_compares_declared_plan_nodes_to_declared_runtime_mediation_points_only",
    "a_pass_does_not_prove_discovery_completeness_reachability_or_signal_delivery",
    "replica_count_is_reported_but_no_fault_domain_independence_is_inferred",
    "audit_executes_no_discovery_probe_signal_access_action_or_enforcement",
]


def _audit_value(
    plan: Mapping[str, Any], profile: Mapping[str, Any], generated_at: str
) -> Dict[str, Any]:
    reviewed_plan = validate_revocation_plan(plan)
    reviewed_profile = validate_runtime_profile(profile)
    _timestamp(generated_at, "topology audit generated_at")
    if _time(generated_at) < max(
        _time(reviewed_plan["created_at"]), _time(reviewed_profile["created_at"])
    ):
        raise ValueError("topology audit cannot predate its plan or runtime profile")
    if reviewed_plan["system_id"] != reviewed_profile["permit"]["system_id"]:
        raise ValueError("revocation plan and runtime profile name different systems")

    mappings: dict[str, list[str]] = {}
    for node in reviewed_plan["nodes"]:
        mappings.setdefault(node["mediation_point_id"], []).append(node["node_id"])
    profile_points = {
        item["point_id"]: item for item in reviewed_profile["mediation_points"]
    }
    results = []
    for point_id in sorted(profile_points):
        point = profile_points[point_id]
        node_ids = sorted(mappings.get(point_id, []))
        results.append(
            {
                "mediation_point_id": point_id,
                "action_types": sorted(point["action_types"]),
                "required_sensor_ids": sorted(point["required_sensor_ids"]),
                "node_ids": node_ids,
                "replica_count": len(node_ids),
                "covered": bool(node_ids),
            }
        )
    unmapped = sorted(
        (
            {
                "node_id": node["node_id"],
                "mediation_point_id": node["mediation_point_id"],
            }
            for node in reviewed_plan["nodes"]
            if node["mediation_point_id"] not in profile_points
        ),
        key=lambda item: (item["mediation_point_id"], item["node_id"]),
    )
    missing = [item["mediation_point_id"] for item in results if not item["covered"]]
    covered_count = len(results) - len(missing)
    verdict = "pass" if not missing and not unmapped else "fail"
    return {
        "schema": TOPOLOGY_AUDIT_SCHEMA,
        "schema_version": 1,
        "generated_at": generated_at,
        "implementation": {"name": "lurebench", "version": __version__},
        "inputs": {
            "revocation_plan": reviewed_plan,
            "revocation_plan_sha256": _sha256(_canonical(reviewed_plan)),
            "runtime_profile": reviewed_profile,
            "runtime_profile_sha256": _sha256(_canonical(reviewed_profile)),
        },
        "results": results,
        "missing_mediation_point_ids": missing,
        "unmapped_nodes": unmapped,
        "summary": {
            "required_mediation_point_count": len(results),
            "covered_mediation_point_count": covered_count,
            "missing_mediation_point_count": len(missing),
            "unmapped_node_count": len(unmapped),
            "mediation_point_coverage_rate": covered_count / len(results),
            "verdict": verdict,
        },
        "limitations": list(TOPOLOGY_LIMITATIONS),
    }


def audit_revocation_topology(
    plan: Mapping[str, Any],
    profile: Mapping[str, Any],
    *,
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    return _audit_value(plan, profile, generated_at or _now())


def validate_revocation_topology_audit(value: Any) -> Dict[str, Any]:
    audit = _exact(
        value,
        "revocation topology audit",
        (
            "schema",
            "schema_version",
            "generated_at",
            "implementation",
            "inputs",
            "results",
            "missing_mediation_point_ids",
            "unmapped_nodes",
            "summary",
            "limitations",
        ),
    )
    if audit["schema"] != TOPOLOGY_AUDIT_SCHEMA or audit["schema_version"] != 1:
        raise ValueError("unsupported LureRevoke topology audit schema")
    inputs = audit.get("inputs")
    if not isinstance(inputs, dict):
        raise ValueError("topology audit inputs must be an object")
    expected = _audit_value(
        inputs.get("revocation_plan"),
        inputs.get("runtime_profile"),
        audit.get("generated_at"),
    )
    if audit != expected:
        raise ValueError("revocation topology audit does not independently recompute")
    return dict(audit)


def write_revocation_topology_audit(path: Path, value: Mapping[str, Any]) -> None:
    _write(Path(path), validate_revocation_topology_audit(value))
