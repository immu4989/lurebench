from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import jsonschema
import pytest
from referencing import Registry, Resource

from lurebench.cli import main
from lurebench.permit import _canonical
from lurebench.revocation import default_revocation_plan
from lurebench.revocation_campaign import (
    CAMPAIGN_LIMITATIONS,
    CAMPAIGN_SCHEMA,
    compose_revocation_plan,
)
from lurebench.revocation_topology import (
    audit_revocation_topology,
    validate_revocation_topology_audit,
)
from lurebench.runtime import default_runtime_profile

ROOT = Path(__file__).parents[1]


def _registry() -> Registry:
    resources = []
    for path in (ROOT / "spec").glob("*.schema.json"):
        value = json.loads(path.read_text(encoding="utf-8"))
        if "$id" in value:
            resources.append((value["$id"], Resource.from_contents(value)))
    return Registry().with_resources(resources)


def _complete_plan():
    profile = default_runtime_profile()
    reference = default_revocation_plan()
    nodes = [
        {
            "node_id": f"revocation-{point['point_id']}",
            "mediation_point_id": point["point_id"],
        }
        for point in profile["mediation_points"]
    ]
    nodes.append(
        {"node_id": "tool-gateway-replica", "mediation_point_id": "tool-gateway"}
    )
    campaign = {
        "schema": CAMPAIGN_SCHEMA,
        "schema_version": 1,
        "campaign_id": "complete-runtime-revocation",
        "created_at": reference["created_at"],
        "system_id": reference["system_id"],
        "stream": reference["stream"],
        "nodes": nodes,
        "events": [reference["events"][0]],
        "acceptance": reference["acceptance"],
        "probe_schedule": {
            "pre_event_offset_ms": 50,
            "propagation_probe_offset_ms": 100,
            "post_deadline_offset_ms": 50,
            "include_unrelated_subject": True,
        },
        "limitations": list(CAMPAIGN_LIMITATIONS),
    }
    return compose_revocation_plan(campaign), profile


def test_topology_audit_fails_when_reference_revocation_scope_omits_runtime_points():
    report = audit_revocation_topology(
        default_revocation_plan(),
        default_runtime_profile(),
        generated_at="2026-08-30T01:00:00Z",
    )
    assert report["summary"] == {
        "required_mediation_point_count": 9,
        "covered_mediation_point_count": 2,
        "missing_mediation_point_count": 7,
        "unmapped_node_count": 2,
        "mediation_point_coverage_rate": 2 / 9,
        "verdict": "fail",
    }
    assert "approval-gateway" in report["missing_mediation_point_ids"]
    assert {item["mediation_point_id"] for item in report["unmapped_nodes"]} == {
        "network-gateway",
        "storage-gateway",
    }


def test_complete_topology_passes_reports_replicas_and_validates_public_schema():
    plan, profile = _complete_plan()
    report = audit_revocation_topology(
        plan, profile, generated_at="2026-08-30T01:00:00Z"
    )
    assert report["summary"]["verdict"] == "pass"
    assert report["summary"]["mediation_point_coverage_rate"] == 1.0
    tool = next(
        item for item in report["results"] if item["mediation_point_id"] == "tool-gateway"
    )
    assert tool["replica_count"] == 2
    assert tool["covered"] is True
    assert validate_revocation_topology_audit(report) == report

    schema = json.loads(
        (ROOT / "spec/lurerevoke-topology-audit-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(
        schema,
        registry=_registry(),
        format_checker=jsonschema.FormatChecker(),
    ).validate(report)

    changed = json.loads(json.dumps(report))
    changed["summary"]["verdict"] = "fail"
    with pytest.raises(ValueError, match="independently recompute"):
        validate_revocation_topology_audit(changed)


def test_topology_audit_rejects_cross_system_comparisons():
    plan, profile = _complete_plan()
    changed = json.loads(json.dumps(profile))
    changed["permit"]["system_id"] = "different-agent-system"
    changed["permit_sha256"] = hashlib.sha256(_canonical(changed["permit"])).hexdigest()
    with pytest.raises(ValueError, match="different systems"):
        audit_revocation_topology(
            plan, changed, generated_at="2026-08-30T01:00:00Z"
        )


def test_topology_audit_cli_writes_a_valid_failing_report(tmp_path: Path):
    output = tmp_path / "topology-audit.json"
    assert main(["revocation-topology-audit", "--out", str(output)]) == 1
    report = json.loads(output.read_text(encoding="utf-8"))
    assert validate_revocation_topology_audit(report)["summary"]["verdict"] == "fail"
    if os.name == "posix":
        assert output.stat().st_mode & 0o777 == 0o600
    original = output.read_bytes()
    assert main(["revocation-topology-audit", "--out", str(output)]) == 2
    assert output.read_bytes() == original
