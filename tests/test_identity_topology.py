from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import jsonschema
import pytest
from referencing import Registry, Resource

from lurebench.cli import main
from lurebench.identity import default_identity_plan
from lurebench.identity_topology import (
    audit_identity_topology,
    validate_identity_topology_audit,
)
from lurebench.permit import _canonical
from lurebench.runtime import default_runtime_profile

ROOT = Path(__file__).parents[1]


def _registry() -> Registry:
    resources = []
    for path in (ROOT / "spec").glob("*.schema.json"):
        value = json.loads(path.read_text(encoding="utf-8"))
        if "$id" in value:
            resources.append((value["$id"], Resource.from_contents(value)))
    return Registry().with_resources(resources)


def test_reference_identity_topology_covers_runtime_and_workload_trust_domains():
    report = audit_identity_topology(
        default_identity_plan(),
        default_runtime_profile(),
        generated_at="2026-09-03T01:00:00Z",
    )
    assert report["summary"] == {
        "required_enforcement_point_count": 9,
        "covered_enforcement_point_count": 9,
        "missing_enforcement_point_count": 0,
        "unmapped_node_count": 0,
        "enforcement_point_coverage_rate": 1.0,
        "workload_identity_count": 2,
        "trusted_workload_identity_count": 2,
        "untrusted_workload_identity_count": 0,
        "workload_trust_domain_coverage_rate": 1.0,
        "verdict": "pass",
    }
    assert all(item["replica_count"] == 1 for item in report["results"])
    assert {item["trust_domain"] for item in report["workload_identities"]} == {
        "example.com"
    }
    assert validate_identity_topology_audit(report) == report

    schema = json.loads(
        (ROOT / "spec/lureidentity-topology-audit-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(
        schema,
        registry=_registry(),
        format_checker=jsonschema.FormatChecker(),
    ).validate(report)


def test_topology_fails_closed_for_missing_unmapped_and_untrusted_scope():
    plan = default_identity_plan()
    plan["nodes"][0]["enforcement_point_id"] = "undeclared-gateway"
    plan["principals"][3]["spiffe_id"] = "spiffe://example.invalid/agents/alpha"
    report = audit_identity_topology(
        plan,
        default_runtime_profile(),
        generated_at="2026-09-03T01:00:00Z",
    )
    assert report["summary"]["verdict"] == "fail"
    assert report["missing_enforcement_point_ids"] == ["approval-gateway"]
    assert report["unmapped_nodes"] == [
        {
            "node_id": "identity-approval-gateway",
            "enforcement_point_id": "undeclared-gateway",
        }
    ]
    assert report["untrusted_workload_principal_ids"] == ["workload-alpha"]
    assert report["summary"]["enforcement_point_coverage_rate"] == 8 / 9
    assert report["summary"]["workload_trust_domain_coverage_rate"] == 0.5


def test_topology_rejects_cross_system_and_tampered_results():
    plan = default_identity_plan()
    profile = default_runtime_profile()
    profile["permit"]["system_id"] = "different-agent-system"
    profile["permit_sha256"] = hashlib.sha256(_canonical(profile["permit"])).hexdigest()
    with pytest.raises(ValueError, match="different systems"):
        audit_identity_topology(
            plan, profile, generated_at="2026-09-03T01:00:00Z"
        )

    report = audit_identity_topology(
        plan,
        default_runtime_profile(),
        generated_at="2026-09-03T01:00:00Z",
    )
    changed = json.loads(json.dumps(report))
    changed["summary"]["verdict"] = "fail"
    with pytest.raises(ValueError, match="independently recompute"):
        validate_identity_topology_audit(changed)


def test_identity_topology_cli_writes_private_no_overwrite_artifact(tmp_path: Path):
    output = tmp_path / "identity-topology.json"
    assert main(["identity-topology-audit", "--out", str(output)]) == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert validate_identity_topology_audit(report)["summary"]["verdict"] == "pass"
    if os.name == "posix":
        assert output.stat().st_mode & 0o777 == 0o600
    original = output.read_bytes()
    assert main(["identity-topology-audit", "--out", str(output)]) == 2
    assert output.read_bytes() == original
