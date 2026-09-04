from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from lurebench.cli import main
from lurebench.identity import default_identity_plan, validate_identity_plan
from lurebench.identity_campaign import (
    CAMPAIGN_LIMITATIONS,
    CAMPAIGN_SCHEMA,
    compose_identity_plan,
    validate_identity_campaign,
)

ROOT = Path(__file__).parents[1]


def _campaign() -> dict:
    plan = default_identity_plan()
    return {
        "schema": CAMPAIGN_SCHEMA,
        "schema_version": 1,
        "campaign_id": "lureidentity-compiled-campaign",
        "created_at": plan["created_at"],
        "system_id": plan["system_id"],
        "directory": plan["directory"],
        "principals": plan["principals"],
        "authority_edges": plan["authority_edges"],
        "grants": plan["grants"],
        "nodes": plan["nodes"],
        "events": [
            {
                key: event[key]
                for key in (
                    "event_id",
                    "occurred_at_ms",
                    "event_type",
                    "target_principal_id",
                    "target_edge_id",
                    "source_event_sha256",
                )
            }
            for event in plan["events"]
        ],
        "acceptance": plan["acceptance"],
        "probe_schedule": {
            "pre_event_offset_ms": 50,
            "propagation_probe_offset_ms": 50,
            "post_deadline_offset_ms": 50,
        },
        "limitations": list(CAMPAIGN_LIMITATIONS),
    }


def _validate_schema(value: dict) -> None:
    resources = []
    for path in (ROOT / "spec").glob("*.schema.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        if "$id" in schema:
            resources.append((schema["$id"], Resource.from_contents(schema)))
    registry = Registry().with_resources(resources)
    schema = json.loads(
        (ROOT / "spec" / "lureidentity-campaign-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(
        schema, registry=registry, format_checker=FormatChecker()
    ).validate(value)


def test_campaign_derives_exact_cuts_exhaustive_controls_and_probe_matrix():
    campaign = _campaign()
    _validate_schema(campaign)
    assert validate_identity_campaign(campaign) == campaign

    plan = compose_identity_plan(campaign)
    assert validate_identity_plan(plan) == plan
    assert [event["sequence"] for event in plan["events"]] == [1, 2, 3, 4]
    assert [event["required_cut_actor_ids"] for event in plan["events"]] == [
        ["agent-alpha", "human-alice", "workload-alpha"],
        ["agent-alpha", "human-alice", "workload-alpha"],
        ["agent-alpha", "workload-alpha"],
        ["workload-alpha"],
    ]
    assert plan["events"][0]["required_preserve_actor_ids"] == [
        "agent-beta",
        "group-ops",
        "human-bob",
        "workload-beta",
    ]
    assert plan["events"][3]["required_preserve_actor_ids"] == [
        "agent-alpha",
        "agent-beta",
        "group-ops",
        "human-alice",
        "human-bob",
        "workload-beta",
    ]
    assert len(plan["probes"]) == 414
    assert compose_identity_plan(json.loads(json.dumps(campaign))) == plan
    phases = {
        probe["attempted_at_ms"]
        for probe in plan["probes"]
        if probe["event_id"] == "identity-1"
    }
    assert phases == {9_950, 10_050, 10_550}


def test_committed_example_is_schema_valid_and_compiles():
    campaign = json.loads(
        (ROOT / "examples" / "lureidentity-campaign-v1.json").read_text(
            encoding="utf-8"
        )
    )
    _validate_schema(campaign)
    plan = compose_identity_plan(campaign)
    assert len(plan["events"]) == 1
    assert len(plan["nodes"]) == 2
    assert len(plan["probes"]) == 26
    assert plan["events"][0]["required_cut_actor_ids"] == [
        "agent-alpha",
        "human-alice",
        "workload-alpha",
    ]


def test_public_campaign_conformance_vector_is_exact():
    vector = ROOT / "conformance" / "lureidentity-campaign-v1"
    campaign = json.loads((vector / "campaign.json").read_text(encoding="utf-8"))
    expected = json.loads((vector / "plan.json").read_text(encoding="utf-8"))
    assert compose_identity_plan(campaign) == expected


def test_campaign_rejects_partial_actor_cut_and_invalid_targets():
    campaign = _campaign()
    campaign["grants"].append(
        {
            "grant_id": "alice-independent-read",
            "principal_id": "human-alice",
            "resource_id": "independent-resource",
            "action": "read",
        }
    )
    with pytest.raises(ValueError, match="partially cuts"):
        compose_identity_plan(campaign)

    campaign = _campaign()
    campaign["events"][0]["target_principal_id"] = "agent-alpha"
    with pytest.raises(ValueError, match="target one human"):
        compose_identity_plan(campaign)

    campaign = _campaign()
    campaign["events"][1]["target_edge_id"] = "delegation-alpha"
    with pytest.raises(ValueError, match="incompatible authority edge"):
        compose_identity_plan(campaign)


def test_campaign_rejects_unbounded_or_ambiguous_schedules_before_output():
    campaign = _campaign()
    campaign["probe_schedule"]["propagation_probe_offset_ms"] = 500
    with pytest.raises(ValueError, match="shorter than"):
        compose_identity_plan(campaign)

    campaign = _campaign()
    campaign["events"][1]["occurred_at_ms"] = campaign["events"][0]["occurred_at_ms"]
    with pytest.raises(ValueError, match="increase strictly"):
        compose_identity_plan(campaign)

    campaign = _campaign()
    campaign["nodes"] = [
        {"node_id": f"node-{index}", "enforcement_point_id": f"point-{index}"}
        for index in range(1, 65)
    ]
    campaign["grants"] = [
        {
            "grant_id": f"grant-{index}",
            "principal_id": "group-ops",
            "resource_id": f"resource-{index}",
            "action": "read",
        }
        for index in range(1, 51)
    ]
    with pytest.raises(ValueError, match="bounded probe budget"):
        compose_identity_plan(campaign)


def test_identity_compose_cli_is_private_and_never_overwrites(tmp_path: Path, capsys):
    source = tmp_path / "campaign.json"
    source.write_text(json.dumps(_campaign()), encoding="utf-8")
    output = tmp_path / "plan.json"
    assert main(["identity-compose", "--campaign", str(source), "--out", str(output)]) == 0
    assert "LUREIDENTITY PLAN COMPOSED" in capsys.readouterr().out
    if os.name == "posix":
        assert output.stat().st_mode & 0o777 == 0o600
    original = output.read_bytes()
    assert main(["identity-compose", "--campaign", str(source), "--out", str(output)]) == 2
    assert output.read_bytes() == original


def test_campaign_rejects_unknown_fields_boolean_integers_and_bad_spiffe():
    campaign = _campaign()
    campaign["unknown"] = True
    with pytest.raises(ValueError, match="must contain exactly"):
        compose_identity_plan(campaign)

    campaign = _campaign()
    campaign["events"][0]["occurred_at_ms"] = True
    with pytest.raises(ValueError, match="campaign event occurrence"):
        compose_identity_plan(campaign)

    campaign = _campaign()
    workload = next(item for item in campaign["principals"] if item["kind"] == "workload")
    workload["spiffe_id"] = "spiffe://example.com/%2e%2e/admin"
    with pytest.raises(ValueError, match="SPIFFE"):
        compose_identity_plan(campaign)
