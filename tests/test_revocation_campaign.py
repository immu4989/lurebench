from __future__ import annotations

import json
import os
from pathlib import Path

import jsonschema
import pytest

from lurebench.cli import main
from lurebench.revocation import (
    CAEP_SESSION_REVOKED,
    evaluate_revocation_run,
    reference_revocation_run,
    validate_revocation_plan,
)
from lurebench.revocation_adapters import project_verified_caep_event
from lurebench.revocation_campaign import (
    CAMPAIGN_LIMITATIONS,
    CAMPAIGN_SCHEMA,
    compose_revocation_plan,
    validate_revocation_campaign,
)

ROOT = Path(__file__).parents[1]


def _event(*, sequence: int = 1, event_timestamp: int = 2_000_000_010) -> dict:
    return project_verified_caep_event(
        {
            "iss": "https://identity.example.invalid",
            "jti": f"event-{sequence}",
            "iat": event_timestamp + 1,
            "aud": "https://receiver.example.invalid/caep",
            "sub_id": {
                "format": "iss_sub",
                "iss": "synthetic-issuer",
                "sub": f"synthetic-subject-{sequence}",
            },
            "events": {CAEP_SESSION_REVOKED: {"event_timestamp": event_timestamp}},
        },
        verification={
            "signature_verified": True,
            "issuer_verified": True,
            "audience_verified": True,
            "time_verified": True,
            "delivery_method": "push",
        },
        expected_issuer="https://identity.example.invalid",
        expected_audience="https://receiver.example.invalid/caep",
        subject_hmac_key=b"campaign-specific-projection-key!",
        sequence=sequence,
        epoch_seconds=2_000_000_000,
    )


def _campaign() -> dict:
    return {
        "schema": CAMPAIGN_SCHEMA,
        "schema_version": 1,
        "campaign_id": "agency-caep-campaign-1",
        "created_at": "2033-05-18T03:33:20Z",
        "system_id": "agency-agent-platform",
        "stream": {
            "transmitter_id": "agency-identity-provider",
            "receiver_audience_id": "agent-control-plane",
            "stream_id": "continuous-access-events",
            "profile": "openid-caep-1.0-final-metadata-projection",
            "authentication_boundary": "externally_verified_set_metadata",
        },
        "nodes": [
            {"node_id": "tool-policy", "mediation_point_id": "tool-gateway"},
            {"node_id": "credential-policy", "mediation_point_id": "credential-broker"},
        ],
        "events": [_event()],
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
        "probe_schedule": {
            "pre_event_offset_ms": 50,
            "propagation_probe_offset_ms": 100,
            "post_deadline_offset_ms": 50,
            "include_unrelated_subject": True,
        },
        "limitations": list(CAMPAIGN_LIMITATIONS),
    }


def test_projected_campaign_composes_deterministic_full_topology_probes():
    campaign = _campaign()
    assert validate_revocation_campaign(campaign) == campaign
    plan = compose_revocation_plan(campaign)
    assert validate_revocation_plan(plan) == plan
    assert len(plan["probes"]) == 8
    assert {item["node_id"] for item in plan["probes"]} == {
        "tool-policy",
        "credential-policy",
    }
    after = [item for item in plan["probes"] if item["probe_id"].endswith("-after")]
    assert {item["attempted_at_ms"] for item in after} == {10_550}
    unrelated = [item for item in plan["probes"] if item["probe_id"].endswith("-unrelated")]
    assert {item["node_id"] for item in unrelated} == {
        "tool-policy",
        "credential-policy",
    }
    assert len({item["subject_id"] for item in unrelated}) == 1
    propagation = [item for item in plan["probes"] if item["probe_id"].endswith("-propagation")]
    assert {item["node_id"] for item in propagation} == {
        "tool-policy",
        "credential-policy",
    }

    schema = json.loads(
        (ROOT / "spec/lurerevoke-campaign-v1.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(
        campaign
    )


def test_campaign_cli_writes_private_plan_without_overwrite(tmp_path: Path):
    campaign_path, plan_path = tmp_path / "campaign.json", tmp_path / "plan.json"
    campaign_path.write_text(json.dumps(_campaign()), encoding="utf-8")
    assert (
        main(
            [
                "revocation-compose",
                "--campaign",
                str(campaign_path),
                "--out",
                str(plan_path),
            ]
        )
        == 0
    )
    validate_revocation_plan(json.loads(plan_path.read_text(encoding="utf-8")))
    if os.name == "posix":
        assert plan_path.stat().st_mode & 0o777 == 0o600
    original = plan_path.read_bytes()
    assert (
        main(["revocation-compose", "--campaign", str(campaign_path), "--out", str(plan_path)]) == 2
    )
    assert plan_path.read_bytes() == original


def test_campaign_detects_collateral_denial_at_a_nonfirst_node():
    plan = compose_revocation_plan(_campaign())
    run = reference_revocation_run(
        plan,
        generated_at="2033-05-18T03:34:00Z",
    )
    affected = next(
        item
        for item in run["access_observations"]
        if item["probe_id"] == "event-1-node-2-unrelated"
    )
    affected["decision"] = "block"
    evaluation = evaluate_revocation_run(
        plan,
        run,
        generated_at="2033-05-18T03:35:00Z",
    )
    assert evaluation["summary"]["collateral_block_count"] == 1
    assert evaluation["summary"]["verdict"] == "fail"
    result = next(
        item
        for item in evaluation["probe_results"]
        if item["probe_id"] == "event-1-node-2-unrelated"
    )
    assert result["classification"] == "collateral_denial"


def test_campaign_rejects_privacy_integrity_timing_and_availability_regressions():
    changed = _campaign()
    changed["events"][0]["signal_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="signal digest"):
        compose_revocation_plan(changed)

    changed = _campaign()
    changed["events"].append(_event(sequence=2, event_timestamp=2_000_000_020))
    changed["events"][1]["subject"] = dict(changed["events"][0]["subject"])
    changed["events"][1]["signal_sha256"] = changed["events"][0]["signal_sha256"]
    with pytest.raises(ValueError, match="distinct opaque subjects"):
        compose_revocation_plan(changed)

    changed = _campaign()
    changed["probe_schedule"]["propagation_probe_offset_ms"] = 500
    with pytest.raises(ValueError, match="shorter than"):
        compose_revocation_plan(changed)

    changed = _campaign()
    changed["probe_schedule"]["include_unrelated_subject"] = False
    with pytest.raises(ValueError, match="must include unrelated"):
        compose_revocation_plan(changed)

    changed = _campaign()
    changed["events"][0]["subject"]["id"] = "unrelated-1"
    with pytest.raises(ValueError, match="reserved availability control"):
        compose_revocation_plan(changed)
