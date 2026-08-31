from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from lurebench.revocation import (
    CAEP_CREDENTIAL_CHANGE,
    CAEP_DEVICE_COMPLIANCE,
    CAEP_RISK_LEVEL,
    CAEP_SESSION_REVOKED,
    _expected_signal_digest,
)
from lurebench.revocation_adapters import project_verified_caep_event

ROOT = Path(__file__).parents[1]
ISSUER = "https://identity.example.invalid"
AUDIENCE = "https://receiver.example.invalid/caep"
KEY = b"a-campaign-specific-secret-key!!"
VERIFICATION = {
    "signature_verified": True,
    "issuer_verified": True,
    "audience_verified": True,
    "time_verified": True,
    "delivery_method": "push",
}


def _claims(event_type: str = CAEP_SESSION_REVOKED, payload: dict | None = None) -> dict:
    if payload is None:
        payload = {"event_timestamp": 2_000_000_010}
    return {
        "iss": ISSUER,
        "jti": "sensitive-jti-123",
        "iat": 2_000_000_011,
        "aud": AUDIENCE,
        "sub_id": {
            "format": "complex",
            "user": {"format": "email", "email": "person@example.gov"},
            "tenant": {"format": "opaque", "id": "agency-sensitive-tenant"},
        },
        "events": {event_type: payload},
    }


def _project(claims: dict, **changes):
    arguments = {
        "verification": VERIFICATION,
        "expected_issuer": ISSUER,
        "expected_audience": AUDIENCE,
        "subject_hmac_key": KEY,
        "sequence": 1,
        "epoch_seconds": 2_000_000_000,
    }
    arguments.update(changes)
    return project_verified_caep_event(claims, **arguments)


@pytest.mark.parametrize(
    ("event_type", "payload", "reason"),
    [
        (CAEP_SESSION_REVOKED, {"event_timestamp": 2_000_000_010}, "session_revoked"),
        (
            CAEP_CREDENTIAL_CHANGE,
            {"event_timestamp": 2_000_000_010, "change_type": "revoke"},
            "credential_revoked",
        ),
        (
            CAEP_DEVICE_COMPLIANCE,
            {"event_timestamp": 2_000_000_010, "current_status": "not-compliant"},
            "device_noncompliant",
        ),
        (
            CAEP_RISK_LEVEL,
            {
                "event_timestamp": 2_000_000_010,
                "current_level": "HIGH",
                "principal": "synthetic-principal",
            },
            "risk_increased",
        ),
    ],
)
def test_all_attenuating_caep_events_project_to_digest_bound_private_metadata(
    event_type, payload, reason
):
    projected = _project(_claims(event_type, payload))

    assert projected["event_type"] == event_type
    assert projected["attenuation_reason"] == reason
    assert projected["occurred_at_ms"] == 10_000
    assert projected["signal_sha256"] == _expected_signal_digest(projected)
    serialized = json.dumps(projected)
    for secret in (
        "person@example.gov",
        "agency-sensitive-tenant",
        "sensitive-jti-123",
        ISSUER,
        AUDIENCE,
    ):
        assert secret not in serialized


def test_projection_is_deterministic_within_a_campaign_but_key_separated():
    claims = _claims()
    first = _project(claims)
    second = _project(claims)
    other_campaign = _project(claims, subject_hmac_key=b"b" * 32)

    assert first == second
    assert first["event_id"] != other_campaign["event_id"]
    assert first["subject"]["id"] != other_campaign["subject"]["id"]


def test_projection_accepts_verified_audience_arrays_and_poll_delivery():
    claims = _claims()
    claims["aud"] = ["https://other.example.invalid", AUDIENCE]
    verification = dict(VERIFICATION, delivery_method="poll")
    assert _project(claims, verification=verification)["sequence"] == 1


@pytest.mark.parametrize(
    ("event_type", "payload"),
    [
        (
            CAEP_CREDENTIAL_CHANGE,
            {"event_timestamp": 2_000_000_010, "change_type": "create"},
        ),
        (
            CAEP_DEVICE_COMPLIANCE,
            {"event_timestamp": 2_000_000_010, "current_status": "compliant"},
        ),
        (
            CAEP_RISK_LEVEL,
            {
                "event_timestamp": 2_000_000_010,
                "current_level": "LOW",
                "principal": "synthetic-principal",
            },
        ),
    ],
)
def test_projection_rejects_non_attenuating_caep_state(event_type, payload):
    with pytest.raises(ValueError, match="attenuate access|not-compliant|become HIGH"):
        _project(_claims(event_type, payload))


def test_projection_requires_an_explicit_external_verification_boundary():
    for field in (
        "signature_verified",
        "issuer_verified",
        "audience_verified",
        "time_verified",
    ):
        verification = dict(VERIFICATION)
        verification[field] = False
        with pytest.raises(ValueError, match="externally verified"):
            _project(_claims(), verification=verification)

    with pytest.raises(ValueError, match="decoded SET claims"):
        project_verified_caep_event(  # type: ignore[arg-type]
            "header.payload.signature",
            verification=VERIFICATION,
            expected_issuer=ISSUER,
            expected_audience=AUDIENCE,
            subject_hmac_key=KEY,
            sequence=1,
            epoch_seconds=2_000_000_000,
        )


def test_projection_rejects_identity_time_key_and_event_ambiguities():
    with pytest.raises(ValueError, match="issuer does not match"):
        _project(_claims(), expected_issuer="https://wrong.example.invalid")
    with pytest.raises(ValueError, match="audience does not contain"):
        _project(_claims(), expected_audience="https://wrong.example.invalid")
    with pytest.raises(ValueError, match="32 to 1024"):
        _project(_claims(), subject_hmac_key=b"short")

    future_event = _claims()
    future_event["events"][CAEP_SESSION_REVOKED]["event_timestamp"] = 2_000_000_012
    with pytest.raises(ValueError, match="later than SET iat"):
        _project(future_event)

    multiple = _claims()
    multiple["events"][CAEP_CREDENTIAL_CHANGE] = {
        "event_timestamp": 2_000_000_010,
        "change_type": "delete",
    }
    with pytest.raises(ValueError, match="exactly one event"):
        _project(multiple)


def test_projection_bounds_structured_subjects():
    missing_format = _claims()
    del missing_format["sub_id"]["format"]
    with pytest.raises(ValueError, match="structured subject"):
        _project(missing_format)

    oversized = _claims()
    oversized["sub_id"]["user"]["email"] = "x" * 2049
    with pytest.raises(ValueError, match="bounded string"):
        _project(oversized)

    too_deep = _claims()
    nested: dict = {"value": "leaf"}
    for _ in range(9):
        nested = {"next": nested}
    too_deep["sub_id"]["nested"] = nested
    with pytest.raises(ValueError, match="nesting depth"):
        _project(too_deep)


def test_projection_example_runs_offline_and_emits_only_opaque_identifiers():
    completed = subprocess.run(
        [sys.executable, str(ROOT / "examples/runtime/project_verified_caep.py")],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    projected = json.loads(completed.stdout)
    assert projected["subject"]["format"] == "opaque"
    assert projected["event_id"].startswith("event-")
    assert "user-123" not in completed.stdout
