"""Privacy-preserving adapters for already-verified OpenID CAEP metadata.

This module does not decode or verify JWTs and deliberately rejects compact
token strings.  A deployment must authenticate the Security Event Token (SET)
before calling :func:`project_verified_caep_event`.  The adapter then checks the
declared verification boundary, validates the attenuation semantics used by
LureRevoke, and replaces the SET ID and subject with keyed commitments.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Dict, Mapping

from .permit import _integer
from .revocation import (
    CAEP_CREDENTIAL_CHANGE,
    CAEP_DEVICE_COMPLIANCE,
    CAEP_RISK_LEVEL,
    CAEP_SESSION_REVOKED,
    EVENT_REASON,
    _expected_signal_digest,
)

MAX_CLAIM_TEXT = 2048
MAX_SUBJECT_BYTES = 16 * 1024
MAX_SUBJECT_DEPTH = 8
MAX_SUBJECT_MEMBERS = 64


def _bounded_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > MAX_CLAIM_TEXT:
        raise ValueError(f"{field} must be a non-empty bounded string")
    return value


def _verified_boundary(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "signature_verified",
        "issuer_verified",
        "audience_verified",
        "time_verified",
        "delivery_method",
    }:
        raise ValueError("verification must contain the exact external verification boundary")
    if any(
        value[field] is not True
        for field in (
            "signature_verified",
            "issuer_verified",
            "audience_verified",
            "time_verified",
        )
    ):
        raise ValueError("signature, issuer, audience, and time must be externally verified")
    if value["delivery_method"] not in {"poll", "push"}:
        raise ValueError("verification delivery_method must be push or poll")
    return dict(value)


def _bounded_subject(value: Any, *, depth: int = 0, members: list[int] | None = None) -> Any:
    if members is None:
        members = [0]
    if depth > MAX_SUBJECT_DEPTH:
        raise ValueError("SET subject exceeds the maximum nesting depth")
    members[0] += 1
    if members[0] > MAX_SUBJECT_MEMBERS:
        raise ValueError("SET subject contains too many members")
    if isinstance(value, str):
        return _bounded_text(value, "SET subject value")
    if isinstance(value, list):
        if not value:
            raise ValueError("SET subject arrays cannot be empty")
        return [_bounded_subject(item, depth=depth + 1, members=members) for item in value]
    if isinstance(value, dict):
        if not value:
            raise ValueError("SET subject objects cannot be empty")
        result = {}
        for key, item in value.items():
            checked_key = _bounded_text(key, "SET subject member")
            result[checked_key] = _bounded_subject(item, depth=depth + 1, members=members)
        return result
    raise ValueError("SET subject values must contain strings, arrays, or objects only")


def _commit(key: bytes, domain: bytes, value: bytes) -> str:
    return hmac.new(key, domain + b"\x00" + value, hashlib.sha256).hexdigest()


def _audience_matches(value: Any, expected: str) -> bool:
    if isinstance(value, str):
        return hmac.compare_digest(value, expected)
    if isinstance(value, list) and value and all(isinstance(item, str) for item in value):
        return any(hmac.compare_digest(item, expected) for item in value)
    return False


def _attenuation_reason(event_type: str, payload: Mapping[str, Any]) -> str:
    if event_type == CAEP_SESSION_REVOKED:
        return EVENT_REASON[event_type]
    if event_type == CAEP_CREDENTIAL_CHANGE:
        if payload.get("change_type") not in {"delete", "revoke"}:
            raise ValueError("credential-change must revoke or delete to attenuate access")
        return EVENT_REASON[event_type]
    if event_type == CAEP_DEVICE_COMPLIANCE:
        if payload.get("current_status") != "not-compliant":
            raise ValueError("device-compliance-change must become not-compliant")
        return EVENT_REASON[event_type]
    if event_type == CAEP_RISK_LEVEL:
        if payload.get("current_level") != "HIGH":
            raise ValueError("risk-level-change must become HIGH to attenuate access")
        _bounded_text(payload.get("principal"), "risk-level-change.principal")
        return EVENT_REASON[event_type]
    raise ValueError("CAEP event type is not supported by LureRevoke")


def project_verified_caep_event(
    verified_claims: Mapping[str, Any],
    *,
    verification: Mapping[str, Any],
    expected_issuer: str,
    expected_audience: str,
    subject_hmac_key: bytes,
    sequence: int,
    epoch_seconds: int,
) -> Dict[str, Any]:
    """Project one externally verified attenuating CAEP event into LureRevoke.

    ``verified_claims`` must be decoded claims, never a compact JWT. The caller
    remains responsible for cryptographic and protocol verification. A fresh
    campaign-specific HMAC key prevents raw subject identifiers from entering
    benchmark artifacts; reusing a key makes commitments correlatable.
    """

    if not isinstance(verified_claims, Mapping):
        raise ValueError("verified_claims must be decoded SET claims, not token bytes")
    _verified_boundary(verification)
    issuer = _bounded_text(verified_claims.get("iss"), "SET issuer")
    expected_issuer = _bounded_text(expected_issuer, "expected issuer")
    if not hmac.compare_digest(issuer, expected_issuer):
        raise ValueError("SET issuer does not match the externally trusted issuer")
    expected_audience = _bounded_text(expected_audience, "expected audience")
    if not _audience_matches(verified_claims.get("aud"), expected_audience):
        raise ValueError("SET audience does not contain the expected receiver")
    event_jti = _bounded_text(verified_claims.get("jti"), "SET jti")
    issued_at = _integer(verified_claims.get("iat"), "SET iat", 0, 4_102_444_800)
    if not isinstance(subject_hmac_key, bytes) or not 32 <= len(subject_hmac_key) <= 1024:
        raise ValueError("subject_hmac_key must contain 32 to 1024 bytes")
    sequence = _integer(sequence, "sequence", 1, 1_000_000)
    epoch_seconds = _integer(epoch_seconds, "epoch_seconds", 0, 4_102_444_800)

    subject = _bounded_subject(verified_claims.get("sub_id"))
    if not isinstance(subject, dict) or "format" not in subject:
        raise ValueError("SET sub_id must be a structured subject identifier")
    _bounded_text(subject["format"], "SET sub_id.format")
    subject_bytes = json.dumps(
        subject, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    if len(subject_bytes) > MAX_SUBJECT_BYTES:
        raise ValueError("SET subject exceeds the 16 KiB projection limit")

    events = verified_claims.get("events")
    if not isinstance(events, dict) or len(events) != 1:
        raise ValueError("SET must contain exactly one event for LureRevoke projection")
    event_type, payload = next(iter(events.items()))
    if event_type not in EVENT_REASON or not isinstance(payload, dict):
        raise ValueError("SET contains an unsupported CAEP event")
    reason = _attenuation_reason(event_type, payload)
    event_timestamp = _integer(
        payload.get("event_timestamp"), "CAEP event_timestamp", 0, 4_102_444_800
    )
    if event_timestamp > issued_at:
        raise ValueError("CAEP event_timestamp cannot be later than SET iat")
    relative_ms = (event_timestamp - epoch_seconds) * 1000
    if not 1 <= relative_ms <= 86_400_000:
        raise ValueError("CAEP event_timestamp falls outside the campaign relative epoch")

    subject_digest = _commit(subject_hmac_key, b"lurerevoke-subject-v1", subject_bytes)
    event_material = f"{issuer}\x00{event_jti}\x00{event_type}".encode("utf-8")
    event_digest = _commit(subject_hmac_key, b"lurerevoke-event-v1", event_material)
    projected: Dict[str, Any] = {
        "event_id": f"event-{event_digest}",
        "sequence": sequence,
        "occurred_at_ms": relative_ms,
        "event_type": event_type,
        "subject": {"format": "opaque", "id": f"subject-{subject_digest}"},
        "attenuation_reason": reason,
    }
    projected["signal_sha256"] = _expected_signal_digest(projected)
    return projected
