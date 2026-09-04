"""Strict production-boundary adapters for LureIdentity.

The adapter accepts only metadata that a caller states it already authenticated,
authorized, and schema-validated.  It does not parse HTTP, authenticate SCIM,
verify a source digest, or retain a SCIM payload.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Sequence

from .identity import _digest, _expected_event_digest, _ids
from .permit import _exact, _identifier, _integer

SCIM_CHANGE_SCHEMA = "https://github.com/immu4989/lurebench/spec/lureidentity-scim-change-v1"
SCIM_PROFILE = "ietf-scim-rfc7643-verified-lifecycle-change-v1"


def project_verified_scim_change(
    value: Any,
    *,
    directory: Mapping[str, Any],
    authority_edges: Sequence[Mapping[str, Any]],
    event_id: str,
    sequence: int,
    occurred_at_ms: int,
    required_cut_actor_ids: Sequence[str],
    required_preserve_actor_ids: Sequence[str],
) -> Dict[str, Any]:
    """Project externally verified RFC 7643 lifecycle metadata into one event.

    The caller remains responsible for SCIM protocol processing, authentication,
    authorization, source-byte retention, and establishing the supplied digest.
    """

    change = _exact(
        value,
        "verified SCIM change",
        (
            "schema",
            "schema_version",
            "profile",
            "issuer_id",
            "tenant_id",
            "verification",
            "source_event_sha256",
            "change",
        ),
    )
    if change["schema"] != SCIM_CHANGE_SCHEMA or change["schema_version"] != 1:
        raise ValueError("unsupported verified SCIM change schema")
    if change["profile"] != SCIM_PROFILE:
        raise ValueError("unsupported verified SCIM lifecycle profile")
    reviewed_directory = _exact(
        directory,
        "directory",
        ("issuer_id", "tenant_id", "profile", "authentication_boundary"),
    )
    directory_issuer = _identifier(reviewed_directory["issuer_id"], "directory issuer")
    directory_tenant = _identifier(reviewed_directory["tenant_id"], "directory tenant")
    if (
        reviewed_directory["profile"] != "ietf-scim-rfc7643-lifecycle-metadata-projection"
        or reviewed_directory["authentication_boundary"]
        != "externally_authenticated_and_authorized"
    ):
        raise ValueError("directory does not declare the LureIdentity SCIM trust boundary")
    if (
        _identifier(change["issuer_id"], "SCIM issuer") != directory_issuer
        or _identifier(change["tenant_id"], "SCIM tenant") != directory_tenant
    ):
        raise ValueError("SCIM issuer or tenant does not match the identity plan")
    verification = _exact(
        change["verification"],
        "verified SCIM change.verification",
        (
            "transport_authenticated",
            "issuer_authorized",
            "operation_authorized",
            "schema_validated",
        ),
    )
    if set(verification.values()) != {True} or any(
        not isinstance(item, bool) for item in verification.values()
    ):
        raise ValueError("SCIM change requires every external verification assertion")
    source_digest = _digest(change["source_event_sha256"], "SCIM source event digest")
    operation = _exact(
        change["change"],
        "verified SCIM change.change",
        ("resource_type", "resource_id", "attribute", "operation", "value"),
    )
    resource_id = _identifier(operation["resource_id"], "SCIM resource id")
    target_principal_id = None
    target_edge_id = None
    if (
        operation["resource_type"] == "User"
        and operation["attribute"] == "active"
        and operation["operation"] == "replace"
        and operation["value"] is False
    ):
        event_type = "scim_user_deactivated"
        target_principal_id = resource_id
    elif (
        operation["resource_type"] == "Group"
        and operation["attribute"] == "members"
        and operation["operation"] == "remove"
        and isinstance(operation["value"], str)
    ):
        member_id = _identifier(operation["value"], "SCIM group member id")
        matches = []
        for index, candidate in enumerate(authority_edges):
            edge = _exact(
                candidate,
                f"authority_edges[{index}]",
                ("edge_id", "source_id", "target_id", "relationship"),
            )
            if (
                edge["source_id"] == resource_id
                and edge["target_id"] == member_id
                and edge["relationship"] == "member_of"
            ):
                matches.append(_identifier(edge["edge_id"], "SCIM membership edge id"))
        if len(matches) != 1:
            raise ValueError("SCIM group removal must resolve to exactly one membership edge")
        event_type = "scim_group_membership_removed"
        target_edge_id = matches[0]
    else:
        raise ValueError("SCIM change is not a supported deactivation or membership removal")

    event: Dict[str, Any] = {
        "event_id": _identifier(event_id, "event id"),
        "sequence": _integer(sequence, "event sequence", 1, 1_000_000),
        "occurred_at_ms": _integer(occurred_at_ms, "event occurrence", 1, 86_400_000),
        "event_type": event_type,
        "target_principal_id": target_principal_id,
        "target_edge_id": target_edge_id,
        "required_cut_actor_ids": _ids(
            list(required_cut_actor_ids), "required cut actors", 128
        ),
        "required_preserve_actor_ids": _ids(
            list(required_preserve_actor_ids), "required preserve actors", 128
        ),
        "source_event_sha256": source_digest,
    }
    event["event_sha256"] = _expected_event_digest(event)
    return event
