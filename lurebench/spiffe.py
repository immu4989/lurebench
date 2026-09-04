"""Bounded canonical SPIFFE ID parsing for metadata-only assurance contracts."""

from __future__ import annotations

import re
from typing import Any

MAX_SPIFFE_ID_BYTES = 2_048
MAX_TRUST_DOMAIN_BYTES = 255

_TRUST_DOMAIN = re.compile(r"^[a-z0-9._-]+$")
_PATH_SEGMENT = re.compile(r"^[A-Za-z0-9._-]+$")


def validate_spiffe_trust_domain(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a SPIFFE trust domain")
    try:
        size = len(value.encode("ascii"))
    except UnicodeEncodeError as exc:
        raise ValueError(f"{field} must contain ASCII characters only") from exc
    if not 1 <= size <= MAX_TRUST_DOMAIN_BYTES or _TRUST_DOMAIN.fullmatch(value) is None:
        raise ValueError(f"{field} must be a canonical SPIFFE trust domain")
    return value


def parse_spiffe_id(
    value: Any,
    field: str,
    *,
    require_path: bool = False,
) -> tuple[str, str]:
    """Return one canonical SPIFFE ID and trust domain without URI normalization.

    This validates the SPIFFE ID grammar but does not authenticate an SVID,
    Workload API response, issuing authority, or possession of a private key.
    """

    if not isinstance(value, str):
        raise ValueError(f"{field} must be a SPIFFE ID")
    try:
        size = len(value.encode("ascii"))
    except UnicodeEncodeError as exc:
        raise ValueError(f"{field} must contain ASCII characters only") from exc
    if not 1 <= size <= MAX_SPIFFE_ID_BYTES or not value.startswith("spiffe://"):
        raise ValueError(f"{field} must be a bounded canonical SPIFFE ID")
    remainder = value[len("spiffe://") :]
    authority, separator, path = remainder.partition("/")
    trust_domain = validate_spiffe_trust_domain(authority, f"{field} trust domain")
    if not separator:
        if require_path:
            raise ValueError(f"{field} workload identity requires a non-root path")
        return value, trust_domain
    segments = path.split("/")
    if any(
        not segment
        or segment in {".", ".."}
        or _PATH_SEGMENT.fullmatch(segment) is None
        for segment in segments
    ):
        raise ValueError(f"{field} contains a noncanonical SPIFFE path")
    return value, trust_domain
