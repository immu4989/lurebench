"""Exact microsecond RFC 3339 profile for authority evidence.

The profile requires an uppercase T and Z (or a numeric minute offset), at
most six fractional digits, and a representable Gregorian UTC instant.
Leap seconds require upstream conversion; precision is never rounded here.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

TIMESTAMP_PATTERN = (
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]"
    r"(?:[.][0-9]{1,6})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$"
)
_PATTERN = re.compile(TIMESTAMP_PATTERN)


def parse_mandate_timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or _PATTERN.fullmatch(value) is None:
        raise ValueError(f"{field} must use the microsecond RFC 3339 timestamp profile")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, OverflowError) as exc:
        raise ValueError(f"{field} is not a representable Gregorian UTC instant") from exc


def validate_mandate_timestamp(value: Any, field: str) -> str:
    parse_mandate_timestamp(value, field)
    return value
