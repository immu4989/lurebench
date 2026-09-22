"""Strict detector probabilities without coercing abstention to a negative."""

from __future__ import annotations

import math
from numbers import Real
from typing import Optional


class DetectorAbstainedError(ValueError):
    """A hard prediction was requested but the detector returned no decision."""


def validate_score(value) -> Optional[float]:
    """Preserve None; reject invalid outputs without including them in errors."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, Real):
        raise ValueError("detector score must be a finite probability in [0, 1] or None")
    try:
        result = float(value)
    except (OverflowError, TypeError, ValueError) as exc:
        raise ValueError("detector score cannot be represented as a probability") from exc
    if not math.isfinite(result) or not 0 <= result <= 1:
        raise ValueError("detector score must be a finite probability in [0, 1] or None")
    return result


def validate_threshold(value) -> float:
    result = validate_score(value)
    if result is None:
        raise ValueError("decision threshold must be a finite probability in [0, 1]")
    return result
