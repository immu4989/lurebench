"""Detector interface.

A detector maps a :class:`~lurebench.schema.Lure` to a probability in ``[0, 1]``
that the record is positive for the detector's task. Return ``None`` from
``score`` to abstain on a record (it is excluded from the metrics and counted as
skipped).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Optional

from ..schema import Lure


class Detector(ABC):
    #: Human-readable id used in reports and the leaderboard.
    name: str = "detector"

    #: Which benchmark task this detector answers: ``fraud`` or ``provenance``.
    task: str = "fraud"

    #: Optional-dependency extras required to construct this detector, if any.
    requires: List[str] = []

    @abstractmethod
    def score(self, lure: Lure) -> Optional[float]:
        """Return P(positive) in ``[0, 1]``, or ``None`` to abstain."""
        raise NotImplementedError

    def predict(self, lure: Lure, threshold: float = 0.5) -> int:
        score = self.score(lure)
        return 0 if score is None else int(score >= threshold)
