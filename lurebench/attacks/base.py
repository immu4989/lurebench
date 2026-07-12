"""Attack interface.

An attack transforms lure text the way an adversary would to evade a detector,
while keeping the message readable to a human victim. The robustness harness
applies an attack to lures a detector currently catches and measures how many
slip through afterward (the attack success rate).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Sequence


class Attack(ABC):
    #: Short id used in reports.
    name: str = "attack"

    #: Optional-dependency extras (e.g. an LLM provider) needed to run this attack.
    requires: List[str] = []

    @abstractmethod
    def apply(self, text: str) -> str:
        """Return an adversarially perturbed version of ``text``."""
        raise NotImplementedError

    def apply_many(self, texts: Sequence[str]) -> List[str]:
        return [self.apply(t) for t in texts]
