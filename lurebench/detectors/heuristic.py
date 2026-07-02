"""A dependency-free heuristic baseline for the ``fraud`` task.

This is intentionally simple: it exists so the harness runs end-to-end with no
model downloads or API keys, and so every trained/LLM detector added later has a
transparent floor to beat. It scores social-engineering surface features
(urgency, authority, credential/payment asks, links, contact hand-off) rather
than trying to model text provenance.
"""

from __future__ import annotations

import re
from typing import Optional

from ..schema import Lure
from .base import Detector

_URGENCY = re.compile(
    r"\b(urgent|immediately|right away|within \d+ (?:hours|minutes)|expire|suspend|"
    r"final notice|act now|as soon as possible|asap|deadline|last chance)\b",
    re.I,
)
_AUTHORITY = re.compile(
    r"\b(it (?:support|department|team)|help ?desk|security team|your bank|"
    r"account team|compliance|hr department|ceo|cfo|director|administrator)\b",
    re.I,
)
_CREDENTIAL = re.compile(
    r"\b(verify your (?:account|identity|password)|confirm your (?:details|password)|"
    r"reset your password|login|log in|sign in|update your (?:payment|billing|account))\b",
    re.I,
)
_PAYMENT = re.compile(
    r"\b(wire transfer|gift ?card|bitcoin|crypto|usdt|bank details|routing number|"
    r"invoice|payment|refund|prize|winnings|inheritance|beneficiary|investment)\b",
    re.I,
)
_HANDOFF = re.compile(r"(<<link>>|<<contact>>|https?://|wa\.me/|t\.me/|whatsapp|telegram)", re.I)
_SECRECY = re.compile(r"\b(do not tell|keep this (?:between us|confidential)|discreet|private matter)\b", re.I)

# Weights are hand-set; they sum to the logit passed through a sigmoid.
_SIGNALS = [
    (_URGENCY, 1.1),
    (_AUTHORITY, 0.8),
    (_CREDENTIAL, 1.3),
    (_PAYMENT, 1.1),
    (_HANDOFF, 0.9),
    (_SECRECY, 1.0),
]
_BIAS = -1.6


def _sigmoid(x: float) -> float:
    if x < 0:
        import math

        return math.exp(x) / (1.0 + math.exp(x))
    import math

    return 1.0 / (1.0 + math.exp(-x))


class HeuristicDetector(Detector):
    name = "heuristic-v0"
    task = "fraud"

    def score(self, lure: Lure) -> Optional[float]:
        text = lure.text
        logit = _BIAS
        for pattern, weight in _SIGNALS:
            if pattern.search(text):
                logit += weight
        return _sigmoid(logit)
