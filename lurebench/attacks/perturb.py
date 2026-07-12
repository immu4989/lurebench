"""Dependency-free, deterministic character-level evasion attacks.

These are the attacks a fraudster runs for free with no model at all: swap a few
letters for lookalikes, sprinkle invisible characters, break up trigger words.
They leave the message readable to a human but shatter the exact-token matching
that keyword and bag-of-words detectors rely on. Deterministic (no randomness) so
results are reproducible.
"""

from __future__ import annotations

from .base import Attack

# Latin -> confusable Cyrillic/Greek homoglyphs (render near-identical).
_HOMOGLYPHS = {
    "a": "а", "c": "с", "e": "е", "o": "о", "p": "р",
    "x": "х", "y": "у", "i": "і", "s": "ѕ", "j": "ј",
    "A": "А", "B": "В", "C": "С", "E": "Е", "H": "Н",
    "K": "К", "M": "М", "O": "О", "P": "Р", "T": "Т", "X": "Х",
}
_LEET = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7", "l": "1", "b": "8"}
_ZERO_WIDTH = "​"


def _apply_rate(text: str, mapping: dict, rate: float) -> str:
    """Substitute eligible chars via ``mapping`` at ~``rate`` (every 1/rate-th, deterministically)."""
    step = max(1, round(1.0 / rate)) if rate > 0 else 0
    if step == 0:
        return text
    out = []
    seen = 0
    for ch in text:
        repl = mapping.get(ch)
        if repl is not None:
            seen += 1
            out.append(repl if seen % step == 0 else ch)
        else:
            out.append(ch)
    return "".join(out)


class HomoglyphAttack(Attack):
    name = "homoglyph"

    def __init__(self, rate: float = 0.5) -> None:
        self.rate = rate

    def apply(self, text: str) -> str:
        return _apply_rate(text, _HOMOGLYPHS, self.rate)


class LeetAttack(Attack):
    name = "leet"

    def __init__(self, rate: float = 0.5) -> None:
        self.rate = rate

    def apply(self, text: str) -> str:
        return _apply_rate(text, _LEET, self.rate)


class ZeroWidthAttack(Attack):
    name = "zero-width"

    def __init__(self, rate: float = 0.34) -> None:
        self.rate = rate

    def apply(self, text: str) -> str:
        step = max(1, round(1.0 / self.rate)) if self.rate > 0 else 0
        if step == 0:
            return text
        out = []
        seen = 0
        for ch in text:
            out.append(ch)
            if ch.isalnum():
                seen += 1
                if seen % step == 0:
                    out.append(_ZERO_WIDTH)
        return "".join(out)


class WhitespaceAttack(Attack):
    """Insert a space inside longer words, e.g. 'verify' -> 've rify'. Breaks token
    matching while staying legible."""

    name = "whitespace"

    def __init__(self, min_len: int = 5) -> None:
        self.min_len = min_len

    def apply(self, text: str) -> str:
        out = []
        for token in text.split(" "):
            if token.isalpha() and len(token) >= self.min_len:
                mid = len(token) // 2
                out.append(token[:mid] + " " + token[mid:])
            else:
                out.append(token)
        return " ".join(out)
