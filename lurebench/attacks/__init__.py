"""Adversarial attack registry.

Character-level attacks are dependency-free and constructed by name. LLM attacks
need a provider ``complete`` callable, so they are built explicitly (see
``attacks.llm`` and the ``lurebench robustness`` CLI).
"""

from __future__ import annotations

from typing import Dict, Type

from .base import Attack
from .perturb import HomoglyphAttack, LeetAttack, WhitespaceAttack, ZeroWidthAttack

_DEP_FREE: Dict[str, Type[Attack]] = {
    a.name: a for a in (HomoglyphAttack, LeetAttack, ZeroWidthAttack, WhitespaceAttack)
}
_LLM = ("llm-paraphrase", "llm-keyword-evasion")


def available() -> list[str]:
    return sorted(_DEP_FREE) + list(_LLM)


def get_attack(name: str, **kwargs) -> Attack:
    """Construct a dependency-free attack by name. LLM attacks are built directly."""
    if name in _DEP_FREE:
        return _DEP_FREE[name](**kwargs)
    if name in _LLM:
        raise KeyError(
            f"{name!r} is an LLM attack; build it with attacks.llm and a provider "
            "complete_fn, or use `lurebench robustness --engine <provider>`."
        )
    raise KeyError(f"unknown attack {name!r}; available: {available()}")


__all__ = ["Attack", "available", "get_attack"]
