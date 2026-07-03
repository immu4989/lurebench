"""Controlled-generation interface and shared types.

LureBench generates synthetic AI fraud lures for the typologies where cleanly
licensed public data is scarce (BEC, romance / pig-butchering, and AI-authored
phishing). This is defensive research data: every record is defanged, labelled,
provenance-logged, and held in a review-pending state until a human approves it.
See docs/SHARD_SPEC.md → Controlled-generation protocol.

This module defines the ``Generator`` interface and the ``GenerationSpec`` that
parameterizes a batch. Concrete engines live alongside it (template, anthropic).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List

from ..schema import TYPOLOGIES

# The generatable fraud typologies (benign controls are sourced, not generated).
GENERATABLE = sorted(t for t in TYPOLOGIES if t != "benign")


@dataclass
class GenerationSpec:
    """Parameters for one generation batch.

    Attributes:
        typology: One of :data:`GENERATABLE`.
        channel: Delivery channel to imitate (``email``, ``sms``, ``chat``, ...).
        language: ISO 639-1 code.
        persuasion: Cialdini-style tags to stamp on the records.
        persona: Short, non-identifying scenario seed (e.g. "IT helpdesk password
            reset"). Must not name a real person or organisation.
        generator: Model/engine id recorded as provenance on every record.
    """

    typology: str
    channel: str = "email"
    language: str = "en"
    persuasion: List[str] = field(default_factory=list)
    persona: str = ""
    generator: str = "template-v0"

    def validate(self) -> None:
        if self.typology not in GENERATABLE:
            raise ValueError(
                f"typology must be one of {GENERATABLE} for generation, got {self.typology!r}"
            )

    def as_meta(self) -> dict:
        return {
            "typology": self.typology,
            "channel": self.channel,
            "language": self.language,
            "persona": self.persona,
            "persuasion": list(self.persuasion),
            "generator": self.generator,
        }


# Shared defensive prompt, reused by every model-backed engine. Constrains output
# to placeholders and forbids real people, organisations, or live infrastructure.
SYSTEM_PROMPT = (
    "You generate synthetic, clearly-fictional example messages used ONLY to train "
    "and evaluate automated fraud-detection models for a defensive security benchmark "
    "(LureBench). Hard rules for every message you write:\n"
    "- Use the placeholders <<link>> for any URL and <<contact>> for any phone/handle/email. "
    "Never write a real or realistic URL, address, phone number, or payment detail.\n"
    "- Never name a real person, company, bank, or government body. Use generic roles only.\n"
    "- Do not include operational instructions, malware, or anything beyond the message text.\n"
    "- Output ONLY the message text — no preamble, no explanation, no quotes."
)


def build_user_prompt(spec: "GenerationSpec") -> str:
    persona = spec.persona or "a generic, unremarkable scenario"
    persuasion = ", ".join(spec.persuasion) if spec.persuasion else "any plausible angle"
    return (
        f"Write one synthetic {spec.typology.replace('_', ' ')} lure delivered over "
        f"{spec.channel} in {spec.language}. Scenario seed: {persona}. "
        f"Persuasion emphasis: {persuasion}. Remember the placeholder and no-real-entity rules."
    )


class Generator(ABC):
    #: Engine id (implementation), distinct from the ``generator`` label on a spec.
    name: str = "generator"

    #: Optional-dependency extras required to construct this engine.
    requires: List[str] = []

    @abstractmethod
    def generate(self, spec: GenerationSpec, n: int) -> List[str]:
        """Return up to ``n`` raw lure texts for ``spec``.

        Implementations may return fewer than ``n`` (e.g. when a model declines a
        request); the pipeline handles the shortfall. Text is defanged downstream
        — implementations should already use placeholders, but must not rely on it.
        """
        raise NotImplementedError
