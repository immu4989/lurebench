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
    # Hard mode: subtler, more varied lures that don't lean on stock spam markers —
    # closer to how real fraud actually reads. Rotates through per-typology angles.
    hard: bool = False
    # Rewrite mode: when set, produce an AI rewrite of this human seed lure —
    # same scenario, typology, and approximate length — for a distribution-matched
    # provenance task (human original vs AI rewrite).
    seed_text: str = ""

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
            "hard": self.hard,
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


# Hard-mode system prompt: reflect how real-world fraud actually reads (often calm,
# brief, and plausible) rather than obvious spam. Same defensive guardrails as v1.
SYSTEM_PROMPT_HARD = (
    "You generate synthetic, clearly-fictional example messages used ONLY to train "
    "and evaluate automated fraud-detection models for a defensive security benchmark "
    "(LureBench). Write REALISTIC, VARIED examples that reflect how real fraud actually "
    "reads — frequently calm, brief, and mundane rather than obviously alarming.\n"
    "- Do NOT rely on stock phishing/spam markers. Avoid opening with 'Urgent:', avoid "
    "stacking urgency + authority + payment-demand language, avoid ALL-CAPS alarms and "
    "'verify your account immediately' clichés. Persuasion should come from context and "
    "plausibility, not alarm words.\n"
    "- Vary tone, length, and structure across messages: some short and casual, some "
    "formal, some conversational. Not every message needs a subject line.\n"
    "- Hard rules (unchanged): use <<link>> for any URL and <<contact>> for any "
    "phone/handle/email; never a real or realistic URL, address, phone, or payment "
    "detail; never name a real person, company, bank, or government body — generic roles "
    "only; no operational instructions or malware.\n"
    "- Output ONLY the message text — no preamble, no explanation, no quotes."
)

# Per-typology angle pools for hard mode. Rotating by call index gives intra-cell
# variety so 50 lures aren't near-duplicates. Each angle steers toward a subtle,
# non-templated scenario rather than a keyword-stuffed alarm.
_HARD_ANGLES = {
    "phishing": [
        "a brief note that a shared document needs a quick sign-in to view",
        "a low-key notice that a routine subscription payment didn't go through",
        "a short internal-sounding message about updating saved delivery details",
        "a calm follow-up asking to re-confirm access after a routine system change",
        "a plain notification that a file is ready to download from a workspace",
        "a mundane request to reactivate a dormant account before it's archived",
        "a quiet heads-up about a mismatch on a recent order that needs confirming",
        "a routine-sounding HR or benefits form that needs completing this week",
    ],
    "bec": [
        "a casual note from a manager asking to quietly set up a new payee",
        "a brief message referencing an offline conversation about redirecting a payment",
        "a short, friendly ask to update banking details for an existing supplier",
        "a low-urgency request to prepare a transfer 'when you get a moment'",
        "a plausible follow-up on an invoice the recipient is expected to recognise",
        "a calm message from 'a partner' confirming new remittance details",
        "a brief request to confirm the account before a scheduled quarterly payment",
        "a mundane forward of a payment instruction with a light personal aside",
    ],
    "romance": [
        "a warm everyday message that gently mentions a small financial worry",
        "a caring check-in that drifts toward needing a little help this month",
        "a hopeful note about future plans that hinges on a minor setback",
        "a low-key message about a travel or paperwork snag, no dramatics",
        "a tender message asking for discretion about a private difficulty",
        "a casual chat that mentions a stalled transfer they're waiting on",
        "an affectionate note framing a request as 'just until things clear up'",
        "a relaxed message building trust before any ask, mostly small talk",
    ],
    "pig_butchering": [
        "a friendly reconnect that mentions a hobby, no investment talk yet",
        "a casual message sharing a modest, plausible-sounding financial win",
        "a low-pressure invite to 'take a look, no rush' at an opportunity",
        "a warm note offering to explain something they seem curious about",
        "a relaxed message positioning the sender as an experienced peer",
        "a mundane check-in that lightly references steady returns over time",
        "a patient message suggesting starting small 'only if it feels right'",
        "a friendly message that builds rapport and defers the ask entirely",
    ],
}


def _angle(spec: "GenerationSpec", index: int) -> str:
    pool = _HARD_ANGLES.get(spec.typology)
    if spec.hard and pool:
        return pool[index % len(pool)]
    return spec.persona or "a generic, unremarkable scenario"


# Rewrite-mode system prompt: produce an equivalent lure in the model's own words,
# matched to the human seed on scenario, typology, and length — for the
# distribution-matched provenance task. Same defensive guardrails.
SYSTEM_PROMPT_REWRITE = (
    "You rewrite fraud-lure messages for a defensive detection benchmark (LureBench). "
    "Given a message, rewrite it in your own words as an equivalent lure of the SAME "
    "type: preserve the scenario, intent, tone, and APPROXIMATE LENGTH.\n"
    "- Keep any <<link>> and <<contact>> placeholders. Never add a real or realistic "
    "URL, address, phone, or payment detail; never introduce a real person, company, "
    "bank, or government body.\n"
    "- Do not summarise or shorten — match the original's length and level of detail.\n"
    "- Output ONLY the rewritten message — no preamble, no explanation, no quotes."
)


def system_prompt_for(spec: "GenerationSpec") -> str:
    if spec.seed_text:
        return SYSTEM_PROMPT_REWRITE
    return SYSTEM_PROMPT_HARD if spec.hard else SYSTEM_PROMPT


# ISO 639-1 code -> English language name, so prompts read "in Spanish" rather than
# the ambiguous "in es". Extend as new languages are added to the benchmark.
LANGUAGE_NAMES = {
    "en": "English",
    "es": "Spanish",
    "fr": "French",
    "de": "German",
    "pt": "Portuguese",
    "it": "Italian",
    "nl": "Dutch",
    "zh": "Chinese (Simplified)",
    "ja": "Japanese",
    "hi": "Hindi",
    "ar": "Arabic",
    "ru": "Russian",
    "tl": "Tagalog",
}


def language_name(code: str) -> str:
    """Human-readable language name for an ISO 639-1 code (falls back to the code)."""
    return LANGUAGE_NAMES.get(code, code)


def build_user_prompt(spec: "GenerationSpec", index: int = 0) -> str:
    lang = language_name(spec.language)
    if spec.seed_text:
        return (
            f"Rewrite this {spec.typology.replace('_', ' ')} message as an equivalent lure "
            f"in your own words, in {lang}, matching its length. Keep placeholders as-is.\n\n"
            f"MESSAGE:\n{spec.seed_text}"
        )
    scenario = _angle(spec, index)
    persuasion = ", ".join(spec.persuasion) if spec.persuasion else "any plausible angle"
    style = " Vary the tone and length; keep it plausible and understated." if spec.hard else ""
    lang_note = "" if spec.language == "en" else (
        f" Write the entire message in natural, native-quality {lang} — not a translation "
        "of an English template."
    )
    return (
        f"Write one synthetic {spec.typology.replace('_', ' ')} lure delivered over "
        f"{spec.channel} in {lang}. Scenario: {scenario}. "
        f"Persuasion emphasis: {persuasion}.{style}{lang_note} "
        f"Remember the placeholder and no-real-entity rules."
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
