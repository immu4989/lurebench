"""Dependency-free template generator.

Assembles clearly-synthetic, defanged lure text from parameterized skeletons so
the generation pipeline runs and tests offline with no model or API key, and so
every model-backed engine has a transparent floor to compare against. Output is
deterministic per index (reproducible; no randomness), and varied by rotating
slot fillers. These are intentionally simple, obviously-synthetic examples — not
optimized to evade detection.
"""

from __future__ import annotations

from typing import Dict, List

from .base import GenerationSpec, Generator

# Neutral, non-identifying slot fillers. No real people, brands, or infrastructure.
_ROLES = ["the finance team", "account services", "the operations lead", "a project sponsor"]
_ACTIONS = ["review the attached note", "confirm the details on file", "complete the pending step"]
_HOOKS = ["a short update", "a quick request", "a time-sensitive item", "a follow-up"]

# One skeleton family per generatable typology. <<link>> / <<contact>> are placeholders.
_SKELETONS: Dict[str, List[str]] = {
    "phishing": [
        "This is {role}. We noticed {hook} on your account and need you to {action}. "
        "Please confirm your access at <<link>> to keep the account active.",
        "Notice from {role}: {hook} requires attention. Verify your account details at "
        "<<link>> before the end of the day to avoid an interruption.",
    ],
    "bec": [
        "Hi, I'm tied up in meetings and need {role} to handle {hook} today. "
        "Reply with the account on file and I'll confirm the amount. Please keep this discreet.",
        "Quick one before I travel: {role} should {action} for a new supplier payment. "
        "Send the banking details you have and treat this as confidential. Time-sensitive.",
    ],
    "romance": [
        "I've really valued getting to know you. Something unexpected came up and I need {hook}. "
        "Could you help me out and reach me at <<contact>>? I'll make it up to you soon.",
        "Thinking of you today. I hit a small setback while travelling and need {hook}. "
        "Message me at <<contact>> and I'll explain everything — I trust you.",
    ],
    "pig_butchering": [
        "Good to reconnect. {role} introduced me to a platform that's done well for me. "
        "If you want, start small and I'll guide you step by step — details at <<link>>.",
        "I don't share this with many people, but {hook} in the market looks promising. "
        "You could try a small amount first; message me at <<contact>> and I'll walk you through it.",
    ],
}


class TemplateGenerator(Generator):
    name = "template"

    def generate(self, spec: GenerationSpec, n: int) -> List[str]:
        spec.validate()
        skeletons = _SKELETONS[spec.typology]
        out: List[str] = []
        for i in range(n):
            skeleton = skeletons[i % len(skeletons)]
            text = skeleton.format(
                role=_ROLES[i % len(_ROLES)],
                action=_ACTIONS[i % len(_ACTIONS)],
                hook=_HOOKS[i % len(_HOOKS)],
            )
            out.append(text)
        return out
