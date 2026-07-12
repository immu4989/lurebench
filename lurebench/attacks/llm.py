"""LLM-driven evasion attacks.

The character-level attacks are free but crude. A fraudster with an LLM does
something stronger: paraphrase the lure so it keeps its intent but shares no
surface features with anything a detector has seen, or rewrite it to dodge the
specific words a detector keys on. These reuse the OpenAI-compatible provider
plumbing (any provider by name, your own key).
"""

from __future__ import annotations

from typing import Callable, Optional

from .base import Attack

_PARAPHRASE_SYS = (
    "You rewrite a message in your own words for a defensive detection benchmark. "
    "Preserve the meaning, intent, and approximate length exactly, but change the "
    "wording and phrasing so it shares as little surface text as possible with the "
    "original. Keep any <<link>> / <<contact>> placeholders. Output ONLY the rewritten "
    "message, no preamble."
)

_EVADE_SYS_TEMPLATE = (
    "You rewrite a message in your own words for a defensive detection benchmark. "
    "Preserve the meaning and intent, but avoid using these words or obvious variants "
    "of them: {words}. Keep any <<link>> / <<contact>> placeholders. Output ONLY the "
    "rewritten message, no preamble."
)


def provider_complete_fn(engine: str, model: Optional[str] = None, max_tokens: int = 1024):
    """Build a ``complete(system, user) -> text`` callable from a provider engine.

    Uses the same provider presets as generation (``deepseek``, ``glm``, ``mistral``,
    ``openai-compat``, ...). Requires that provider's key in the environment.
    """
    from ..generate import get_generator

    kwargs = {"max_tokens": max_tokens}
    if model:
        kwargs["model"] = model
    gen = get_generator(engine, **kwargs)
    return gen.complete


class LLMParaphraseAttack(Attack):
    name = "llm-paraphrase"
    requires = ["a provider key (DEEPSEEK_API_KEY / MISTRAL_API_KEY / ...)"]

    def __init__(self, complete_fn: Callable[[str, str], str]) -> None:
        self._complete = complete_fn

    def apply(self, text: str) -> str:
        out = self._complete(_PARAPHRASE_SYS, text)
        return out.strip() or text  # fall back to original if the model fails


class LLMKeywordEvasionAttack(Attack):
    """Rewrite avoiding a detector's most predictive words — the targeted attack."""

    name = "llm-keyword-evasion"
    requires = ["a provider key"]

    def __init__(self, complete_fn: Callable[[str, str], str], words) -> None:
        self._complete = complete_fn
        self._sys = _EVADE_SYS_TEMPLATE.format(words=", ".join(words))

    def apply(self, text: str) -> str:
        out = self._complete(self._sys, text)
        return out.strip() or text
