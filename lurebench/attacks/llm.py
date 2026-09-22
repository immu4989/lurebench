"""LLM-driven evasion attacks.

The character-level attacks are free but crude. A fraudster with an LLM does
something stronger: paraphrase the lure so it keeps its intent but shares no
surface features with anything a detector has seen, or rewrite it to dodge the
specific words a detector keys on. These reuse the OpenAI-compatible provider
plumbing (any provider by name, your own key).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, List, Optional

from ..probability import DetectorAbstainedError, validate_score, validate_threshold
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


def provider_complete_fn(engine: str, model: Optional[str] = None, max_tokens: int = 1024,
                         temperature: float = 0.0):
    """Build a ``complete(system, user) -> text`` callable from a provider engine.

    Uses the same provider presets as generation (``deepseek``, ``glm``, ``mistral``,
    ``openai-compat``, ...). Requires that provider's key in the environment.

    Temperature defaults to 0 to reduce sampling variability, not to guarantee
    provider determinism. Exact replay requires preserving the original response
    in a completion cache. Separate uncached draws or separate cache namespaces
    are needed for independent replicates; cached replay is not new evidence.
    """
    from ..generate import get_generator

    kwargs = {"max_tokens": max_tokens, "temperature": temperature}
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


# Each round tells the model its previous attempt was still flagged and asks for a
# larger departure. The instruction to preserve intent is what keeps the measurement
# meaningful: a rewrite that quietly drops the fraudulent ask would "evade" by no
# longer being a lure, which would flatter the attack rather than measure it.
_ADAPTIVE_SYS_TEMPLATE = (
    "You rewrite a message in your own words for a defensive detection benchmark. A "
    "classifier still flagged your previous attempt, so this rewrite (attempt {round}) "
    "must depart further from the wording of the original while preserving its meaning, "
    "intent, and approximate length. Do not weaken or remove the request the message "
    "makes; only change how it is expressed. Keep any <<link>> / <<contact>> "
    "placeholders. Output ONLY the rewritten message, no preamble."
)


@dataclass
class AdaptiveResult:
    """Outcome of an adaptive attack against one record."""

    original: str
    text: str                     # best (lowest-scoring) attempt found
    rounds: int                   # rewrites actually issued
    evaded: bool                  # got under the threshold within the budget
    scores: List[float]           # score trajectory, starting with the clean score
    attempts_to_evade: Optional[int] = None  # 1-indexed round that first evaded


class AdaptiveParaphraseAttack(Attack):
    """Paraphrase repeatedly until the detector stops flagging it, or the budget runs out.

    The one-shot ``llm-paraphrase`` attack answers "does a single rewrite evade?".
    A real attacker does not stop at one try: they rewrite, check, and rewrite again.
    This attack closes that loop, so instead of a yes/no it yields *how many attempts*
    a detector costs an adversary — a far better robustness measure, because a
    detector that survives one rewrite but folds on the third is not robust, it is
    slow to fail.

    Needs a scoring callback as well as a generator, since it is the detector's own
    feedback that drives the loop::

        atk = AdaptiveParaphraseAttack(complete_fn, detector_score_fn, max_rounds=5)
        result = atk.run(lure_text)
        result.evaded, result.attempts_to_evade
    """

    name = "adaptive-paraphrase"
    requires = ["a provider key", "a detector to score against"]

    def __init__(
        self,
        complete_fn: Callable[[str, str], str],
        score_fn: Callable[[str], Optional[float]],
        threshold: float = 0.5,
        max_rounds: int = 5,
    ) -> None:
        self._complete = complete_fn
        self._score = score_fn
        self.threshold = validate_threshold(threshold)
        if type(max_rounds) is not int or not 1 <= max_rounds <= 1000:
            raise ValueError("adaptive max_rounds must be an integer between 1 and 1000")
        self.max_rounds = max_rounds

    def _observed_score(self, text: str) -> float:
        score = validate_score(self._score(text))
        if score is None:
            raise DetectorAbstainedError(
                "adaptive experiment stopped on abstention; no evasion/resistance result"
            )
        return score

    def run(self, text: str) -> AdaptiveResult:
        """Iterate rewrites against the detector, stopping at the first evasion."""
        clean = self._observed_score(text)
        scores = [clean]
        best_text, best_score, current = text, clean, text

        if clean < self.threshold:
            # Never flagged to begin with; there is nothing to evade.
            return AdaptiveResult(text, text, 0, False, scores)

        for rnd in range(1, self.max_rounds + 1):
            out = self._complete(_ADAPTIVE_SYS_TEMPLATE.format(round=rnd), current)
            if not isinstance(out, str):
                raise ValueError("adaptive generator must return a string")
            candidate = out.strip()
            if not candidate:
                raise ValueError("adaptive generation unavailable; no resistance result")
            score = self._observed_score(candidate)
            scores.append(score)
            current = candidate
            if score < best_score:
                best_text, best_score = candidate, score
            if score < self.threshold:
                return AdaptiveResult(text, candidate, rnd, True, scores, rnd)

        return AdaptiveResult(text, best_text, len(scores) - 1, False, scores)

    def apply(self, text: str) -> str:
        """Attack interface: return the best attempt found."""
        return self.run(text).text
