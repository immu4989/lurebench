"""LLM-as-classifier fraud detector.

The trained baselines read tokens: they are brittle under attack and collapse on
languages they never saw. An LLM reads *meaning*, so it is the strongest detector a
user can realistically run — and the natural test of whether that actually holds up.

It reuses the OpenAI-compatible provider plumbing that powers generation (DeepSeek,
GLM, Mistral, ... — your own key, never api.openai.com or api.anthropic.com). The model
is asked for a 0-100 fraud-likelihood, mapped to a probability in ``[0, 1]``, so it slots
into the same leaderboard / robustness / multilingual / cross-generator harnesses as
every other detector.

    lurebench eval -d data/full/core/test.jsonl -m llm-judge         # needs MISTRAL_API_KEY
    get_detector("llm-judge", engine="deepseek")

``max_tokens`` defaults to 512 because reasoning models (DeepSeek, GLM) spend their budget
on hidden reasoning and emit an empty answer at a small cap; a non-reasoning model like
Mistral still returns just the number, so the higher cap is safe (it bills on actual
output). Mistral is the fast, cheap default; any provider works.
"""

from __future__ import annotations

import re
from typing import Callable, Optional

from ..generate.openai_compat import ProviderConfigurationError
from ..schema import Lure
from .base import Detector

_SYSTEM = (
    "You are a fraud-detection classifier for a security benchmark. You are shown one "
    "message. Judge how likely it is to be a FRAUD LURE — a phishing, business email "
    "compromise, romance, or investment / 'pig butchering' scam intended to deceive the "
    "recipient into giving up credentials, money, or access. Ordinary legitimate personal "
    "or business messages are NOT fraud and should score low. The message may be in any "
    "language; judge it in whatever language it is written. Placeholders like <<link>> or "
    "<<contact>> stand in for a redacted URL or contact and are not themselves evidence. "
    "Respond with ONLY an integer from 0 to 100 (the percent likelihood it is a fraud "
    "lure). No words, no punctuation, no explanation."
)

_INT = re.compile(r"\d{1,3}")


class LLMJudgeDetector(Detector):
    name = "llm-judge"
    task = "fraud"
    #: System prompt defining the question. Subclasses override it to ask a
    #: different one (see :class:`LLMProvenanceJudgeDetector`).
    system_prompt = _SYSTEM
    requires = ["a provider key (DEEPSEEK_API_KEY / MISTRAL_API_KEY / ZHIPUAI_API_KEY / ...)"]

    def __init__(
        self,
        engine: str = "mistral",
        model: Optional[str] = None,
        complete_fn: Optional[Callable[[str, str], str]] = None,
        max_tokens: int = 512,
        extra_params: Optional[dict] = None,
    ) -> None:
        if complete_fn is not None:
            self._complete = complete_fn
        else:
            from ..generate import get_generator

            kwargs = {"max_tokens": max_tokens, "temperature": 0.0}
            if model:
                kwargs["model"] = model
            # Reasoning models otherwise burn the whole completion budget on hidden
            # reasoning and return empty content, which reads here as an abstention.
            # Pass e.g. extra_params={"reasoning": {"effort": "minimal"}}.
            if extra_params:
                kwargs["extra_params"] = extra_params
            self._complete = get_generator(engine, **kwargs).complete
        self.engine = engine
        # Distinguish providers in the leaderboard (e.g. "llm-judge (mistral)").
        self.name = f"llm-judge ({engine})"

    @staticmethod
    def _parse(out: str) -> Optional[float]:
        if not out:
            return None
        m = _INT.search(out)
        if m:
            return max(0.0, min(1.0, int(m.group()) / 100.0))
        low = out.lower()
        if any(w in low for w in ("fraud", "scam", "phish", "malicious", "suspicious")):
            return 0.9
        if any(w in low for w in ("benign", "legitimate", "safe", "not a", "no ")):
            return 0.1
        return None  # unparseable -> abstain

    def score(self, lure: Lure) -> Optional[float]:
        try:
            out = self._complete(self.system_prompt, lure.text)
        except ProviderConfigurationError:
            # A bad key, missing entitlement or unroutable model fails the same way
            # for every record. Abstaining here would turn it into a full column of
            # abstentions that reads like the model declining, after one wasted
            # request per record, so it propagates.
            raise
        except Exception:  # noqa: BLE001 - provider/network failure -> abstain, don't crash
            return None
        return self._parse(out)


# The provenance question is the opposite of the fraud question: not "is this a
# scam" but "did a machine write it". Both the AI and human records here are
# already fraud, so the judge must not fall back on scamminess as a proxy, and the
# corpus-wide defang placeholders are an artifact of redaction rather than a
# provenance signal. Saying both things explicitly is what keeps the measurement
# honest — LureBench's headline finding is that this task looks trivially easy
# until you remove the artifacts that were leaking the answer.
_PROVENANCE_SYSTEM = (
    "You are a text-provenance classifier for a security benchmark. You are shown one "
    "message. Judge how likely it is that the message was WRITTEN BY AN AI LANGUAGE "
    "MODEL rather than by a human. Judge authorship only. Many of these messages are "
    "fraudulent or scam-like regardless of who wrote them, so how deceptive or "
    "suspicious the content is tells you nothing about the author and must not affect "
    "your answer. Placeholders like <<link>> or <<contact>> are redactions applied "
    "uniformly to every message in this corpus, human and AI alike, so they are not "
    "evidence either way. Base your judgement only on style, structure, fluency, and "
    "phrasing. The message may be in any language. Respond with ONLY an integer from 0 "
    "to 100 (the percent likelihood it was written by an AI). No words, no punctuation, "
    "no explanation."
)


class LLMProvenanceJudgeDetector(LLMJudgeDetector):
    """LLM-as-classifier for the ``provenance`` task: did an AI write this?

    LureBench's headline result is that AI-vs-human fraud detection scores a perfect
    AUC on a naively assembled corpus and falls to near chance once the corpus is
    distribution-matched. That was measured with a trained classifier. This detector
    asks the same question of an LLM, which is the natural rebuttal ("surely a
    frontier model can just tell"), on the same distribution-matched data.

        get_detector("llm-judge-provenance", engine="openrouter",
                     model="openai/gpt-5-nano")
    """

    name = "llm-judge-provenance"
    task = "provenance"
    system_prompt = _PROVENANCE_SYSTEM

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.name = f"llm-judge-provenance ({self.engine})"
        self.task = "provenance"

    @staticmethod
    def _parse(out: str) -> Optional[float]:
        """Parse a 0-100 AI-likelihood. Falls back to authorship words, not fraud words."""
        if not out:
            return None
        m = _INT.search(out)
        if m:
            return max(0.0, min(1.0, int(m.group()) / 100.0))
        low = out.lower()
        if any(w in low for w in ("ai", "machine", "generated", "model", "synthetic")):
            return 0.9
        if any(w in low for w in ("human", "person", "handwritten", "authentic")):
            return 0.1
        return None  # unparseable -> abstain
