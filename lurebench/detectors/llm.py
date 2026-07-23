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
    requires = ["a provider key (DEEPSEEK_API_KEY / MISTRAL_API_KEY / ZHIPUAI_API_KEY / ...)"]

    def __init__(
        self,
        engine: str = "mistral",
        model: Optional[str] = None,
        complete_fn: Optional[Callable[[str, str], str]] = None,
        max_tokens: int = 512,
    ) -> None:
        if complete_fn is not None:
            self._complete = complete_fn
        else:
            from ..generate import get_generator

            kwargs = {"max_tokens": max_tokens, "temperature": 0.0}
            if model:
                kwargs["model"] = model
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
            out = self._complete(_SYSTEM, lure.text)
        except Exception:  # noqa: BLE001 - provider/network failure -> abstain, don't crash
            return None
        return self._parse(out)
