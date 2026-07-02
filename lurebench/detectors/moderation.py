"""Wrapper for the OpenAI moderation endpoint — a ``fraud`` baseline.

Moderation APIs target harassment/abuse/self-harm categories, not fraud, so they
are expected to under-flag fraud lures; the baseline quantifies that gap.

Install the extra:  pip install "lurebench[openai]"
Set OPENAI_API_KEY in the environment.
"""

from __future__ import annotations

import os
from typing import Optional

from ..schema import Lure
from .base import Detector


class OpenAIModerationDetector(Detector):
    name = "openai-moderation"
    task = "fraud"
    requires = ["openai"]

    def __init__(self, model: str = "omni-moderation-latest") -> None:
        try:
            from openai import OpenAI  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "OpenAIModerationDetector requires the 'openai' extra.\n"
                "  pip install 'lurebench[openai]'"
            ) from exc
        if not os.environ.get("OPENAI_API_KEY"):
            raise RuntimeError("OPENAI_API_KEY is not set in the environment.")
        self._client = OpenAI()
        self._model = model

    def score(self, lure: Lure) -> Optional[float]:
        resp = self._client.moderations.create(model=self._model, input=lure.text)
        result = resp.results[0]
        # Use the maximum category score as a soft fraud proxy.
        scores = getattr(result, "category_scores", None)
        if scores is None:
            return 1.0 if result.flagged else 0.0
        values = [v for v in vars(scores).values() if isinstance(v, (int, float))]
        return max(values) if values else (1.0 if result.flagged else 0.0)
