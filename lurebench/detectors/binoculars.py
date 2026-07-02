"""Wrapper for Binoculars (Hans et al., ICML 2024) — a ``provenance`` detector.

Binoculars is a zero-shot machine-generated-text detector. It answers "was this
written by an LLM?", so LureBench scores it on the ``provenance`` task, not the
``fraud`` task. It is dormant upstream (last release May 2024) and academic-only,
which is exactly why it belongs here as a baseline rather than a dependency.

Install the extra:  pip install "lurebench[binoculars]"
and the package:    pip install git+https://github.com/ahans30/Binoculars
"""

from __future__ import annotations

from typing import Optional

from ..schema import Lure
from .base import Detector


class BinocularsDetector(Detector):
    name = "binoculars"
    task = "provenance"
    requires = ["torch", "transformers", "binoculars @ git+https://github.com/ahans30/Binoculars"]

    def __init__(self) -> None:
        try:
            from binoculars import Binoculars  # type: ignore
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise ImportError(
                "BinocularsDetector requires the 'binoculars' package.\n"
                "  pip install 'lurebench[binoculars]'\n"
                "  pip install git+https://github.com/ahans30/Binoculars"
            ) from exc
        self._model = Binoculars()

    def score(self, lure: Lure) -> Optional[float]:
        # Binoculars returns a score where lower => more likely machine-generated.
        # It exposes a raw score and a predict() label; we map the raw score to a
        # calibrated P(ai) via its published threshold band.
        raw = self._model.compute_score(lure.text)
        # Published accuracy/low-fpr thresholds ~ 0.85-0.90; map linearly and clamp.
        p_ai = max(0.0, min(1.0, (0.95 - raw) / 0.30 + 0.5))
        return p_ai
