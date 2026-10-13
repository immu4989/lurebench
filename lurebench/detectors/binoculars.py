"""Wrapper for Binoculars (Hans et al., ICML 2024) — a ``provenance`` detector.

Binoculars is a zero-shot machine-generated-text detector. It answers "was this
written by an LLM?", so LureBench scores it on the ``provenance`` task, not the
``fraud`` task. Its upstream constructor can download models and execute remote
model code. Default construction is therefore disabled: inject a reviewed backend
or explicitly opt into that upstream behavior in an isolated environment.

The historical linear score transform is retained for compatibility. It is an
uncalibrated ranking proxy, not P(ai) or the upstream published operating point.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from numbers import Real
from types import MethodType
from typing import Optional

from ..schema import Lure
from .base import Detector

SCORE_CONTRACT = "binoculars-linear-proxy-finite-full-input-v2"
MAX_INPUT_CHARACTERS = 100_000


class BinocularsDetector(Detector):
    name = "binoculars"
    task = "provenance"
    requires = ["torch", "transformers", "binoculars"]

    def __init__(self, *, backend=None, allow_unsafe_upstream: bool = False,
                 cache_context: Optional[str] = None) -> None:
        if type(allow_unsafe_upstream) is not bool:
            raise ValueError("allow_unsafe_upstream must be boolean")
        if backend is not None and allow_unsafe_upstream:
            raise ValueError("choose a reviewed backend or upstream loading, not both")
        if cache_context is not None and (not isinstance(cache_context, str)
                or re.fullmatch(r"[0-9a-f]{64}", cache_context) is None):
            raise ValueError("cache_context must be a reviewed lowercase SHA-256 identity")
        if backend is None:
            if not allow_unsafe_upstream:
                raise ValueError(
                    "Binoculars upstream loading may download models and execute remote code; "
                    "inject a reviewed backend or explicitly set allow_unsafe_upstream=True"
                )
            try:
                from binoculars import Binoculars  # type: ignore
            except ImportError as exc:  # pragma: no cover - optional external package
                raise ImportError(
                    "BinocularsDetector requires a separately reviewed Binoculars installation "
                    "and the 'binoculars' extra; do not install unreviewed upstream code"
                ) from exc
            backend = Binoculars()
        limit = getattr(backend, "max_token_observed", None)
        if type(limit) is not int or not 1 <= limit <= 128_000:
            raise ValueError("backend token limit must be an integer from 1 through 128000")
        if not callable(getattr(backend, "compute_score", None)) or not callable(
            getattr(backend, "tokenizer", None)
        ):
            raise ValueError("backend requires compute_score and a callable tokenizer")
        self._model = backend
        self._tokenizer = backend.tokenizer
        self._max_tokens = limit
        identity = {"contract": SCORE_CONTRACT, "reviewed_backend": cache_context,
                    "maximum_tokens": limit, "maximum_characters": MAX_INPUT_CHARACTERS,
                    "task": self.task}
        # The caller's identity must bind both models, tokenizers, backend code,
        # and numerical configuration. A Hub name alone is not such a pin.
        self.cache_namespace = (hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
                                if cache_context is not None else None)

    def score(self, lure: Lure) -> Optional[float]:
        if not isinstance(lure.text, str):
            raise ValueError("Binoculars input must be text")
        if not lure.text or len(lure.text) > MAX_INPUT_CHARACTERS:
            return None
        current_limit = getattr(self._model, "max_token_observed", None)
        current_tokenizer = getattr(self._model, "tokenizer", None)
        same_tokenizer = current_tokenizer is self._tokenizer or (
            isinstance(current_tokenizer, MethodType) and isinstance(self._tokenizer, MethodType)
            and current_tokenizer.__self__ is self._tokenizer.__self__
            and current_tokenizer.__func__ is self._tokenizer.__func__
        )
        if type(current_limit) is not int or current_limit != self._max_tokens or not same_tokenizer:
            raise ValueError("Binoculars backend tokenization contract changed")
        encoded = self._tokenizer(lure.text, truncation=False, return_token_type_ids=False,
                                  return_attention_mask=False)
        ids = encoded.get("input_ids") if isinstance(encoded, Mapping) else None
        if not isinstance(ids, list) or any(type(value) is not int or value < 0 for value in ids):
            raise ValueError("Binoculars tokenizer must return a flat list of nonnegative token IDs")
        if len(ids) < 2 or len(ids) > self._max_tokens:
            return None
        # Lower raw values indicate more likely machine-generated text. This
        # legacy transform is not calibrated and does not implement predict().
        raw = self._model.compute_score(lure.text)
        if isinstance(raw, bool) or not isinstance(raw, Real):
            raise ValueError("Binoculars raw score must be a finite positive real number")
        try:
            raw = float(raw)
        except (OverflowError, ValueError, TypeError):
            raise ValueError("Binoculars raw score is not representable") from None
        if not math.isfinite(raw) or raw <= 0:
            raise ValueError("Binoculars raw score must be a finite positive real number")
        proxy = max(0.0, min(1.0, (0.95 - raw) / 0.30 + 0.5))
        return proxy
