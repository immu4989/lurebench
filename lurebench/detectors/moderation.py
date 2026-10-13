"""Wrapper for the OpenAI moderation endpoint — a ``fraud`` baseline.

Moderation APIs target harassment/abuse/self-harm categories, not fraud, so they
are expected to under-flag fraud lures; the baseline quantifies that gap.

Install the extra:  pip install "lurebench[openai]"
Set OPENAI_API_KEY in the environment.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping
from importlib.metadata import PackageNotFoundError, version
from typing import Optional

from ..probability import validate_score
from ..schema import Lure
from .base import Detector

PARSER_VERSION = "omni-text-13-complete-finite-category-max-v1"
CATEGORIES = (
    "harassment", "harassment/threatening", "hate", "hate/threatening", "illicit",
    "illicit/violent", "self-harm", "self-harm/intent", "self-harm/instructions",
    "sexual", "sexual/minors", "violence", "violence/graphic",
)
_ALIASES = {name.replace("-", "_").replace("/", "_"): name for name in CATEGORIES}


class ModerationResponseError(RuntimeError):
    """No valid numeric moderation result is available; never a benign verdict."""


def _field(value, name):
    return value.get(name) if isinstance(value, Mapping) else getattr(value, name, None)


def _category_max(response) -> float:
    results = _field(response, "results")
    if not isinstance(results, list) or len(results) != 1:
        raise ModerationResponseError("moderation requires exactly one result")
    result = results[0]
    if type(_field(result, "flagged")) is not bool:
        raise ModerationResponseError("moderation result has no valid boolean flag")
    scores = _field(result, "category_scores")
    if not isinstance(scores, Mapping):
        dump = getattr(scores, "model_dump", None)
        try:
            scores = dump(by_alias=True) if callable(dump) else vars(scores)
        except (TypeError, ValueError) as exc:
            raise ModerationResponseError("moderation category scores are unavailable") from exc
    if not isinstance(scores, Mapping) or len(scores) != len(CATEGORIES):
        raise ModerationResponseError("moderation requires the complete reviewed category set")
    normalized = {}
    for key, value in scores.items():
        if not isinstance(key, str):
            raise ModerationResponseError("moderation category identity is invalid")
        name = _ALIASES.get(key, key)
        if name not in CATEGORIES or name in normalized:
            raise ModerationResponseError("moderation category identity is invalid")
        try:
            score = validate_score(value)
        except ValueError as exc:
            raise ModerationResponseError("moderation category score is invalid") from exc
        if score is None:
            raise ModerationResponseError("moderation category score is unavailable")
        normalized[name] = score
    if set(normalized) != set(CATEGORIES):
        raise ModerationResponseError("moderation requires the complete reviewed category set")
    # This is a content-safety proxy, not a calibrated probability of fraud.
    return max(normalized.values())


class OpenAIModerationDetector(Detector):
    name = "openai-moderation"
    task = "fraud"
    requires = ["openai"]

    def __init__(self, model: str = "omni-moderation-latest", *, client=None,
                 cache_context: Optional[str] = None) -> None:
        if not isinstance(model, str) or not 1 <= len(model) <= 256 or any(
            ord(c) <= 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in model
        ):
            raise ValueError("moderation model must be bounded text without whitespace or controls")
        if cache_context is not None and (not isinstance(cache_context, str)
                or re.fullmatch(r"[0-9a-f]{64}", cache_context) is None):
            raise ValueError("cache_context must be a reviewed lowercase SHA-256 identity")
        custom_client = client is not None
        if client is None:
            try:
                from openai import OpenAI  # type: ignore
            except ImportError as exc:  # pragma: no cover
                raise ImportError(
                    "OpenAIModerationDetector requires the 'openai' extra.\n"
                    "  pip install 'lurebench[openai]'"
                ) from exc
            if not os.environ.get("OPENAI_API_KEY"):
                raise RuntimeError("OPENAI_API_KEY is not set in the environment.")
            client = OpenAI()
        if not callable(getattr(getattr(client, "moderations", None), "create", None)):
            raise ValueError("moderation client requires moderations.create")
        self._client = client
        self._model = model
        try:
            sdk_version = version("openai")
        except PackageNotFoundError:
            sdk_version = None
        endpoint = str(getattr(client, "base_url", ""))
        identity = {"parser": PARSER_VERSION, "categories": CATEGORIES, "model": model,
                    "task": self.task, "endpoint": endpoint, "sdk_version": sdk_version,
                    "custom_client": custom_client, "reviewed_context": cache_context}
        self.cache_namespace = (hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
                                if (not custom_client and endpoint) or cache_context is not None else None)

    def score(self, lure: Lure) -> Optional[float]:
        resp = self._client.moderations.create(model=self._model, input=lure.text)
        return _category_max(resp)
