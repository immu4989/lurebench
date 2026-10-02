"""Wrapper for Meta Llama Guard — a ``fraud`` (content-safety) detector.

Llama Guard classifies content against a safety taxonomy. On AI-generated
romance-baiting text it has been reported at a 0% true-positive rate even while
scoring well on tax/e-commerce scams, so it is a load-bearing baseline for
showing where content-safety models fail on fraud lures.

Install the extra:  pip install "lurebench[llamaguard]"
Model access to meta-llama/Llama-Guard-3-8B (gated) is required.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Optional

from ..schema import Lure
from .base import Detector

PARSER_VERSION = "llama-guard-3-taxonomy-v2"


def parse_verdict(output: str) -> Optional[float]:
    """Only the documented safe / unsafe-plus-taxonomy format is a verdict."""
    if not isinstance(output, str) or len(output) > 256:
        return None
    text = output.strip(" \t\r\n")
    if text == "safe":
        return 0.0
    match = re.fullmatch(r"unsafe\r?\n(S(?:[1-9]|1[0-4])(?:,[ \t]*S(?:[1-9]|1[0-4]))*)", text)
    if match is None:
        return None
    categories = [value.strip() for value in match[1].split(",")]
    if len(categories) != len(set(categories)):
        return None
    return 1.0


class LlamaGuardDetector(Detector):
    name = "llama-guard-3"
    task = "fraud"
    requires = ["torch", "transformers", "accelerate"]

    def __init__(self, model_id: str = "meta-llama/Llama-Guard-3-8B", device: str = "auto",
                 *, revision: Optional[str] = None, local_files_only: bool = False,
                 max_input_tokens: int = 8192, cache_context: Optional[str] = None) -> None:
        if not isinstance(model_id, str) or not 1 <= len(model_id) <= 512 or any(
            ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in model_id
        ):
            raise ValueError("model_id must be a bounded string without controls")
        if not isinstance(device, str) or not 1 <= len(device) <= 64:
            raise ValueError("device must be a bounded device string")
        if revision is not None and (not isinstance(revision, str) or
                                     re.fullmatch(r"[0-9a-f]{40}", revision) is None):
            raise ValueError("revision must be an immutable lowercase 40-character commit")
        if type(local_files_only) is not bool:
            raise ValueError("local_files_only must be boolean")
        if type(max_input_tokens) is not int or not 1 <= max_input_tokens <= 128_000:
            raise ValueError("max_input_tokens must be an integer from 1 through 128000")
        if cache_context is not None and (not isinstance(cache_context, str) or
                re.fullmatch(r"[0-9a-f]{64}", cache_context) is None):
            raise ValueError("cache_context must be a reviewed lowercase SHA-256 identity")
        try:
            import torch  # noqa: F401
            from transformers import AutoModelForCausalLM, AutoTokenizer  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "LlamaGuardDetector requires the 'llamaguard' extra.\n"
                "  pip install 'lurebench[llamaguard]'"
            ) from exc
        options = {"revision": revision, "local_files_only": local_files_only,
                   "trust_remote_code": False}
        self._tokenizer = AutoTokenizer.from_pretrained(model_id, **options)
        self._model = AutoModelForCausalLM.from_pretrained(
            model_id, device_map=device, use_safetensors=True, **options,
        )
        self._model.eval()
        self._max_input_tokens = max_input_tokens
        identity = {"parser": PARSER_VERSION, "model": model_id, "revision": revision,
                    "device": device, "local_files_only": local_files_only,
                    "max_input_tokens": max_input_tokens, "max_new_tokens": 128,
                    "cache_context": cache_context,
                    "chat_template": getattr(self._tokenizer, "chat_template", None)}
        # Unpinned/local artifacts need an external reviewed identity. A path or
        # mutable Hub branch is not a content pin. This is not publisher proof.
        self.cache_namespace = (hashlib.sha256(json.dumps(
            identity, sort_keys=True, allow_nan=False,
        ).encode()).hexdigest() if cache_context is not None or
            (revision is not None and not Path(model_id).exists()) else None)

    def score(self, lure: Lure) -> Optional[float]:
        import torch

        if not lure.text or len(lure.text) > 100_000:
            return None
        conversation = [{"role": "user", "content": lure.text}]
        input_ids = self._tokenizer.apply_chat_template(conversation, return_tensors="pt")
        if input_ids.shape[-1] > self._max_input_tokens:
            return None  # Do not silently assess only a truncated message.
        input_ids = input_ids.to(self._model.device)
        with torch.no_grad():
            out = self._model.generate(input_ids, max_new_tokens=128, do_sample=False)
        continuation = out[0][input_ids.shape[-1]:]
        if len(continuation) >= 128:
            return None  # A syntactically valid prefix may still be truncated.
        decoded = self._tokenizer.decode(
            continuation, skip_special_tokens=True
        )
        # Hard safety-taxonomy verdict, not a calibrated fraud probability.
        return parse_verdict(decoded)
