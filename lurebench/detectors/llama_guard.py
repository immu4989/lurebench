"""Wrapper for Meta Llama Guard — a ``fraud`` (content-safety) detector.

Llama Guard classifies content against a safety taxonomy. On AI-generated
romance-baiting text it has been reported at a 0% true-positive rate even while
scoring well on tax/e-commerce scams, so it is a load-bearing baseline for
showing where content-safety models fail on fraud lures.

Install the extra:  pip install "lurebench[llamaguard]"
Model access to meta-llama/Llama-Guard-3-8B (gated) is required.
"""

from __future__ import annotations

from typing import Optional

from ..schema import Lure
from .base import Detector

_UNSAFE_TOKEN = "unsafe"


class LlamaGuardDetector(Detector):
    name = "llama-guard-3"
    task = "fraud"
    requires = ["torch", "transformers", "accelerate"]

    def __init__(self, model_id: str = "meta-llama/Llama-Guard-3-8B", device: str = "auto") -> None:
        try:
            import torch  # noqa: F401
            from transformers import AutoModelForCausalLM, AutoTokenizer  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "LlamaGuardDetector requires the 'llamaguard' extra.\n"
                "  pip install 'lurebench[llamaguard]'"
            ) from exc
        self._tokenizer = AutoTokenizer.from_pretrained(model_id)
        self._model = AutoModelForCausalLM.from_pretrained(model_id, device_map=device)

    def score(self, lure: Lure) -> Optional[float]:
        import torch

        conversation = [{"role": "user", "content": lure.text}]
        input_ids = self._tokenizer.apply_chat_template(conversation, return_tensors="pt").to(
            self._model.device
        )
        with torch.no_grad():
            out = self._model.generate(input_ids, max_new_tokens=20, do_sample=False)
        decoded = self._tokenizer.decode(
            out[0][input_ids.shape[-1]:], skip_special_tokens=True
        ).strip().lower()
        # Binary safety verdict → hard 0/1 score.
        return 1.0 if decoded.startswith(_UNSAFE_TOKEN) else 0.0
