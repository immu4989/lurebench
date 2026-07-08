"""Load the published LureBench corpus straight from the Hugging Face Hub.

    from lurebench import load_core
    test = load_core("test")      # list[Lure], downloaded and cached from the Hub
    train = load_core("train")

No manual file placement needed. Requires the ``hub`` extra (huggingface_hub).
"""

from __future__ import annotations

from typing import List

from .schema import Lure, load_jsonl

HUB_REPO = "immu4989/lurebench-core"


def load_core(split: str = "test", repo_id: str = HUB_REPO) -> List[Lure]:
    """Download a split of ``lurebench-core`` from the Hub and return ``list[Lure]``.

    Args:
        split: ``"train"`` or ``"test"``.
        repo_id: Hub dataset repo (defaults to the canonical LureBench corpus).
    """
    if split not in ("train", "test"):
        raise ValueError(f"split must be 'train' or 'test', got {split!r}")
    try:
        from huggingface_hub import hf_hub_download
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "load_core requires the 'hub' extra: pip install 'lurebench[hub]'"
        ) from exc
    path = hf_hub_download(repo_id=repo_id, filename=f"{split}.jsonl", repo_type="dataset")
    return load_jsonl(path)
