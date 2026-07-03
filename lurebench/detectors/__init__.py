"""Detector registry.

Only the dependency-free ``HeuristicDetector`` is imported eagerly. The others
are resolved lazily through :func:`get_detector` so that ``import lurebench``
never requires torch/transformers/openai.
"""

from __future__ import annotations

from typing import Dict, Type

from .base import Detector
from .heuristic import HeuristicDetector

# name -> "module:ClassName" for lazily-loaded detectors.
_LAZY: Dict[str, str] = {
    "tfidf-logreg": "lurebench.detectors.tfidf:TfidfLogisticDetector",
    "binoculars": "lurebench.detectors.binoculars:BinocularsDetector",
    "llama-guard-3": "lurebench.detectors.llama_guard:LlamaGuardDetector",
    "openai-moderation": "lurebench.detectors.moderation:OpenAIModerationDetector",
}

_EAGER: Dict[str, Type[Detector]] = {
    HeuristicDetector.name: HeuristicDetector,
}


def available() -> list[str]:
    """All registered detector names."""
    return sorted({*_EAGER, *_LAZY})


def get_detector_class(name: str) -> Type[Detector]:
    """Resolve a detector name to its class, importing lazily if needed."""
    if name in _EAGER:
        return _EAGER[name]
    if name in _LAZY:
        import importlib

        module_path, cls_name = _LAZY[name].split(":")
        module = importlib.import_module(module_path)
        return getattr(module, cls_name)
    raise KeyError(f"unknown detector {name!r}; available: {available()}")


def get_detector(name: str, **kwargs) -> Detector:
    """Construct a detector by name."""
    return get_detector_class(name)(**kwargs)


__all__ = [
    "Detector",
    "HeuristicDetector",
    "available",
    "get_detector",
    "get_detector_class",
]
