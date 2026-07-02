"""Controlled-generation registry.

The dependency-free ``template`` engine is eager; ``anthropic`` is lazy so
``import lurebench`` never requires the anthropic SDK.
"""

from __future__ import annotations

from typing import Dict, Type

from .base import GenerationSpec, Generator
from .pipeline import generate_records, promote, screen
from .template import TemplateGenerator

_EAGER: Dict[str, Type[Generator]] = {TemplateGenerator.name: TemplateGenerator}
_LAZY: Dict[str, str] = {
    "anthropic": "lurebench.generate.anthropic_generator:AnthropicGenerator",
}


def available() -> list[str]:
    return sorted({*_EAGER, *_LAZY})


def get_generator(name: str, **kwargs) -> Generator:
    if name in _EAGER:
        return _EAGER[name](**kwargs)
    if name in _LAZY:
        import importlib

        module_path, cls_name = _LAZY[name].split(":")
        return getattr(importlib.import_module(module_path), cls_name)(**kwargs)
    raise KeyError(f"unknown generator engine {name!r}; available: {available()}")


__all__ = [
    "GenerationSpec",
    "Generator",
    "TemplateGenerator",
    "available",
    "get_generator",
    "generate_records",
    "screen",
    "promote",
]
