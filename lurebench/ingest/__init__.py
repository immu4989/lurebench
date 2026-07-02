"""Ingestion registry.

Concrete, zero-config adapters are addressable by name from the CLI. The
column-mapped :class:`GenericAdapter` is for programmatic build scripts.
"""

from __future__ import annotations

from typing import Dict, Type

from .base import Adapter, dedupe, defang, norm_key
from .ephishgen import EPhishGenAdapter
from .generic import GenericAdapter

_ADAPTERS: Dict[str, Type[Adapter]] = {
    EPhishGenAdapter.source_id: EPhishGenAdapter,
}


def available() -> list[str]:
    return sorted(_ADAPTERS)


def get_adapter(name: str, **kwargs) -> Adapter:
    if name not in _ADAPTERS:
        raise KeyError(f"unknown adapter {name!r}; available: {available()}")
    return _ADAPTERS[name](**kwargs)


__all__ = [
    "Adapter",
    "GenericAdapter",
    "EPhishGenAdapter",
    "available",
    "get_adapter",
    "dedupe",
    "defang",
    "norm_key",
]
