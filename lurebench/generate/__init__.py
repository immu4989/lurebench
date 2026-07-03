"""Controlled-generation registry.

The dependency-free ``template`` engine is eager; ``anthropic`` is lazy so
``import lurebench`` never requires the anthropic SDK.
"""

from __future__ import annotations

from typing import Dict, Type

from .base import GenerationSpec, Generator
from .openai_compat import OpenAICompatibleGenerator
from .pipeline import generate_records, promote, rewrite_records, screen
from .template import TemplateGenerator

_EAGER: Dict[str, Type[Generator]] = {TemplateGenerator.name: TemplateGenerator}
_LAZY: Dict[str, str] = {
    "anthropic": "lurebench.generate.anthropic_generator:AnthropicGenerator",
}

# Named presets for OpenAI-compatible providers — each fills base_url + api_key_env
# and a sensible default model (override with model=...). Verified 2026-07-02;
# re-check the provider docs, model IDs drift (see docs/sources.md notes).
PROVIDERS: Dict[str, dict] = {
    "deepseek": {
        "base_url": "https://api.deepseek.com",
        "api_key_env": "DEEPSEEK_API_KEY",
        "default_model": "deepseek-v4-pro",
    },
    "qwen": {
        "base_url": "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
        "api_key_env": "DASHSCOPE_API_KEY",
        "default_model": "qwen3-max",
    },
    "glm": {
        "base_url": "https://api.z.ai/api/paas/v4",
        "api_key_env": "ZHIPUAI_API_KEY",
        "default_model": "glm-4.6",
    },
    "kimi": {
        "base_url": "https://api.moonshot.ai/v1",
        "api_key_env": "MOONSHOT_API_KEY",
        "default_model": "kimi-k2.6",
    },
    "mistral": {
        "base_url": "https://api.mistral.ai/v1",
        "api_key_env": "MISTRAL_API_KEY",
        "default_model": "mistral-large-latest",
    },
}


def available() -> list[str]:
    return sorted({*_EAGER, *_LAZY, "openai-compat", *PROVIDERS})


def get_generator(name: str, **kwargs) -> Generator:
    if name in _EAGER:
        return _EAGER[name](**kwargs)
    if name == "openai-compat":
        return OpenAICompatibleGenerator(**kwargs)
    if name in PROVIDERS:
        preset = PROVIDERS[name]
        model = kwargs.pop("model", None) or preset["default_model"]
        return OpenAICompatibleGenerator(
            base_url=preset["base_url"],
            model=model,
            api_key_env=preset["api_key_env"],
            **kwargs,
        )
    if name in _LAZY:
        import importlib

        module_path, cls_name = _LAZY[name].split(":")
        return getattr(importlib.import_module(module_path), cls_name)(**kwargs)
    raise KeyError(f"unknown generator engine {name!r}; available: {available()}")


__all__ = [
    "GenerationSpec",
    "Generator",
    "TemplateGenerator",
    "OpenAICompatibleGenerator",
    "PROVIDERS",
    "available",
    "get_generator",
    "generate_records",
    "rewrite_records",
    "screen",
    "promote",
]
