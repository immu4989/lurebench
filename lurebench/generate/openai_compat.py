"""Generic OpenAI-compatible Chat Completions generator.

Covers every provider that speaks the OpenAI Chat Completions protocol
(DeepSeek, Qwen/DashScope, GLM/Zhipu, Kimi/Moonshot, Mistral, and others) with a
single engine. It talks HTTP directly via the standard library — it does **not**
import the ``openai`` or ``anthropic`` SDK and never contacts api.openai.com or
api.anthropic.com. Authentication uses the provider's own key, read from the
environment variable you name (e.g. ``DEEPSEEK_API_KEY``).

    OpenAICompatibleGenerator(
        base_url="https://api.deepseek.com",
        model="deepseek-v4-pro",
        api_key_env="DEEPSEEK_API_KEY",
    )
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import List

from .base import SYSTEM_PROMPT, GenerationSpec, Generator, build_user_prompt


class OpenAICompatibleGenerator(Generator):
    name = "openai-compat"

    def __init__(
        self,
        base_url: str,
        model: str,
        api_key_env: str,
        max_tokens: int = 1024,
        temperature: float = 1.0,
        timeout: float = 60.0,
    ) -> None:
        if not base_url or not model or not api_key_env:
            raise ValueError("base_url, model, and api_key_env are all required")
        self.endpoint = base_url.rstrip("/") + "/chat/completions"
        self.model = model
        self.api_key_env = api_key_env
        self.max_tokens = max_tokens
        # Temperature > 0 gives variety across the N calls in a batch; unlike the
        # Anthropic engine, these providers accept it.
        self.temperature = temperature
        self.timeout = timeout

        self._api_key = os.environ.get(api_key_env)
        if not self._api_key:
            raise RuntimeError(
                f"{api_key_env} is not set in the environment. "
                f"Export your provider key, e.g.  export {api_key_env}=..."
            )

    def _post(self, payload: dict) -> dict:
        """POST a chat-completions request. Isolated so tests can stub the HTTP call."""
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.endpoint,
            data=data,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310 - configured host
            return json.load(resp)

    @staticmethod
    def _extract(response: dict) -> str:
        choices = response.get("choices") or []
        if not choices:
            return ""
        choice = choices[0]
        # Skip provider-side content filtering rather than treating it as output.
        if choice.get("finish_reason") == "content_filter":
            return ""
        message = choice.get("message") or {}
        content = message.get("content")
        return content.strip() if isinstance(content, str) else ""

    def generate(self, spec: GenerationSpec, n: int) -> List[str]:
        spec.validate()
        payload_base = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": build_user_prompt(spec)},
            ],
        }
        out: List[str] = []
        for _ in range(n):
            try:
                response = self._post(dict(payload_base))
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
                # Network / transient errors: skip this item, keep the batch going.
                continue
            text = self._extract(response)
            if text:
                out.append(text)
        return out
