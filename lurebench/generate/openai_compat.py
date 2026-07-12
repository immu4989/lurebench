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
import time
import urllib.error
import urllib.request
from typing import List, Optional

from .base import GenerationSpec, Generator, build_user_prompt, system_prompt_for


class OpenAICompatibleGenerator(Generator):
    name = "openai-compat"

    def __init__(
        self,
        base_url: str,
        model: str,
        api_key_env: str,
        max_tokens: int = 1024,
        temperature: float = 1.0,
        timeout: float = 120.0,
        max_retries: int = 5,
        retry_base: float = 2.0,
        max_delay: float = 30.0,
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
        # Retry/backoff for rate limits (429) and server errors (5xx).
        self.max_retries = max_retries
        self.retry_base = retry_base
        self.max_delay = max_delay
        # Per-batch outcome counters, reset at the start of each generate().
        self.stats: dict = {}

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
        message = choices[0].get("message") or {}
        content = message.get("content")
        return content.strip() if isinstance(content, str) else ""

    def _one(self, payload: dict) -> Optional[str]:
        """Return one lure text, or None. Retries 429/5xx with backoff; updates stats."""
        delay = self.retry_base
        for attempt in range(self.max_retries + 1):
            try:
                response = self._post(payload)
            except urllib.error.HTTPError as exc:
                retryable = exc.code == 429 or exc.code >= 500
                if retryable and attempt < self.max_retries:
                    retry_after = exc.headers.get("Retry-After") if exc.headers else None
                    try:
                        wait = float(retry_after) if retry_after else delay
                    except ValueError:
                        wait = delay
                    time.sleep(min(wait, self.max_delay))
                    delay *= 2
                    continue
                self.stats["rate_limited" if exc.code == 429 else "http_error"] += 1
                return None
            except (OSError, json.JSONDecodeError):
                # Transient network errors — incl. urllib.error.URLError and read
                # timeouts (socket.timeout, which on Python 3.9 is NOT a TimeoutError
                # subclass). Retryable, then counted rather than crashing the batch.
                if attempt < self.max_retries:
                    time.sleep(min(delay, self.max_delay))
                    delay *= 2
                    continue
                self.stats["http_error"] += 1
                return None

            choice = (response.get("choices") or [{}])[0]
            if choice.get("finish_reason") == "content_filter":
                self.stats["content_filter"] += 1
                return None
            text = self._extract(response)
            if text:
                self.stats["ok"] += 1
                return text
            self.stats["empty"] += 1
            return None
        return None

    def complete(self, system: str, user: str) -> str:
        """Single raw chat completion (system + user) -> text, or '' on failure.

        Reused by adversarial attacks and any caller needing a free-form completion
        with the same retry/backoff and error handling as generation.
        """
        self.stats = {"attempted": 1, "ok": 0, "rate_limited": 0,
                      "content_filter": 0, "http_error": 0, "empty": 0}
        payload = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        return self._one(payload) or ""

    def generate(self, spec: GenerationSpec, n: int) -> List[str]:
        spec.validate()
        self.stats = {"attempted": 0, "ok": 0, "rate_limited": 0,
                      "content_filter": 0, "http_error": 0, "empty": 0}
        system = system_prompt_for(spec)
        out: List[str] = []
        for i in range(n):
            self.stats["attempted"] += 1
            payload = {
                "model": self.model,
                "max_tokens": self.max_tokens,
                "temperature": self.temperature,
                "messages": [
                    {"role": "system", "content": system},
                    # Per-call prompt: in hard mode this rotates through varied angles.
                    {"role": "user", "content": build_user_prompt(spec, i)},
                ],
            }
            text = self._one(payload)
            if text:
                out.append(text)
        return out
