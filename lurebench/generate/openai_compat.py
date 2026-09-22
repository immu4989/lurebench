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

import http.client
import json
import math
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from numbers import Real
from typing import List, Optional

from ..receipts import loads_strict_json
from .base import GenerationSpec, Generator, build_user_prompt, system_prompt_for

# Status codes that mean "this request will never work as configured": bad or missing
# key, no entitlement, unknown model, or no provider route. Unlike a 429 or a 5xx
# there is nothing to retry, and unlike a content filter it is not a property of the
# record being sent.
_CONFIG_ERROR_CODES = frozenset({401, 403, 404})
MAX_PROVIDER_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_ERROR_BODY_BYTES = 4096
_RESERVED_PARAMS = {"model", "messages", "temperature", "max_tokens", "stream", "n"}


class ProviderConfigurationError(RuntimeError):
    """The provider cannot serve this model as configured.

    Raised rather than returning ``None`` so the failure cannot be mistaken for a
    detector abstention. That distinction matters: an abstention is per-record and
    is legitimately excluded from metrics, whereas this fails identically on every
    record. Swallowed, it produces a plausible-looking row of 100% abstentions
    after burning one request per record — which is exactly what a mistyped model
    name or a missing entitlement used to look like.
    """


class ProviderResponseError(RuntimeError):
    """A response violates bounded transport/JSON expectations."""


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        fp.close()
        raise ProviderConfigurationError(
            "provider redirects are disabled; configure the canonical trusted endpoint"
        )


def _bounded_number(value, name: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, Real):
        raise ValueError(f"{name} must be a bounded finite number")
    try:
        result = float(value)
    except (ValueError, OverflowError) as exc:
        raise ValueError(f"{name} must be a bounded finite number") from exc
    if not math.isfinite(result) or not minimum <= result <= maximum:
        raise ValueError(f"{name} must be a bounded finite number")
    return result


def _provider_endpoint(base_url: str, allow_insecure_http: bool) -> str:
    if type(allow_insecure_http) is not bool:
        raise ValueError("allow_insecure_http must be boolean")
    if (
        not isinstance(base_url, str) or not 1 <= len(base_url) <= 2048
        or any(ord(character) <= 32 or ord(character) == 127 for character in base_url)
        or "\\" in base_url
    ):
        raise ValueError("provider base URL must be a bounded credential-free URL")
    parts = urllib.parse.urlsplit(base_url)
    port = parts.port  # Validate syntax before reading credentials or making requests.
    if (
        parts.scheme not in ({"https", "http"} if allow_insecure_http else {"https"})
        or not parts.hostname or parts.username is not None or parts.password is not None
        or "?" in base_url or "#" in base_url or port == 0
    ):
        raise ValueError("provider URL requires HTTPS without credentials, query, or fragment")
    return base_url.rstrip("/") + "/chat/completions"


def _read_body(exc: "urllib.error.HTTPError") -> str:
    """Read an error body once. It is a stream, so a second read returns nothing."""
    try:
        return exc.read(MAX_ERROR_BODY_BYTES).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001 - already consumed or unreadable
        return ""
    finally:
        exc.close()


def _is_model_rejection(exc: "urllib.error.HTTPError", body: str) -> bool:
    """Whether a 400 is the provider rejecting the *model*, not the record.

    400 is ambiguous in a way 401/403/404 are not: it covers both "no such model",
    which fails identically for every record, and per-record problems like an
    over-long message, where abstaining really is the right response. Escalating
    every 400 would crash a whole sweep over one oversized record.

    Require a model-related rejection phrase, not just a model-ID substring:
    short model IDs such as "m" otherwise match ordinary context-length errors.
    This remains a bounded textual heuristic, not a provider-independent error
    taxonomy; unrecognized record-level errors fall back to abstention.
    """
    if exc.code != 400 or not body:
        return False
    low = body.lower()
    return bool(re.search(r"\bmodels?\b", low)) and any(phrase in low for phrase in (
        "not found", "does not exist", "unknown model", "unsupported model",
        "supported api model names", "invalid model", "not available", "no provider route",
    ))


def _config_error_message(model: str, endpoint: str, api_key_env: str,
                          exc: "urllib.error.HTTPError") -> str:
    hints = {
        400: "the provider rejected this model id",
        401: f"check that {api_key_env} is set and valid",
        403: f"the key in {api_key_env} lacks access to this model",
        404: ("unknown model id, or no provider route is available for it - on "
              "aggregators this is often a data-policy or privacy setting rather "
              "than a bad name"),
    }
    hint = hints.get(exc.code, "check the model id and credentials")
    return (f"provider returned HTTP {exc.code} for model {model!r} at {endpoint}: "
            f"{hint}. This is a configuration error, not a detector abstention, so "
            f"it is raised rather than counted as one. Provider response content is redacted.")


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
        extra_params: Optional[dict] = None,
        allow_insecure_http: bool = False,
    ) -> None:
        if not base_url or not model or not api_key_env:
            raise ValueError("base_url, model, and api_key_env are all required")
        self.endpoint = _provider_endpoint(base_url, allow_insecure_http)
        if not isinstance(model, str) or not 1 <= len(model) <= 256:
            raise ValueError("model must be a bounded nonempty string")
        if type(max_tokens) is not int or not 1 <= max_tokens <= 1_000_000:
            raise ValueError("max_tokens must be an integer between 1 and 1000000")
        if type(max_retries) is not int or not 0 <= max_retries <= 10:
            raise ValueError("max_retries must be an integer between 0 and 10")
        self.model = model
        self.api_key_env = api_key_env
        self.max_tokens = max_tokens
        # Temperature > 0 gives variety across the N calls in a batch; unlike the
        # Anthropic engine, these providers accept it.
        self.temperature = _bounded_number(temperature, "temperature", 0, 2)
        self.timeout = _bounded_number(timeout, "timeout", 0.001, 600)
        # Provider-specific request fields merged into every payload. The case that
        # forced this: a reasoning model spends its completion budget on hidden
        # reasoning and returns empty content, which a detector reads as an
        # abstention — silently, and in a way that *improves* its apparent scores,
        # because metrics are computed only over records it answered. Passing
        # ``extra_params={"reasoning": {"effort": "minimal"}}`` turns reasoning off
        # and the model answers normally. Empty by default: unknown fields are
        # rejected by some providers, so this is opt-in.
        if extra_params is not None and not isinstance(extra_params, dict):
            raise ValueError("extra_params must be an object")
        if _RESERVED_PARAMS.intersection(extra_params or {}):
            raise ValueError("extra_params cannot override protected request fields")
        encoded_params = json.dumps(extra_params or {}, allow_nan=False).encode("utf-8")
        if len(encoded_params) > 64 * 1024:
            raise ValueError("extra_params exceeds the 64 KiB limit")
        self.extra_params = loads_strict_json(encoded_params)
        # Retry/backoff for rate limits (429) and server errors (5xx).
        self.max_retries = max_retries
        self.retry_base = _bounded_number(retry_base, "retry_base", 0, 300)
        self.max_delay = _bounded_number(max_delay, "max_delay", 0, 300)
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
        data = json.dumps(payload, allow_nan=False).encode("utf-8")
        req = urllib.request.Request(
            self.endpoint,
            data=data,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        opener = urllib.request.build_opener(_RejectRedirects())
        with opener.open(req, timeout=self.timeout) as resp:
            raw = resp.read(MAX_PROVIDER_RESPONSE_BYTES + 1)
        if len(raw) > MAX_PROVIDER_RESPONSE_BYTES:
            raise ProviderResponseError("provider response exceeds its bounded size")
        try:
            response = loads_strict_json(raw)
        except ValueError as exc:
            raise ProviderResponseError("provider response is not strict bounded JSON") from exc
        if not isinstance(response, dict):
            raise ProviderResponseError("provider response must be a JSON object")
        return response

    @staticmethod
    def _extract(response: dict) -> str:
        if not isinstance(response, dict):
            return ""
        choices = response.get("choices")
        if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict):
            return ""
        message = choices[0].get("message")
        if not isinstance(message, dict):
            return ""
        content = message.get("content")
        return content.strip() if isinstance(content, str) else ""

    def _one(self, payload: dict) -> Optional[str]:
        """Return one lure text, or None. Retries 429/5xx with backoff; updates stats.

        Authentication and routing failures raise :class:`ProviderConfigurationError`
        instead of returning ``None``. They are a property of the configuration, not
        of the record being scored, so they fail identically every time and must not
        be reported as the detector declining to answer.
        """
        delay = self.retry_base
        for attempt in range(self.max_retries + 1):
            try:
                response = self._post(payload)
            except urllib.error.HTTPError as exc:
                body = _read_body(exc)
                if exc.code in _CONFIG_ERROR_CODES or _is_model_rejection(exc, body):
                    raise ProviderConfigurationError(
                        _config_error_message(self.model, self.endpoint,
                                              self.api_key_env, exc)
                    ) from exc
                retryable = exc.code == 429 or exc.code >= 500
                if retryable and attempt < self.max_retries:
                    retry_after = exc.headers.get("Retry-After") if exc.headers else None
                    try:
                        wait = float(retry_after) if retry_after else delay
                    except ValueError:
                        wait = delay
                    if not math.isfinite(wait) or wait < 0:
                        wait = delay
                    time.sleep(min(wait, self.max_delay))
                    delay *= 2
                    continue
                self.stats["rate_limited" if exc.code == 429 else "http_error"] += 1
                return None
            except ProviderResponseError:
                self.stats["http_error"] += 1
                return None
            except (OSError, json.JSONDecodeError, http.client.HTTPException):
                # Transient network errors — incl. urllib.error.URLError and read
                # timeouts (socket.timeout, which on Python 3.9 is NOT a TimeoutError
                # subclass). Retryable, then counted rather than crashing the batch.
                # http.client.HTTPException covers a truncated response
                # (IncompleteRead) and a dropped keep-alive (RemoteDisconnected).
                # Neither is an OSError, so before this they escaped the retry loop
                # and killed the whole sweep on a single blip mid-run.
                if attempt < self.max_retries:
                    time.sleep(min(delay, self.max_delay))
                    delay *= 2
                    continue
                self.stats["http_error"] += 1
                return None

            choices = response.get("choices") if isinstance(response, dict) else None
            if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict):
                self.stats["empty"] += 1
                return None
            choice = choices[0]
            reason = choice.get("finish_reason")
            if reason == "content_filter":
                self.stats["content_filter"] += 1
                return None
            if reason is not None and reason != "stop":
                self.stats["incomplete"] += 1
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
                      "content_filter": 0, "http_error": 0, "empty": 0, "incomplete": 0}
        payload = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            **self.extra_params,
        }
        return self._one(payload) or ""

    def generate(self, spec: GenerationSpec, n: int) -> List[str]:
        spec.validate()
        self.stats = {"attempted": 0, "ok": 0, "rate_limited": 0,
                      "content_filter": 0, "http_error": 0, "empty": 0, "incomplete": 0}
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
                **self.extra_params,
            }
            text = self._one(payload)
            if text:
                out.append(text)
        return out
