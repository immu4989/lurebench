import io
import json
import urllib.error
import urllib.request
import urllib.response
from email.message import Message

import pytest

from lurebench.generate import openai_compat as transport


def generator(monkeypatch, **kwargs):
    monkeypatch.setenv("SYNTHETIC_PROVIDER_KEY", "synthetic-test-only-key")
    return transport.OpenAICompatibleGenerator(
        base_url=kwargs.pop("base_url", "https://provider.invalid/v1"),
        model="synthetic-model", api_key_env="SYNTHETIC_PROVIDER_KEY", **kwargs,
    )


@pytest.mark.parametrize("url", [
    "http://provider.invalid/v1", "file:///tmp/config", "ftp://provider.invalid",
    "https://user:secret@provider.invalid", "https://provider.invalid?key=secret",
    "https://provider.invalid#fragment", "https://provider.invalid?", "https://provider.invalid#",
    "https://provider.invalid:0", "https://provider.invalid:70000", "https://",
    " https://provider.invalid", "https://provider.invalid\n", "https://provider.invalid\\path",
])
def test_invalid_endpoint_refused_before_credential_lookup(monkeypatch, url):
    monkeypatch.delenv("SYNTHETIC_PROVIDER_KEY", raising=False)
    with pytest.raises(ValueError):
        transport.OpenAICompatibleGenerator(base_url=url, model="m", api_key_env="SYNTHETIC_PROVIDER_KEY")


def test_plain_http_requires_explicit_operator_opt_in(monkeypatch):
    gen = generator(monkeypatch, base_url="http://127.0.0.1:8000/v1", allow_insecure_http=True)
    assert gen.endpoint == "http://127.0.0.1:8000/v1/chat/completions"


@pytest.mark.parametrize("parameter,value", [
    ("timeout", 0), ("timeout", float("nan")), ("timeout", float("inf")), ("timeout", True),
    ("max_tokens", True), ("max_tokens", 0), ("max_tokens", 1.5),
    ("max_retries", -1), ("max_retries", 11), ("max_retries", True),
    ("retry_base", -1), ("max_delay", float("inf")), ("temperature", float("nan")),
])
def test_transport_parameters_are_finite_bounded_and_correctly_typed(monkeypatch, parameter, value):
    with pytest.raises(ValueError):
        generator(monkeypatch, **{parameter: value})


@pytest.mark.parametrize("name", ["model", "messages", "temperature", "max_tokens", "stream", "n"])
def test_extra_params_cannot_override_protected_request_contract(monkeypatch, name):
    with pytest.raises(ValueError, match="protected"):
        generator(monkeypatch, extra_params={name: "replacement"})


def test_extra_params_are_detached_from_caller_mutation(monkeypatch):
    params = {"reasoning": {"effort": "low"}}
    gen = generator(monkeypatch, extra_params=params)
    params["reasoning"]["effort"] = "high"
    assert gen.extra_params == {"reasoning": {"effort": "low"}}


@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
def test_authenticated_redirects_never_make_a_second_request(monkeypatch, code):
    requests = []
    streams = []
    build_opener = urllib.request.build_opener

    class InMemoryHTTPS(urllib.request.HTTPSHandler):
        def https_open(self, request):
            requests.append(request)
            headers = Message()
            headers["Location"] = "https://other-origin.invalid/collect"
            body = io.BytesIO(b"redirect body")
            streams.append(body)
            response = urllib.response.addinfourl(body, headers, request.full_url, code)
            response.msg = "Redirect"
            return response

    monkeypatch.setattr(transport.urllib.request, "build_opener", lambda *handlers: build_opener(
        urllib.request.ProxyHandler({}), InMemoryHTTPS(), *handlers,
    ))
    gen = generator(monkeypatch, max_retries=3)
    with pytest.raises(transport.ProviderConfigurationError, match="redirects are disabled"):
        gen.complete("synthetic system", "synthetic user")
    assert len(requests) == 1
    assert requests[0].full_url == gen.endpoint
    assert requests[0].get_header("Authorization") == "Bearer synthetic-test-only-key"
    assert all(stream.closed for stream in streams)


@pytest.mark.parametrize("payload", [b"[]", b'{"x":1,"x":2}', b'{"x":NaN}', b"x" * 33])
def test_response_read_is_bounded_and_strict(monkeypatch, payload):
    requested = []
    monkeypatch.setattr(transport, "MAX_PROVIDER_RESPONSE_BYTES", 32)

    class Response(io.BytesIO):
        def read(self, count=-1):
            requested.append(count)
            return super().read(count)

    class Opener:
        def open(self, request, timeout):
            return Response(payload)

    monkeypatch.setattr(transport.urllib.request, "build_opener", lambda *args: Opener())
    with pytest.raises(transport.ProviderResponseError):
        generator(monkeypatch)._post({})
    assert requested == [33]


def test_error_body_read_is_bounded_once_and_closed():
    requested = []

    class Body(io.BytesIO):
        def read(self, count=-1):
            requested.append(count)
            return super().read(count)

    body = Body(b"x" * 8192)
    error = urllib.error.HTTPError("https://provider.invalid", 400, "bad", None, body)
    result = transport._read_body(error)
    assert len(result) == transport.MAX_ERROR_BODY_BYTES
    assert requested == [transport.MAX_ERROR_BODY_BYTES]
    assert body.closed


@pytest.mark.parametrize("reason", ["length", "tool_calls", "function_call", "unknown", [], {}])
def test_incomplete_response_is_never_accepted_as_a_score(monkeypatch, reason):
    gen = generator(monkeypatch)
    monkeypatch.setattr(gen, "_post", lambda payload: {
        "choices": [{"finish_reason": reason, "message": {"content": "1"}}],
    })
    assert gen.complete("s", "u") == ""
    assert gen.stats["incomplete"] == 1


@pytest.mark.parametrize("choices", [None, "bad", {}, [], [None], [{}, {}], [{"message": []}]])
def test_malformed_choice_shapes_abstain_without_crashing(monkeypatch, choices):
    gen = generator(monkeypatch)
    monkeypatch.setattr(gen, "_post", lambda payload: {"choices": choices})
    assert gen.complete("s", "u") == ""


@pytest.mark.parametrize("retry_after", ["-1", "nan", "inf", "not-a-number", "1e999"])
def test_retry_delay_cannot_be_negative_or_nonfinite(monkeypatch, retry_after):
    gen = generator(monkeypatch, max_retries=1, retry_base=2, max_delay=3)
    waits = []
    monkeypatch.setattr(transport.time, "sleep", waits.append)

    def fail(payload):
        headers = Message()
        headers["Retry-After"] = retry_after
        raise urllib.error.HTTPError(gen.endpoint, 429, "rate", headers, io.BytesIO(b"{}"))

    monkeypatch.setattr(gen, "_post", fail)
    assert gen.complete("s", "u") == ""
    assert waits == [2]


def test_short_model_id_does_not_turn_context_error_into_model_rejection(monkeypatch):
    gen = generator(monkeypatch, max_retries=0)
    gen.model = "m"

    def fail(payload):
        body = json.dumps({"error": {"message": "input exceeds maximum context length"}}).encode()
        raise urllib.error.HTTPError(gen.endpoint, 400, "bad", None, io.BytesIO(body))

    monkeypatch.setattr(gen, "_post", fail)
    assert gen.complete("s", "u") == ""
