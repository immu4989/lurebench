"""Tests for the LLM-as-classifier detector (provider stubbed, no network)."""

from __future__ import annotations

from lurebench.detectors.llm import LLMJudgeDetector
from lurebench.schema import Lure


def _lure(text="hi"):
    return Lure(id="x", text=text, label=1, source="ai", typology="phishing")


def test_parses_integer_score():
    det = LLMJudgeDetector(complete_fn=lambda s, u: "87")
    assert det.score(_lure()) == 0.87


def test_clamps_and_maps_range():
    assert LLMJudgeDetector(complete_fn=lambda s, u: "0").score(_lure()) == 0.0
    assert LLMJudgeDetector(complete_fn=lambda s, u: "100").score(_lure()) == 1.0
    # extracts the first integer even with stray text
    assert LLMJudgeDetector(complete_fn=lambda s, u: "score: 42.").score(_lure()) == 0.42


def test_word_fallback_when_no_number():
    assert LLMJudgeDetector(complete_fn=lambda s, u: "this is a phishing scam").score(_lure()) == 0.9
    assert LLMJudgeDetector(complete_fn=lambda s, u: "benign message").score(_lure()) == 0.1


def test_abstains_on_empty_or_unparseable():
    assert LLMJudgeDetector(complete_fn=lambda s, u: "").score(_lure()) is None
    assert LLMJudgeDetector(complete_fn=lambda s, u: "¯\\_(ツ)_/¯").score(_lure()) is None


def test_abstains_on_provider_error():
    def boom(s, u):
        raise RuntimeError("network down")

    assert LLMJudgeDetector(complete_fn=boom).score(_lure()) is None


def test_name_includes_engine_and_registered():
    from lurebench.detectors import available

    det = LLMJudgeDetector(complete_fn=lambda s, u: "50", engine="mistral")
    assert det.name == "llm-judge (mistral)"
    assert det.task == "fraud"
    assert "llm-judge" in available()


# --- configuration errors must not masquerade as abstentions --------------------

def _http_error(code, body=b'{"error":{"message":"nope"}}'):
    import io
    import urllib.error
    return urllib.error.HTTPError("https://x/chat/completions", code, "err",
                                  hdrs=None, fp=io.BytesIO(body))


def test_auth_and_routing_failures_raise_instead_of_abstaining(monkeypatch):
    # Regression: a 404 was counted as an abstention, so pointing the harness at a
    # model you cannot reach produced a plausible row of 100% abstentions after
    # burning one request per record. Discovered when deepseek-v4-flash-0731 turned
    # out to be gated behind an account data policy and scored 40/40 "abstentions".
    import pytest

    from lurebench.generate import get_generator
    from lurebench.generate.openai_compat import ProviderConfigurationError

    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test")
    for code in (401, 403, 404):
        gen = get_generator("openrouter", model="vendor/does-not-exist",
                            max_retries=2, retry_base=0)
        monkeypatch.setattr(gen, "_post", lambda p, c=code: (_ for _ in ()).throw(_http_error(c)))
        with pytest.raises(ProviderConfigurationError) as ei:
            gen.complete("sys", "user")
        msg = str(ei.value)
        assert "vendor/does-not-exist" in msg      # names the model
        assert str(code) in msg                    # names the status
        assert "not a detector abstention" in msg  # says what it is not


def test_config_error_is_not_retried(monkeypatch):
    # There is nothing to retry: it fails identically every time.
    import pytest

    from lurebench.generate import get_generator
    from lurebench.generate.openai_compat import ProviderConfigurationError

    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test")
    gen = get_generator("openrouter", model="m", max_retries=5, retry_base=0)
    calls = {"n": 0}

    def boom(payload):
        calls["n"] += 1
        raise _http_error(404)

    monkeypatch.setattr(gen, "_post", boom)
    with pytest.raises(ProviderConfigurationError):
        gen.complete("sys", "user")
    assert calls["n"] == 1


def test_detector_propagates_config_error_but_still_abstains_on_transient(monkeypatch):
    import pytest

    from lurebench.detectors import get_detector
    from lurebench.generate.openai_compat import ProviderConfigurationError
    from lurebench.schema import Lure

    lure = Lure(id="x", text="verify your account", label=1, source="ai",
                typology="phishing")

    def raises_config(system, user):
        raise ProviderConfigurationError("unreachable")

    det = get_detector("llm-judge", complete_fn=raises_config)
    with pytest.raises(ProviderConfigurationError):
        det.score(lure)

    # A genuine transient failure must still abstain rather than crash a sweep.
    def raises_transient(system, user):
        raise OSError("connection reset")

    det2 = get_detector("llm-judge", complete_fn=raises_transient)
    assert det2.score(lure) is None

    # And an unparseable answer is still an abstention, not an error.
    det3 = get_detector("llm-judge", complete_fn=lambda s, u: "???")
    assert det3.score(lure) is None


def test_rate_limit_and_server_errors_are_still_retried_not_raised(monkeypatch):
    # Only 401/403/404 change behaviour; 429/5xx keep their retry-then-count path.
    from lurebench.generate import get_generator

    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test")
    for code in (429, 500, 503):
        gen = get_generator("openrouter", model="m", max_retries=1, retry_base=0)
        monkeypatch.setattr(gen, "_post", lambda p, c=code: (_ for _ in ()).throw(_http_error(c)))
        assert gen.complete("sys", "user") == ""   # empty, not an exception


def test_model_rejection_400_raises_but_record_level_400_still_abstains(monkeypatch):
    """400 is ambiguous where 401/403/404 are not.

    It covers both "no such model", which fails identically for every record, and
    per-record problems like an over-long message, where abstaining is correct.
    Escalating every 400 would crash a 2,000-record sweep over one oversized
    record, so only a rejection that names the model is escalated.

    The real case: DeepSeek's official API answers a dated snapshot id with 400 and
    "The supported API model names are deepseek-v4-pro or deepseek-v4-flash, but
    you passed deepseek-v4-flash-0731".
    """
    import pytest

    from lurebench.generate import get_generator
    from lurebench.generate.openai_compat import ProviderConfigurationError

    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")

    model_rejection = (b'{"error":{"message":"The supported API model names are '
                       b'deepseek-v4-pro or deepseek-v4-flash, but you passed '
                       b'deepseek-v4-flash-0731.","type":"invalid_request_error"}}')
    gen = get_generator("deepseek", model="deepseek-v4-flash-0731",
                        max_retries=2, retry_base=0)
    monkeypatch.setattr(gen, "_post",
                        lambda p: (_ for _ in ()).throw(_http_error(400, model_rejection)))
    with pytest.raises(ProviderConfigurationError) as ei:
        gen.complete("sys", "user")
    assert "deepseek-v4-flash-0731" in str(ei.value)

    # A per-record 400 that says nothing about the model must still abstain, so one
    # bad record cannot take down a sweep.
    record_problem = b'{"error":{"message":"input exceeds maximum context length"}}'
    gen2 = get_generator("deepseek", model="deepseek-v4-flash", max_retries=1, retry_base=0)
    monkeypatch.setattr(gen2, "_post",
                        lambda p: (_ for _ in ()).throw(_http_error(400, record_problem)))
    assert gen2.complete("sys", "user") == ""   # abstains, does not raise


def test_error_body_is_read_once_and_surfaced(monkeypatch):
    # The body is a stream; reading it twice yields nothing the second time, which
    # would silently drop the provider's explanation from the message.
    import pytest

    from lurebench.generate import get_generator
    from lurebench.generate.openai_compat import ProviderConfigurationError

    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test")
    gen = get_generator("openrouter", model="m", max_retries=1, retry_base=0)
    body = b'{"error":{"message":"data policy blocks all endpoints"}}'
    monkeypatch.setattr(gen, "_post", lambda p: (_ for _ in ()).throw(_http_error(404, body)))
    with pytest.raises(ProviderConfigurationError) as ei:
        gen.complete("sys", "user")
    assert "data policy blocks all endpoints" in str(ei.value)
