"""Tests for the controlled-generation harness."""

from __future__ import annotations

import pytest

from lurebench.generate import (
    GenerationSpec,
    TemplateGenerator,
    available,
    generate_records,
    get_generator,
    promote,
    screen,
)


def test_spec_rejects_benign_and_unknown():
    with pytest.raises(ValueError):
        GenerationSpec(typology="benign").validate()
    with pytest.raises(ValueError):
        GenerationSpec(typology="nope").validate()


def test_template_generator_produces_n_defanged_records():
    spec = GenerationSpec(typology="bec", generator="template-v0", persuasion=["authority"])
    records = generate_records(TemplateGenerator(), spec, 6)
    assert 1 <= len(records) <= 6  # dedup may trim near-identical skeletons
    for r in records:
        assert r.label == 1 and r.source == "ai" and r.typology == "bec"
        assert r.meta["review"] == "pending"
        assert r.meta["generation"]["engine"] == "template"
        assert "https://" not in r.text  # defanged


def test_phishing_templates_use_link_placeholder():
    spec = GenerationSpec(typology="phishing", generator="template-v0")
    records = generate_records(TemplateGenerator(), spec, 2)
    assert any("<<link>>" in r.text for r in records)


def test_screen_flags_undefanged_content():
    from lurebench.schema import Lure

    clean_rec = Lure(id="g1", text="Please confirm the details at <<link>> today.",
                     label=1, source="ai", typology="phishing", meta={"review": "pending"})
    dirty_rec = Lure(id="g2", text="Log in at http://evil.example now.",
                     label=1, source="ai", typology="phishing", meta={"review": "pending"})
    clean, flagged = screen([clean_rec, dirty_rec])
    assert [r.id for r in clean] == ["g1"]
    assert [r.id for r in flagged] == ["g2"]
    assert flagged[0].meta["review"] == "flagged"
    assert "undefanged url" in flagged[0].meta["review_reasons"]


def test_promote_only_returns_approved():
    from lurebench.schema import Lure

    pending = Lure(id="p", text="confirm at <<link>>", label=1, source="ai",
                   typology="bec", meta={"review": "pending"})
    approved = Lure(id="a", text="send the account on file", label=1, source="ai",
                    typology="bec", meta={"review": "approved"})
    assert [r.id for r in promote([pending, approved])] == ["a"]


def test_registry_and_lazy_engine():
    assert "template" in available()
    assert "anthropic" in available()
    assert "openai-compat" in available()
    for provider in ("deepseek", "qwen", "glm", "kimi", "mistral"):
        assert provider in available()
    assert isinstance(get_generator("template"), TemplateGenerator)
    with pytest.raises(KeyError):
        get_generator("does-not-exist")


def test_openai_compat_requires_key(monkeypatch):
    from lurebench.generate import OpenAICompatibleGenerator

    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    with pytest.raises(RuntimeError):
        OpenAICompatibleGenerator(base_url="https://api.deepseek.com",
                                  model="deepseek-v4-pro", api_key_env="DEEPSEEK_API_KEY")


def test_provider_preset_builds_endpoint(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")
    gen = get_generator("deepseek")
    assert gen.endpoint == "https://api.deepseek.com/chat/completions"
    assert gen.model == "deepseek-v4-pro"
    # model override flows through the preset
    gen2 = get_generator("deepseek", model="deepseek-v4-flash")
    assert gen2.model == "deepseek-v4-flash"


def test_openai_compat_generate_stubbed(monkeypatch):
    from lurebench.generate import OpenAICompatibleGenerator

    monkeypatch.setenv("MOONSHOT_API_KEY", "sk-test")
    gen = get_generator("kimi", model="kimi-k2.6")

    calls = {"n": 0}

    def fake_post(payload):
        calls["n"] += 1
        # Sanity: the defensive system prompt is actually sent.
        assert payload["messages"][0]["role"] == "system"
        assert "LureBench" in payload["messages"][0]["content"]
        return {"choices": [{"finish_reason": "stop",
                             "message": {"content": "Confirm the details at <<link>> today."}}]}

    monkeypatch.setattr(gen, "_post", fake_post)
    spec = GenerationSpec(typology="phishing", generator="kimi-k2.6")
    records = generate_records(gen, spec, 3)
    assert calls["n"] == 3
    assert len(records) >= 1
    assert all(r.generator == "kimi-k2.6" and r.source == "ai" for r in records)


def test_openai_compat_skips_content_filter(monkeypatch):
    from lurebench.generate import OpenAICompatibleGenerator

    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")
    gen = get_generator("deepseek")
    monkeypatch.setattr(gen, "_post", lambda payload: {
        "choices": [{"finish_reason": "content_filter", "message": {"content": "blocked"}}]
    })
    spec = GenerationSpec(typology="bec", generator="deepseek-v4-pro")
    assert generate_records(gen, spec, 2) == []
