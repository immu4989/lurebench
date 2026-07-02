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
    assert isinstance(get_generator("template"), TemplateGenerator)
    with pytest.raises(KeyError):
        get_generator("does-not-exist")
