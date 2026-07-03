"""Tests for the ingestion framework."""

from __future__ import annotations

import json

import pytest

from lurebench.ingest import GenericAdapter, dedupe, defang, get_adapter, norm_key
from lurebench.ingest.ephishgen import EPhishGenAdapter


def test_defang_replaces_links_and_contacts():
    text = "Verify at https://evil.example/login or email me@bad.example or t.me/scammer"
    out = defang(text)
    assert "https://" not in out
    assert "@bad.example" not in out
    assert "t.me/scammer" not in out
    assert "<<link>>" in out and "<<contact>>" in out


def test_defang_is_idempotent():
    text = "click https://x.example now"
    assert defang(defang(text)) == defang(text)


def test_norm_key_ignores_whitespace_and_case():
    assert norm_key("Hello   World") == norm_key("hello world")


def test_dedupe_drops_normalized_duplicates():
    from lurebench.schema import Lure

    a = Lure(id="1", text="Wire the FUNDS now", label=1, source="ai", typology="bec")
    b = Lure(id="2", text="wire the funds   now", label=1, source="ai", typology="bec")
    c = Lure(id="3", text="different", label=1, source="ai", typology="bec")
    out = dedupe([a, b, c])
    assert [r.id for r in out] == ["1", "3"]


def test_ephishgen_adapter_normalizes(tmp_path):
    fixture = [
        {"Subject": "Reset needed", "Body": "Log in at https://x.example to verify.", "type": 1, "Language": "en"},
        {"Subject": "Team lunch", "Body": "See you at noon.", "type": 0, "Language": "it"},
    ]
    src = tmp_path / "ephishLLM.json"
    src.write_text(json.dumps(fixture), encoding="utf-8")

    records = list(EPhishGenAdapter(generator="gpt-4o").parse(str(src)))
    assert len(records) == 2

    phish, benign = records
    assert phish.label == 1 and phish.typology == "phishing"
    assert phish.source == "ai" and phish.generator == "gpt-4o"
    assert "<<link>>" in phish.text and "https://" not in phish.text

    assert benign.label == 0 and benign.typology == "benign"
    assert benign.language == "it"


def test_generic_adapter_csv(tmp_path):
    src = tmp_path / "emails.csv"
    src.write_text("body,label\n\"Urgent: verify your account\",phishing\n\"lunch tomorrow?\",ham\n", encoding="utf-8")

    adapter = GenericAdapter(
        source_id="demo",
        text_col="body",
        label_col="label",
        label_true={"phishing"},
        source="human",
    )
    records = list(adapter.parse(str(src)))
    assert [r.label for r in records] == [1, 0]
    assert records[0].meta["source_id"] == "demo"


def test_detokenize_rejoins_urls_and_preserves_words():
    from lurebench.ingest.base import defang, detokenize

    # spaced domain/scheme rejoin, then defang
    assert defang(detokenize("visit lookdog . com today")) == "visit <<link>> today"
    assert "<<link>>" in defang(detokenize("go to http : / / evil . biz / x"))
    # natural punctuation restored
    assert detokenize("word , next . end") == "word, next. end"
    # legit TLD-homograph words survive (no over-stripping)
    assert detokenize("net income for the org this year") == "net income for the org this year"


def test_registry_get_adapter():
    assert isinstance(get_adapter("ephishgen"), EPhishGenAdapter)
    with pytest.raises(KeyError):
        get_adapter("does-not-exist")
