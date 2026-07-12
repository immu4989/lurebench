"""Tests for the adversarial attack module."""

from __future__ import annotations

from lurebench.attacks import available, get_attack
from lurebench.attacks.perturb import (
    HomoglyphAttack,
    LeetAttack,
    WhitespaceAttack,
    ZeroWidthAttack,
)

SAMPLE = "Please verify your account urgently by clicking the link"


def test_registry_lists_char_and_llm_attacks():
    names = available()
    for expected in ("homoglyph", "leet", "zero-width", "whitespace",
                     "llm-paraphrase", "llm-keyword-evasion"):
        assert expected in names


def test_char_attacks_are_deterministic():
    for name in ("homoglyph", "leet", "zero-width", "whitespace"):
        atk = get_attack(name)
        assert atk.apply(SAMPLE) == atk.apply(SAMPLE)


def test_homoglyph_changes_text_but_preserves_length_and_shape():
    out = HomoglyphAttack().apply(SAMPLE)
    assert out != SAMPLE
    assert len(out) == len(SAMPLE)          # 1:1 char substitution
    assert out.lower().split() != SAMPLE.lower().split()  # tokens differ as bytes


def test_leet_substitutes_digits_for_letters():
    out = LeetAttack(rate=1.0).apply("aeiost")
    assert out == "431057"


def test_zero_width_inserts_invisible_chars_that_strip_back():
    out = ZeroWidthAttack().apply(SAMPLE)
    assert "​" in out
    assert out.replace("​", "") == SAMPLE  # human reads the original


def test_whitespace_splits_long_words_only():
    out = WhitespaceAttack(min_len=5).apply("verify me")
    assert out == "ver ify me"           # long word split, short word "me" left alone
    assert out.replace(" ", "") == "verifyme"


def test_llm_attack_names_require_explicit_construction():
    import pytest

    with pytest.raises(KeyError):
        get_attack("llm-paraphrase")


def test_unknown_attack_raises():
    import pytest

    with pytest.raises(KeyError):
        get_attack("does-not-exist")
