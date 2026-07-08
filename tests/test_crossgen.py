"""Tests for balanced accuracy, cross-generator provenance, and the Hub loader guard."""

from __future__ import annotations

import pytest

from lurebench.metrics import evaluate
from lurebench.schema import Lure


def test_balanced_accuracy_chance_and_perfect():
    # perfect: recall 1, fpr 0 -> bal-acc 1
    m = evaluate([1, 1, 0, 0], [1, 1, 0, 0], [0.9, 0.8, 0.2, 0.1])
    assert m.balanced_accuracy == pytest.approx(1.0)
    # always-predict-AI: recall 1, fpr 1 -> bal-acc 0.5 (chance)
    m2 = evaluate([1, 1, 0, 0], [1, 1, 1, 1], [0.9, 0.8, 0.7, 0.6])
    assert m2.balanced_accuracy == pytest.approx(0.5)


def _matched_corpus():
    human = [Lure(id=f"h{i}", text=f"dear customer please review your account statement number {i}",
                  label=1, source="human", typology="phishing") for i in range(30)]
    gen_a = [Lure(id=f"a{i}", text=f"hey quick one, mind confirming the account on file today {i}",
                  label=1, source="ai", typology="phishing", generator="gen-A") for i in range(30)]
    gen_b = [Lure(id=f"b{i}", text=f"hi there, could you take a look when you get a sec {i}",
                  label=1, source="ai", typology="phishing", generator="gen-B") for i in range(30)]
    return human + gen_a + gen_b


def test_cross_generator_returns_fold_per_generator():
    pytest.importorskip("sklearn")
    from lurebench.crossgen import cross_generator_provenance

    res = cross_generator_provenance(_matched_corpus())
    assert {r.held_out for r in res} == {"gen-A", "gen-B"}
    for r in res:
        assert 0.0 <= r.auc <= 1.0
        assert 0.0 <= r.balanced_accuracy <= 1.0
        assert r.n_test_ai == 30


def test_cross_generator_needs_two_generators():
    pytest.importorskip("sklearn")
    from lurebench.crossgen import cross_generator_provenance

    one = [Lure(id="h", text="human review your account", label=1, source="human", typology="phishing"),
           Lure(id="a", text="ai confirm now please", label=1, source="ai", typology="phishing", generator="A")]
    with pytest.raises(ValueError, match="two|>= 2|multiple"):
        cross_generator_provenance(one)


def test_cross_generator_needs_human_negatives():
    pytest.importorskip("sklearn")
    from lurebench.crossgen import cross_generator_provenance

    no_human = [
        Lure(id="a", text="x confirm now", label=1, source="ai", typology="phishing", generator="A"),
        Lure(id="b", text="y verify today", label=1, source="ai", typology="phishing", generator="B"),
    ]
    with pytest.raises(ValueError, match="human"):
        cross_generator_provenance(no_human)


def test_load_core_rejects_bad_split():
    from lurebench.data import load_core

    with pytest.raises(ValueError, match="train.*test|split"):
        load_core("nonsense")
