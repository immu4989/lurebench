"""Tests for cross-generator splits."""

from __future__ import annotations

from lurebench.schema import Lure
from lurebench.splits import ai_generators, leave_one_generator_out


def _corpus():
    return [
        Lure(id="h1", text="benign one", label=0, source="human", typology="benign"),
        Lure(id="h2", text="human phish", label=1, source="human", typology="phishing"),
        Lure(id="a1", text="ai a", label=1, source="ai", typology="bec", generator="gen-A"),
        Lure(id="a2", text="ai a2", label=1, source="ai", typology="bec", generator="gen-A"),
        Lure(id="b1", text="ai b", label=1, source="ai", typology="bec", generator="gen-B"),
    ]


def test_ai_generators_lists_distinct():
    assert ai_generators(_corpus()) == ["gen-A", "gen-B"]


def test_logo_holds_out_only_target_generator():
    train, test = leave_one_generator_out(_corpus(), "gen-A")
    assert {r.id for r in test} == {"a1", "a2"}  # only gen-A AI records
    # train has everything else, including gen-B AI and all human records
    assert {r.id for r in train} == {"h1", "h2", "b1"}
    # no gen-A record leaks into train
    assert all(not (r.source == "ai" and r.generator == "gen-A") for r in train)
