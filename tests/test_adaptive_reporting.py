"""Offline adaptive-report interpretation and interrupted-work persistence."""

import json
from types import SimpleNamespace

import pytest

from lurebench.probability import DetectorAbstainedError
from lurebench.schema import Lure
from scripts import adaptive_robustness as script


def _row(rate=.5, string_keys=False):
    return {
        "detector": "example", "n_lures": 2, "n_caught_clean": 2,
        "n_evaded": 1 if rate is not None else 0, "evasion_rate": rate,
        "median_attempts": 1 if rate is not None else None,
        "evaded_by_round": {"1" if string_keys else 1: rate},
    }


def test_aggregate_handles_mixed_json_and_memory_round_keys():
    aggregate = script.aggregate([[_row()], [_row(string_keys=True)]])
    assert aggregate[0]["evasion_mean"] == .5
    assert aggregate[0]["by_round_mean"] == {"1": .5}


def test_missing_replicates_are_not_dropped_to_make_a_mean():
    aggregate = script.aggregate([[_row()], [_row(None)]])
    assert aggregate[0]["evasion_mean"] is None
    assert aggregate[0]["evasion_min"] is None
    assert aggregate[0]["evasion_max"] is None
    assert aggregate[0]["n_replicates_with_rates"] == 1
    assert aggregate[0]["by_round_mean"] == {"1": None}


def test_generated_narrative_does_not_assert_unmeasured_results():
    single = script.to_markdown([_row()], 1, "attacker", "synthetic", .5)
    multiple = script.to_markdown_agg(script.aggregate([[_row()], [_row()]]),
                                      1, "attacker", "synthetic", .5, 2)
    for text in (single, multiple):
        assert "intent" in text
        assert "not verified" in text or "does not verify" in text
        assert "reproduces exactly" not in text
        assert "hardest to get past" not in text
        assert "is the most evadable" not in text
        assert "independent replicates" not in text
        assert "score drops" in text
        lines = [line for line in text.splitlines() if line.startswith("|")]
        assert len({line.count("|") for line in lines}) == 1


def test_aborted_adaptive_run_preserves_completed_work(tmp_path, monkeypatch):
    monkeypatch.setattr(script, "CACHE_ROOT", str(tmp_path))
    counts = {"score": 0, "generate": 0}

    def score(lure):
        counts["score"] += 1
        return .9 if lure.text == "original" else None

    def complete(*args):
        counts["generate"] += 1
        return "candidate"

    monkeypatch.setattr(script, "get_detector", lambda *a, **k: SimpleNamespace(
        name="synthetic", task="fraud", score=score,
    ))
    monkeypatch.setattr(script, "provider_complete_fn", lambda *a, **k: complete)
    records = [Lure(id="one", text="original", label=1, source="human", typology="phishing")]
    for _ in range(2):
        with pytest.raises(DetectorAbstainedError):
            script.run_defender("synthetic", {}, records, "attacker", 3, .5, 1)
    assert counts == {"score": 2, "generate": 1}
    assert list(json.loads((tmp_path / "generations_r0.json").read_text()).values()) == ["candidate"]
