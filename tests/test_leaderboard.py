"""Tests for leaderboard generation, manifest, and Hub assembly."""

from __future__ import annotations

from pathlib import Path

from lurebench import load_jsonl
from lurebench.hub import assemble, build_dataset_card
from lurebench.leaderboard import evaluate_detectors, render_markdown
from lurebench.manifest import build_manifest, check_balance

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples" / "lures.jsonl"


def test_evaluate_produces_slices_for_fraud_detector():
    data = load_jsonl(SAMPLES)
    results = evaluate_detectors(data, ["heuristic-v0"])
    assert len(results) == 1
    entry = results[0]
    assert entry["task"] == "fraud"
    # Per-typology detection-rate slices are present.
    assert "phishing" in entry["slices"]
    assert "pig_butchering" in entry["slices"]
    # heuristic should detect at least some phishing on the sample shard.
    assert entry["slices"]["phishing"] is not None


def test_evaluate_records_error_for_missing_extra():
    data = load_jsonl(SAMPLES)
    results = evaluate_detectors(data, ["openai-moderation"])
    assert "error" in results[0]


def test_evaluate_survives_detector_that_throws(monkeypatch):
    # A detector that constructs fine but raises at score time (e.g. gated model,
    # network error) must be recorded as an error, not crash the leaderboard.
    from lurebench import leaderboard

    class Boom:
        name = "boom"
        task = "fraud"

        def score(self, lure):
            raise OSError("gated repo 403")

    monkeypatch.setattr(leaderboard, "get_detector", lambda name: Boom())
    data = load_jsonl(SAMPLES)
    results = leaderboard.evaluate_detectors(data, ["boom"])
    assert "error" in results[0]
    assert "gated repo 403" in results[0]["error"]


def test_render_markdown_has_tables():
    data = load_jsonl(SAMPLES)
    results = evaluate_detectors(data, ["heuristic-v0"])
    md = render_markdown(results, "sample", len(data))
    assert "# Leaderboard" in md
    assert "Task: `fraud`" in md
    assert "Detection rate by fraud typology" in md


def test_manifest_counts_and_balance():
    data = load_jsonl(SAMPLES)
    man = build_manifest(data)
    assert man["n"] == 16
    assert man["n_fraud"] + man["n_benign"] == 16
    assert set(man["by_source"]) <= {"ai", "human"}
    # check_balance returns a list (may warn on the tiny sample shard).
    assert isinstance(check_balance(man), list)


def test_hub_assemble_writes_card_and_manifest(tmp_path):
    out = tmp_path / "hub"
    res = assemble({"test": str(SAMPLES)}, str(out), repo_id="lurebench/core")
    assert (out / "test.jsonl").exists()
    assert (out / "manifest.json").exists()
    assert (out / "README.md").exists()
    assert res["manifest"]["n"] == 16


def test_dataset_card_is_yaml_fronted():
    man = build_manifest(load_jsonl(SAMPLES))
    card = build_dataset_card("lurebench/core", man, "v1")
    assert card.startswith("---")
    assert "license: apache-2.0" in card
