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


# --- detector specs, abstention accounting, and provider extra params -------------

def test_parse_detector_spec_forms():
    from lurebench.leaderboard import parse_detector_spec

    assert parse_detector_spec("tfidf-logreg") == ("tfidf-logreg", {}, None)
    name, kw, disp = parse_detector_spec("llm-judge@openrouter/openai/gpt-5-nano")
    assert name == "llm-judge"
    # the model id keeps its own slashes; only the first segment is the engine
    assert kw == {"engine": "openrouter", "model": "openai/gpt-5-nano"}
    assert disp == "llm-judge (openai/gpt-5-nano)"
    assert parse_detector_spec("llm-judge@mistral")[1] == {"engine": "mistral"}
    n2, kw2, d2 = parse_detector_spec(("llm-judge", {"engine": "x", "model": "m/1"}))
    assert (n2, kw2["model"], d2) == ("llm-judge", "m/1", "llm-judge (m/1)")


class _AbstainingDetector:
    """Scores fraud records, declines every benign one."""

    name = "abstainer"
    task = "fraud"

    def score(self, lure):
        return 0.9 if lure.label == 1 else None


def test_abstentions_are_reported_not_hidden(monkeypatch):
    # A detector that answers only some records must not look like it handled all
    # of them: metrics are computed over the answered subset, so the denominator
    # has to be visible.
    from lurebench import leaderboard as lb

    monkeypatch.setattr(lb, "get_detector", lambda name, **kw: _AbstainingDetector())
    data = load_jsonl(SAMPLES)
    n_benign = sum(1 for r in data if r.label == 0)
    res = lb.evaluate_detectors(data, ["abstainer"])[0]
    assert res["n_records"] == len(data)
    assert res["n_skipped"] == n_benign

    md = lb.render_markdown([res], "sample", len(data))
    assert "scored" in md
    assert f"{n_benign} abstained" in md


def test_slice_recall_excludes_abstentions_so_it_agrees_with_tpr(monkeypatch):
    from lurebench import leaderboard as lb

    monkeypatch.setattr(lb, "get_detector", lambda name, **kw: _AbstainingDetector())
    data = load_jsonl(SAMPLES)
    res = lb.evaluate_detectors(data, ["abstainer"])[0]
    # Every scored positive was flagged, so headline TPR and each slice are 1.0.
    assert res["metrics"]["recall"] == 1.0
    for value in res["slices"].values():
        assert value in (None, 1.0)


def test_extra_params_are_merged_into_the_request_payload(monkeypatch):
    # The knob that stops a reasoning model from spending its budget on hidden
    # reasoning and returning an empty answer.
    from lurebench.generate import get_generator

    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test")
    gen = get_generator("openrouter", model="openai/gpt-5-nano",
                        extra_params={"reasoning": {"effort": "minimal"}})
    seen = {}

    def fake_post(payload):
        seen.update(payload)
        return {"choices": [{"finish_reason": "stop", "message": {"content": "42"}}]}

    monkeypatch.setattr(gen, "_post", fake_post)
    assert gen.complete("sys", "user") == "42"
    assert seen["reasoning"] == {"effort": "minimal"}
    assert seen["model"] == "openai/gpt-5-nano"


def test_generator_without_extra_params_sends_none(monkeypatch):
    from lurebench.generate import get_generator

    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test")
    gen = get_generator("openrouter", model="m")
    seen = {}
    monkeypatch.setattr(gen, "_post", lambda p: (seen.update(p), {
        "choices": [{"finish_reason": "stop", "message": {"content": "1"}}]})[1])
    gen.complete("s", "u")
    assert "reasoning" not in seen  # opt-in only; some providers reject unknown fields
