"""Validate experiment inputs before paid work; isolate trusted callback objects."""

from types import SimpleNamespace

import pytest

from lurebench import leaderboard
from lurebench.cli import main
from lurebench.detectors.cache import CachedDetector, prewarm
from lurebench.robustness import run_robustness
from lurebench.schema import Lure, copy_lures, save_jsonl


def record(i=0):
    return Lure(str(i), f"synthetic original {i}", 1, "ai", "phishing", generator="synthetic",
                meta={"nested": ["original"]}, persuasion=["urgency"])


@pytest.mark.parametrize("options", [{"threshold": 2}, {"threshold": True}, {"threshold": None},
    {"task": ""}, {"task": False}, {"task": []}, {"workers": True}, {"workers": 0}])
def test_leaderboard_controls_reject_before_detector_construction(tmp_path, monkeypatch, options):
    calls = []
    monkeypatch.setattr(leaderboard, "get_detector", lambda *a, **kw: calls.append("constructed"))
    with pytest.raises(ValueError):
        leaderboard.evaluate_detectors([record()], ["synthetic"], cache_dir=str(tmp_path), **options)
    assert calls == []
    assert list(tmp_path.iterdir()) == []


def test_late_invalid_dataset_rejects_before_any_leaderboard_constructor(tmp_path, monkeypatch):
    records = [record(0), record(1)]
    records[1].text = None
    monkeypatch.setattr(leaderboard, "get_detector", lambda *a, **kw: pytest.fail("constructed"))
    with pytest.raises(ValueError, match="record 2"):
        leaderboard.evaluate_detectors(records, ["synthetic"], cache_dir=str(tmp_path))


@pytest.mark.parametrize("cached", [False, True])
@pytest.mark.parametrize("task", ["fraud", "provenance"])
def test_leaderboard_mutation_cannot_change_slices_or_cause_paid_rescoring(tmp_path, monkeypatch, cached, task):
    records = [record(0), record(1)]
    before = [r.to_dict() for r in records]
    seen = []

    def score(r):
        seen.append(r.text)
        r.text = "modified"
        r.id = "modified"
        r.label = 0
        r.typology = "benign"
        r.source = "human"
        r.generator = None
        r.meta["nested"].append("modified")
        r.persuasion.clear()
        return .9

    monkeypatch.setattr(leaderboard, "get_detector", lambda *a, **kw:
                        SimpleNamespace(name="mutator", task=task, score=score))
    result = leaderboard.evaluate_detectors(records, ["mutator"], task=task, workers=1,
                                            cache_dir=str(tmp_path) if cached else None)[0]
    assert "error" not in result
    assert seen == [r["text"] for r in before]
    assert [r.to_dict() for r in records] == before
    assert result["metrics"]["tp"] == 2
    assert result["slices"]["phishing" if task == "fraud" else "synthetic"] == 1.


def test_prewarm_copies_repeated_references_per_observation(tmp_path):
    original = record()
    before = original.to_dict()
    calls = []

    def mutate(r):
        calls.append(r.text)
        r.text = "modified"
        r.meta["nested"].clear()
        return .9

    cache = CachedDetector(SimpleNamespace(name="mutator", score=mutate), str(tmp_path / "cache.json"))
    prewarm(cache, [original, original], workers=1, progress_every=0)
    assert original.to_dict() == before
    assert cache.score(original) == .9
    assert calls == [before["text"]]


def test_prewarm_rejects_late_invalid_record_before_work_or_persistence(tmp_path):
    invalid = record(1)
    invalid.label = True
    path = tmp_path / "absent.json"
    cache = CachedDetector(SimpleNamespace(name="never", score=lambda r: pytest.fail("scored")), str(path))
    with pytest.raises(ValueError, match="record 2"):
        prewarm(cache, [record(), invalid], workers=1, progress_every=0)
    assert not path.exists()


@pytest.mark.parametrize("task", ["fraud", "provenance"])
def test_robustness_attack_receives_original_text_and_detached_metadata(task):
    records = [record(0), record(1)]
    before = [r.to_dict() for r in records]
    scored, attacked = [], []

    def mutate(r):
        scored.append(r.to_dict())
        r.text = "modified"
        r.label = 0
        r.typology = "benign"
        r.source = "human"
        r.meta["nested"].clear()
        return .9

    attack = SimpleNamespace(name="synthetic-append", apply=lambda text: (attacked.append(text) or text + "!"))
    result = run_robustness(SimpleNamespace(name="mutator", score=mutate), records, attack, task=task)
    assert attacked == [r["text"] for r in before]
    assert [r["text"] for r in scored] == [r["text"] for r in before] + [r["text"] + "!" for r in before]
    assert all(r["meta"] == {"nested": ["original"]} for r in scored)
    assert [r.to_dict() for r in records] == before
    assert result.n_detected_clean == result.n_detected_after == 2


@pytest.mark.parametrize("output", [None, 123, b"bytes", {"text": "object"}, "\ud800"])
def test_robustness_invalid_attack_result_rejects_before_attacked_score(output):
    calls = []
    detector = SimpleNamespace(name="fixed", score=lambda r: (calls.append(r.text) or .9))
    attack = SimpleNamespace(name="invalid", apply=lambda text: output)
    with pytest.raises(ValueError):
        run_robustness(detector, [record()], attack)
    assert len(calls) == 1


def test_robustness_validates_negative_records_too_before_callbacks():
    invalid = Lure("negative", "synthetic", 0, "human", "benign")
    invalid.text = None
    with pytest.raises(ValueError, match="record 2"):
        run_robustness(SimpleNamespace(score=lambda r: pytest.fail("scored")),
                       [record(), invalid], SimpleNamespace(name="noop", apply=lambda text: text))


@pytest.mark.parametrize("cache_enabled", [False, True])
def test_failed_detector_cannot_poison_the_next_leaderboard_model(tmp_path, monkeypatch, cache_enabled):
    records = [record(0), record(1)]
    before = [r.to_dict() for r in records]
    seen = []

    def bad(r):
        r.text = "modified"
        r.meta["nested"].clear()
        raise RuntimeError("synthetic failure")

    def good(r):
        seen.append(r.to_dict())
        return .9

    monkeypatch.setattr(leaderboard, "get_detector", lambda name:
                        SimpleNamespace(name=name, task="fraud", score=bad if name == "bad" else good))
    results = leaderboard.evaluate_detectors(records, ["bad", "good"], workers=1,
                                             cache_dir=str(tmp_path) if cache_enabled else None)
    assert "error" in results[0]
    assert results[1]["metrics"]["tp"] == 2
    assert seen == before
    assert [r.to_dict() for r in records] == before


def test_invalid_detector_default_task_cannot_start_cache_warming(tmp_path, monkeypatch):
    monkeypatch.setattr(leaderboard, "get_detector", lambda name:
                        SimpleNamespace(name=name, task="invalid", score=lambda r: pytest.fail("scored")))
    result = leaderboard.evaluate_detectors([record()], ["invalid"], cache_dir=str(tmp_path))[0]
    assert "error" in result
    assert list(tmp_path.iterdir()) == []


def test_valid_explicit_task_overrides_invalid_detector_default(monkeypatch):
    monkeypatch.setattr(leaderboard, "get_detector", lambda name:
                        SimpleNamespace(name=name, task="invalid", score=lambda r: .9))
    assert leaderboard.evaluate_detectors([record()], ["valid"], task="fraud")[0]["metrics"]["tp"] == 1


@pytest.mark.parametrize("operation", [copy_lures, lambda rows: run_robustness(
    SimpleNamespace(score=lambda r: .9), rows, SimpleNamespace(name="noop", apply=lambda t: t))])
def test_repeated_references_and_nested_lists_stay_detached(operation):
    original = record()
    before = original.to_dict()
    result = operation([original, original])
    assert original.to_dict() == before
    if isinstance(result, list):
        assert result[0] is not result[1]
        result[0].meta["nested"].clear()
        assert result[1].to_dict() == original.to_dict() == before


@pytest.mark.parametrize("task", [False, [], "", "invalid"])
def test_invalid_robustness_task_has_controlled_error(task):
    with pytest.raises(ValueError):
        run_robustness(SimpleNamespace(score=lambda r: pytest.fail("scored")), [record()],
                       SimpleNamespace(name="noop", apply=lambda t: t), task=task)


@pytest.mark.parametrize("command", ["leaderboard", "robustness"])
def test_cli_invalid_threshold_rejects_before_construction_and_output(tmp_path, monkeypatch, capsys, command):
    dataset = tmp_path / "dataset.jsonl"
    save_jsonl([record()], dataset)
    monkeypatch.setattr("lurebench.cli.get_detector", lambda *a, **kw: pytest.fail("constructed"))
    monkeypatch.setattr(leaderboard, "get_detector", lambda *a, **kw: pytest.fail("constructed"))
    output = tmp_path / "report.md"
    args = [command, "--dataset", str(dataset), "--detector", "synthetic", "--threshold", "2", "--out", str(output)]
    if command == "robustness":
        args += ["--attack", "homoglyph"]
    assert main(args) == 2
    assert not output.exists()
    captured = capsys.readouterr()
    assert not captured.out
    assert "inputs rejected (ValueError)" in captured.err
