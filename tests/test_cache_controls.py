"""Offline replay and call admission controls must fail before external work."""

import concurrent.futures
import json
from types import SimpleNamespace

import pytest

from lurebench.cli import main
from lurebench.detectors.cache import CachedDetector, ReplayDetector, prewarm
from lurebench.diskcache import (
    CacheOnlyMissError,
    CacheReadError,
    ComputationBudgetExceeded,
    JsonDiskCache,
)
from lurebench.generate.completion_cache import cached_complete_fn
from lurebench.schema import Lure, save_jsonl


def record(text, label=1):
    return Lure(id=text, text=text, label=label, source="human", typology="phishing")


def forbidden(*args, **kwargs):
    pytest.fail("live callback invoked")


def test_read_only_replays_none_and_preserves_bytes_mode_and_mtime(tmp_path):
    path = tmp_path / "scores.json"
    path.write_text('{"one":null}')
    before = (path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns)
    cache = JsonDiskCache(str(path), read_only=True)
    assert cache.get_or_compute("one", forbidden) is None
    with pytest.raises(CacheOnlyMissError):
        cache.get_or_compute("missing", forbidden)
    with pytest.raises(ValueError, match="read-only"):
        cache.set("new", 1)
    cache.flush()
    assert cache.computations_started == 0
    assert before == (path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns)


def test_missing_read_only_file_fails_without_creating_it(tmp_path):
    path = tmp_path / "missing.json"
    with pytest.raises(CacheReadError):
        JsonDiskCache(str(path), read_only=True)
    assert not path.exists()


@pytest.mark.parametrize("bad", [True, False, -1, 1.0, "2", []])
def test_invalid_budgets_rejected(bad):
    with pytest.raises(ValueError):
        JsonDiskCache(max_computations=bad)


def test_concurrent_distinct_keys_cannot_exceed_budget():
    cache = JsonDiskCache(max_computations=3)
    calls = []

    def compute(key):
        calls.append(key)
        return .5

    def request(key):
        try:
            return cache.get_or_compute(key, lambda: compute(key))
        except ComputationBudgetExceeded:
            return "denied"

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        values = list(pool.map(request, map(str, range(100))))
    assert values.count(.5) == len(calls) == cache.computations_started == 3
    assert values.count("denied") == 97
    for key in calls:
        assert cache.get_or_compute(key, forbidden) == .5


def test_failed_computations_consume_budget_but_cache_hits_do_not():
    cache = JsonDiskCache(max_computations=1)
    cache.set("old", None)

    def fail():
        raise RuntimeError("synthetic unavailable response")

    with pytest.raises(RuntimeError, match="synthetic"):
        cache.get_or_compute("new", fail)
    with pytest.raises(ComputationBudgetExceeded):
        cache.get_or_compute("new", forbidden)
    assert cache.get_or_compute("old", forbidden) is None
    assert cache.computations_started == 1


def test_same_key_coalescing_consumes_one_budget_unit():
    cache = JsonDiskCache(max_computations=1)
    calls = []

    def compute():
        calls.append(1)
        return "answer"

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        assert list(pool.map(lambda _: cache.get_or_compute("same", compute), range(50))) == [
            "answer"
        ] * 50
    assert calls == [1]


def test_detector_plan_counts_duplicates_and_cached_abstentions(tmp_path):
    path = str(tmp_path / "scores.json")
    inner = SimpleNamespace(name="synthetic", task="fraud", score=lambda r: None)
    writer = CachedDetector(inner, path, flush_every=1)
    writer.score(record("one"))
    replay = ReplayDetector(path, name="synthetic", task="fraud")
    plan = replay.plan([record("one"), record("one"), record("missing")])
    assert plan["records"] == 3
    assert plan["unique_score_keys"] == 2
    assert plan["missing_unique_keys"] == 1
    assert plan["cached_records"] == plan["cached_abstained_records"] == 2
    assert plan["replay_complete"] is False
    assert replay.hits == replay.misses == 0
    with pytest.raises(CacheOnlyMissError):
        prewarm(replay, [record("missing")], workers=2)


def test_prewarm_preserves_finished_work_on_budget_failure(tmp_path):
    path = str(tmp_path / "scores.json")
    det = CachedDetector(SimpleNamespace(name="synthetic", task="fraud", score=lambda r: .5),
                         path, max_new_calls=1)
    with pytest.raises(ComputationBudgetExceeded):
        prewarm(det, [record("one"), record("two")], workers=1)
    assert len(json.loads((tmp_path / "scores.json").read_text())) == 1


def test_completion_replay_cannot_fall_back_or_write(tmp_path):
    path = str(tmp_path / "completions.json")
    calls = []
    live = cached_complete_fn(lambda *a: calls.append(1) or "answer", path, model="m",
                              max_new_calls=1)
    assert live("s", "u") == "answer"
    with pytest.raises(ComputationBudgetExceeded):
        live("s", "other")
    before = (tmp_path / "completions.json").read_bytes()
    replay = cached_complete_fn(forbidden, path, model="m", cache_only=True)
    assert replay("s", "u") == "answer"
    with pytest.raises(CacheOnlyMissError):
        replay("s", "other")
    assert calls == [1]
    assert before == (tmp_path / "completions.json").read_bytes()


def test_replay_cli_never_constructs_a_detector(tmp_path, monkeypatch, capsys):
    import lurebench.cli as cli
    import lurebench.detectors as registry

    path, data = tmp_path / "scores.json", tmp_path / "records.jsonl"
    records = [record("one")]
    save_jsonl(records, data)
    det = CachedDetector(SimpleNamespace(name="synthetic", task="fraud", score=lambda r: .9),
                         str(path), flush_every=1)
    det.score(records[0])
    monkeypatch.setattr(cli, "get_detector", forbidden)
    monkeypatch.setattr(registry, "get_detector", forbidden)
    args = ["cache-replay", "-d", str(data), "--cache", str(path),
            "--detector-name", "synthetic", "--task", "fraud"]
    assert main(args) == 0
    assert json.loads(capsys.readouterr().out)["metrics"]["tp"] == 1
    assert main(args + ["--decision-counts"]) == 0
    exported = json.loads(capsys.readouterr().out)
    assert exported["task"] == "fraud"
    assert exported["counts"] == dict(tp=1, fp=0, tn=0, fn=0,
                                      abstained_positive=0, abstained_negative=0)
    save_jsonl(records + [record("missing")], data)
    assert main(args) == 2
    assert "no model/provider" in capsys.readouterr().err
    assert main(args + ["--plan"]) == 0
    assert json.loads(capsys.readouterr().out)["missing_unique_keys"] == 1


def test_context_bound_replay_requires_matching_namespace(tmp_path):
    path = str(tmp_path / "scores.json")
    inner = SimpleNamespace(name="synthetic", task="fraud", cache_namespace="a" * 64,
                            score=lambda r: .9)
    CachedDetector(inner, path, flush_every=1).score(record("one"))
    replay = ReplayDetector(path, name="synthetic", task="fraud", cache_namespace="a" * 64)
    assert replay.score(record("one")) == .9
    with pytest.raises(CacheReadError):
        ReplayDetector(path, name="synthetic", task="fraud", cache_namespace="b" * 64)
    without_namespace = ReplayDetector(path, name="synthetic", task="fraud")
    assert not without_namespace.plan([record("one")])["replay_complete"]
    with pytest.raises(CacheOnlyMissError):
        without_namespace.score(record("one"))


@pytest.mark.parametrize("changes", [
    {"name": ""}, {"name": "line\nbreak"}, {"name": "x" * 257}, {"name": None},
    {"task": "guessed"}, {"cache_namespace": "A" * 64}, {"cache_namespace": True},
])
def test_replay_rejects_invalid_identity(tmp_path, changes):
    identity = dict(name="synthetic", task="fraud")
    identity.update(changes)
    with pytest.raises(ValueError):
        ReplayDetector(str(tmp_path / "missing.json"), **identity)


def test_corrupt_relevant_score_prevents_plan_and_replay(tmp_path):
    path = tmp_path / "scores.json"
    det = CachedDetector(SimpleNamespace(name="synthetic", task="fraud", score=lambda r: .9),
                         str(path), flush_every=1)
    det.score(record("one"))
    payload = json.loads(path.read_text())
    payload[next(iter(payload))] = "not a score"
    path.write_text(json.dumps(payload))
    replay = ReplayDetector(str(path), name="synthetic", task="fraud")
    with pytest.raises(ValueError):
        replay.plan([record("one")])
    with pytest.raises(ValueError):
        replay.score(record("one"))


def test_zero_budget_allows_existing_hits_only():
    cache = JsonDiskCache(max_computations=0)
    cache.set("known", .1)
    assert cache.get_or_compute("known", forbidden) == .1
    with pytest.raises(ComputationBudgetExceeded):
        cache.get_or_compute("missing", forbidden)
    assert cache.computations_started == 0
