"""Tests for on-disk detector score caching and concurrent pre-warming."""

from __future__ import annotations

import json

import pytest

from lurebench.detectors.base import Detector
from lurebench.detectors.cache import CachedDetector, prewarm
from lurebench.schema import Lure

_UNSET = object()


class CountingDetector(Detector):
    """Scores by text length, counting calls so we can prove caching works.

    ``returns`` pins a fixed result; it uses a sentinel default so that pinning it
    to ``None`` (an abstention) is distinguishable from leaving it unset.
    """

    name = "counting"
    task = "fraud"

    def __init__(self, returns=_UNSET):
        self.calls = 0
        self._returns = returns

    def score(self, lure):
        self.calls += 1
        if self._returns is not _UNSET:
            return self._returns
        return min(1.0, len(lure.text) / 100.0)


def _lure(i, text=None):
    return Lure(id=f"c{i}", text=text or f"message number {i}", label=1,
                source="human", typology="phishing")


def test_second_score_is_served_from_cache(tmp_path):
    inner = CountingDetector()
    det = CachedDetector(inner, str(tmp_path / "c.json"))
    lure = _lure(1)
    first = det.score(lure)
    second = det.score(lure)
    assert first == second
    assert inner.calls == 1          # the inner detector ran exactly once
    assert det.hits == 1 and det.misses == 1


@pytest.mark.parametrize("options", [{"workers": True}, {"workers": 0}, {"workers": 129},
    {"workers": 1.5}, {"progress_every": False}, {"progress_every": -1}, {"progress_every": "2"}])
def test_prewarm_controls_fail_before_consuming_records(options):
    def records():
        pytest.fail("invalid controls consumed dataset")
        yield _lure(0)

    with pytest.raises(ValueError):
        prewarm(CachedDetector(CountingDetector()), records(), **options)


def test_prewarm_stops_after_failure_and_keeps_successful_cache_entries(tmp_path):
    class FailingDetector(CountingDetector):
        def score(self, lure):
            self.calls += 1
            if lure.id == "c2":
                raise RuntimeError("synthetic failure")
            return .25

    inner = FailingDetector()
    path = tmp_path / "cache.json"
    cached = CachedDetector(inner, str(path), flush_every=0)
    with pytest.raises(RuntimeError, match="synthetic failure"):
        prewarm(cached, [_lure(i) for i in range(100)], workers=1, progress_every=0)
    assert inner.calls == 3
    assert len(json.loads(path.read_text())) == 2
    restored = CachedDetector(CountingDetector(), str(path))
    assert restored.score(_lure(0)) == restored.score(_lure(1)) == .25
    assert restored.inner.calls == 0


def test_prewarm_validates_existing_scores_before_new_work(tmp_path):
    from lurebench.detectors.cache import _key

    path = tmp_path / "cache.json"
    path.write_text(json.dumps({_key("counting", _lure(0).text): "not-a-probability"}))
    inner = CountingDetector()
    cached = CachedDetector(inner, str(path))
    before = path.read_bytes()
    with pytest.raises(ValueError):
        prewarm(cached, [_lure(1), _lure(0)], workers=2)
    assert inner.calls == 0
    assert path.read_bytes() == before


def test_prewarm_never_submits_more_than_the_worker_window(monkeypatch):
    import concurrent.futures

    from lurebench.detectors import cache

    outstanding = {}
    submitted = []

    class ControlledExecutor:
        def __init__(self, max_workers):
            assert max_workers == 3

        def __enter__(self):
            return self

        def __exit__(self, *args):
            assert not outstanding

        def submit(self, fn, record):
            future = concurrent.futures.Future()
            outstanding[future] = (fn, record)
            submitted.append(record.id)
            assert len(outstanding) <= 3
            return future

    def complete_one(pending, return_when):
        assert return_when == concurrent.futures.FIRST_COMPLETED
        assert set(pending) == set(outstanding)
        future = next(iter(outstanding))
        fn, record = outstanding.pop(future)
        future.set_result(fn(record))
        return {future}, set(pending) - {future}

    monkeypatch.setattr(cache.concurrent.futures, "ThreadPoolExecutor", ControlledExecutor)
    monkeypatch.setattr(cache.concurrent.futures, "wait", complete_one)
    detector = CachedDetector(CountingDetector())
    assert prewarm(detector, [_lure(i) for i in range(25)], workers=3, progress_every=0) == 25
    assert submitted == [f"c{i}" for i in range(25)]
    assert detector.inner.calls == 25


def test_abstention_is_cached_and_not_retried(tmp_path):
    # None is a real result (the detector abstained), not a cache miss to retry.
    inner = CountingDetector(returns=None)
    det = CachedDetector(inner, str(tmp_path / "c.json"))
    lure = _lure(2)
    assert det.score(lure) is None
    assert det.score(lure) is None
    assert inner.calls == 1


def test_cache_persists_and_a_new_instance_resumes(tmp_path):
    path = str(tmp_path / "c.json")
    lures = [_lure(i) for i in range(3)]
    first = CachedDetector(CountingDetector(), path, flush_every=1)
    for lure in lures:
        first.score(lure)
    first.flush()

    inner2 = CountingDetector()
    second = CachedDetector(inner2, path)
    for lure in lures:
        second.score(lure)
    assert inner2.calls == 0          # everything replayed from disk
    assert second.hits == 3


def test_corrupt_cache_file_stops_before_spending_again(tmp_path):
    path = tmp_path / "c.json"
    path.write_text("{not valid json", encoding="utf-8")
    inner = CountingDetector()
    with pytest.raises(ValueError, match="existing cache"):
        CachedDetector(inner, str(path))
    assert inner.calls == 0
    assert path.read_text() == "{not valid json"


def test_cached_detector_is_transparent_to_the_harness(tmp_path):
    inner = CountingDetector()
    det = CachedDetector(inner, str(tmp_path / "c.json"))
    # name/task are adopted so leaderboard rows and task routing are unchanged.
    assert det.name == inner.name
    assert det.task == inner.task


def test_prewarm_fills_cache_and_is_resumable(tmp_path):
    path = str(tmp_path / "c.json")
    inner = CountingDetector()
    det = CachedDetector(inner, path)
    lures = [_lure(i) for i in range(20)]

    n = prewarm(det, lures, workers=4, progress_every=0)
    assert n == 20
    assert inner.calls == 20

    # A second pre-warm has nothing to do.
    assert prewarm(det, lures, workers=4, progress_every=0) == 0
    assert inner.calls == 20

    on_disk = json.loads(open(path, encoding="utf-8").read())
    assert len(on_disk) == 20


def test_prewarm_then_scoring_costs_nothing(tmp_path):
    inner = CountingDetector()
    det = CachedDetector(inner, str(tmp_path / "c.json"))
    lures = [_lure(i) for i in range(10)]
    prewarm(det, lures, workers=4, progress_every=0)
    calls_after_prewarm = inner.calls
    for lure in lures:                      # what the sequential harness then does
        det.score(lure)
    assert inner.calls == calls_after_prewarm


def test_concurrent_flushes_do_not_race(tmp_path):
    # Regression: flush() used one shared "<path>.tmp" for every writer, so two
    # threads flushing at once raced — the first os.replace consumed the temp file
    # and the second raised FileNotFoundError. Fast local detectors triggered it
    # constantly because they score thousands of records per second.
    path = str(tmp_path / "c.json")
    det = CachedDetector(CountingDetector(), path, flush_every=1)  # flush on every score
    lures = [_lure(i) for i in range(300)]

    prewarm(det, lures, workers=12, progress_every=0)   # must not raise

    on_disk = json.loads(open(path, encoding="utf-8").read())
    assert len(on_disk) == 300
    # No temp files left behind.
    assert [p.name for p in tmp_path.iterdir() if p.name.endswith(".tmp")] == []
