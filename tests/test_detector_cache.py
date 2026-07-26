"""Tests for on-disk detector score caching and concurrent pre-warming."""

from __future__ import annotations

import json

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


def test_corrupt_cache_file_starts_empty_rather_than_raising(tmp_path):
    path = tmp_path / "c.json"
    path.write_text("{not valid json", encoding="utf-8")
    det = CachedDetector(CountingDetector(), str(path))
    assert det.score(_lure(9)) is not None   # did not raise


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
