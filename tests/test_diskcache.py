import json
import os
import threading
from concurrent.futures import Future, ThreadPoolExecutor

import pytest

from lurebench import diskcache
from lurebench.diskcache import CacheReadError, JsonDiskCache


@pytest.mark.parametrize("payload", ["", "[]", "null", '{"x":1,"x":2}', '{"x":NaN}',
                                    '{"x":1e999}', "{broken"])
def test_invalid_existing_cache_is_preserved_and_not_reset(tmp_path, payload):
    path = tmp_path / "cache.json"
    path.write_text(payload)
    with pytest.raises(CacheReadError):
        JsonDiskCache(str(path))
    assert path.read_text() == payload


def test_missing_cache_is_empty_and_abstention_is_a_hit(tmp_path):
    cache = JsonDiskCache(str(tmp_path / "new.json"))
    cache.set("abstention", None)
    assert cache.lookup("abstention") == (True, None)
    assert cache.lookup("missing") == (False, None)


def test_oversize_cache_rejected_before_read(tmp_path, monkeypatch):
    path = tmp_path / "cache.json"
    path.write_text('{"x":"large"}')
    monkeypatch.setattr(diskcache, "MAX_CACHE_BYTES", 4)
    with pytest.raises(CacheReadError):
        JsonDiskCache(str(path))


def test_cache_symlink_refused_without_overwriting_target(tmp_path):
    target = tmp_path / "private.json"
    target.write_text("{}")
    alias = tmp_path / "alias.json"
    alias.symlink_to(target)
    with pytest.raises(CacheReadError):
        JsonDiskCache(str(alias))
    assert target.read_text() == "{}"


@pytest.mark.parametrize("failure", ["replace", "oversize", "nan"])
def test_failed_flush_keeps_previous_file_and_pending_work(tmp_path, monkeypatch, failure):
    path = tmp_path / "cache.json"
    cache = JsonDiskCache(str(path), flush_every=0)
    cache.set("old", "preserved")
    cache.flush()
    previous = path.read_bytes()
    cache.set("new", float("nan") if failure == "nan" else "pending")
    if failure == "replace":
        def reject(*args):
            raise OSError("injected replacement failure")

        monkeypatch.setattr(diskcache.os, "replace", reject)
    elif failure == "oversize":
        monkeypatch.setattr(diskcache, "MAX_CACHE_BYTES", len(previous))
    with pytest.raises((OSError, ValueError)):
        cache.flush()
    assert path.read_bytes() == previous
    assert cache._pending == 1
    assert not list(tmp_path.glob(".lurecache-*.tmp"))


@pytest.mark.skipif(os.name != "posix", reason="POSIX file mode")
def test_cache_files_are_owner_only_even_when_replacing_broad_permissions(tmp_path):
    path = tmp_path / "cache.json"
    path.write_text("{}")
    path.chmod(0o644)
    cache = JsonDiskCache(str(path), flush_every=1)
    cache.set("sensitive", "completion")
    assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("value", ["answer", None])
def test_single_flight_same_key_computes_once(value):
    cache = JsonDiskCache()
    calls = []
    start = threading.Barrier(8)

    def worker():
        start.wait(timeout=3)
        return cache.get_or_compute("key", lambda: (calls.append(1), value)[1])

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: worker(), range(8)))
    assert results == [value] * 8
    assert len(calls) == 1
    assert cache.misses == 1 and cache.hits == 7


def test_failed_computation_is_shared_then_can_be_retried(monkeypatch):
    cache = JsonDiskCache()
    followers_ready = threading.Event()
    release = threading.Event()
    lock = threading.Lock()
    followers = []
    calls = []

    class ObservedFuture(Future):
        def result(self, timeout=None):
            with lock:
                followers.append(1)
                if len(followers) == 3:
                    followers_ready.set()
            return super().result(timeout=timeout)

    monkeypatch.setattr(diskcache, "Future", ObservedFuture)

    def fail():
        calls.append(1)
        assert release.wait(timeout=3)
        raise RuntimeError("synthetic provider failure")

    with ThreadPoolExecutor(max_workers=4) as pool:
        jobs = [pool.submit(cache.get_or_compute, "key", fail) for _ in range(4)]
        try:
            assert followers_ready.wait(timeout=3)
        finally:
            release.set()
        for job in jobs:
            with pytest.raises(RuntimeError, match="synthetic"):
                job.result(timeout=3)
    assert calls == [1]
    assert "key" not in cache
    assert not cache._inflight
    assert cache.get_or_compute("key", lambda: "recovered") == "recovered"


def test_different_keys_remain_concurrent():
    cache = JsonDiskCache()
    concurrent = threading.Barrier(2)

    def compute(value):
        concurrent.wait(timeout=3)
        return value

    with ThreadPoolExecutor(max_workers=2) as pool:
        jobs = [pool.submit(cache.get_or_compute, key, lambda key=key: compute(key))
                for key in ("a", "b")]
        assert [job.result(timeout=3) for job in jobs] == ["a", "b"]


def test_older_flush_cannot_overwrite_a_newer_snapshot(tmp_path, monkeypatch):
    cache = JsonDiskCache(str(tmp_path / "cache.json"), flush_every=0)
    cache.set("old", 1)
    first_replacing = threading.Event()
    release_first = threading.Event()
    second_attempted = threading.Event()
    original_replace = os.replace
    replacements = []
    underlying_lock = threading.Lock()

    class ObservedLock:
        def __enter__(self):
            if first_replacing.is_set():
                second_attempted.set()
            underlying_lock.acquire()

        def __exit__(self, *args):
            underlying_lock.release()

    def replace(source, destination):
        replacements.append(1)
        if len(replacements) == 1:
            first_replacing.set()
            assert release_first.wait(timeout=3)
        original_replace(source, destination)

    cache._flush_lock = ObservedLock()
    monkeypatch.setattr(diskcache.os, "replace", replace)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(cache.flush)
        assert first_replacing.wait(timeout=3)
        cache.set("new", 2)
        second = pool.submit(cache.flush)
        try:
            assert second_attempted.wait(timeout=3)
        finally:
            release_first.set()
        first.result(timeout=3)
        second.result(timeout=3)
    assert json.loads((tmp_path / "cache.json").read_bytes()) == {"old": 1, "new": 2}
    assert len(replacements) == 2
    assert cache._pending == 0
