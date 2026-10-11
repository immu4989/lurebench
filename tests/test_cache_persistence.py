"""Successful persistence must remain readable by the strict restart loader."""

import json
import os
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor

import pytest

from lurebench import diskcache
from lurebench.diskcache import CacheWriteError, JsonDiskCache


def nested(levels):
    value = "leaf"
    for _ in range(levels):
        value = [value]
    return value


@pytest.mark.parametrize("value", [
    {1: "first", "1": "second"}, {True: "first", "true": "second"},
    {None: "first", "null": "second"}, {"outer": {2: 1, "2": 2}},
    nested(128), nested(1100), float("nan"), float("inf"), {"not-json"},
])
@pytest.mark.parametrize("existing", [False, True])
def test_invalid_serialized_snapshot_cannot_replace_previous_cache(tmp_path, value, existing):
    path = tmp_path / "cache.json"
    cache = JsonDiskCache(str(path), flush_every=0)
    if existing:
        cache.set("paid-result", "preserved completion")
        cache.flush()
    previous = path.read_bytes() if existing else None
    cache.set("new", value)
    with pytest.raises(CacheWriteError):
        cache.flush()
    assert (path.read_bytes() if path.exists() else None) == previous
    assert cache._pending == 1
    if existing:
        assert JsonDiskCache(str(path)).get("paid-result") == "preserved completion"
    assert not list(tmp_path.glob(".lurecache-*.tmp"))


def test_maximum_depth_and_json_coercions_remain_restart_compatible(tmp_path):
    path = tmp_path / "cache.json"
    cache = JsonDiskCache(str(path), flush_every=0)
    values = {"depth": nested(127), "tuple": (1, "two"), "keys": {1: "one"},
              "unicode": "café 東京", "abstention": None}
    for key, value in values.items():
        cache.set(key, value)
    cache.flush()
    assert JsonDiskCache(str(path)).snapshot() == json.loads(json.dumps(values))


def test_circular_value_preserves_previous_file_and_can_be_corrected(tmp_path):
    path = tmp_path / "cache.json"
    cache = JsonDiskCache(str(path), flush_every=0)
    cache.set("saved", .5)
    cache.flush()
    before = path.read_bytes()
    value = []
    value.append(value)
    cache.set("new", value)
    with pytest.raises(CacheWriteError):
        cache.flush()
    assert path.read_bytes() == before
    cache.set("new", "reviewed correction")
    cache.flush()
    assert JsonDiskCache(str(path)).snapshot() == {"saved": .5, "new": "reviewed correction"}
    assert cache._pending == 0


def test_staged_bytes_not_a_second_serialization_are_validated(tmp_path, monkeypatch):
    path = tmp_path / "cache.json"
    cache = JsonDiskCache(str(path), flush_every=0)
    cache.set("valid", .5)
    cache.flush()
    before = path.read_bytes()
    cache.set("new", "valid too")
    # Invalid bytes emitted by the serializer must not become a successful file
    # just because the original Python snapshot itself would pass validation.
    monkeypatch.setattr(diskcache.json.JSONEncoder, "iterencode",
                        lambda self, value: iter(['{"private-key":1,"private-key":2}']))
    with pytest.raises(CacheWriteError) as error:
        cache.flush()
    assert "private-key" not in "".join(traceback.format_exception(error.value))
    assert path.read_bytes() == before
    assert cache._pending == 1
    assert not list(tmp_path.glob(".lurecache-*.tmp"))


def test_exact_file_byte_limit_is_restart_compatible(tmp_path, monkeypatch):
    path = tmp_path / "cache.json"
    cache = JsonDiskCache(str(path), flush_every=0)
    value = "café 東京"
    cache.set("text", value)
    size = len(json.dumps({"text": value}, allow_nan=False).encode())
    monkeypatch.setattr(diskcache, "MAX_CACHE_BYTES", size)
    cache.flush()
    assert path.stat().st_size == size
    assert JsonDiskCache(str(path)).get("text") == value
    previous = path.read_bytes()
    cache.set("text", value + "x")
    with pytest.raises(CacheWriteError):
        cache.flush()
    assert path.read_bytes() == previous


@pytest.mark.parametrize("failure", ["oversize", "replace", "fsync"])
def test_persistence_retry_does_not_repeat_completed_callback(tmp_path, monkeypatch, failure):
    path = tmp_path / "cache.json"
    cache = JsonDiskCache(str(path), flush_every=1, max_computations=1)
    calls = []

    def compute():
        calls.append(1)
        return "one observed completion"

    def fail(*args):
        raise OSError("injected persistence failure")

    with monkeypatch.context() as patch:
        if failure == "oversize":
            patch.setattr(diskcache, "MAX_CACHE_BYTES", 1)
        else:
            patch.setattr(diskcache.os, failure, fail)
        with pytest.raises((CacheWriteError, OSError)):
            cache.get_or_compute("key", compute)
        assert cache.get_or_compute("key", compute) == "one observed completion"
        assert cache._pending == 1 and not cache._inflight
        assert not path.exists()
        assert not list(tmp_path.glob(".lurecache-*.tmp"))
    cache.flush()
    assert cache.computations_started == 1 and calls == [1]
    replay = JsonDiskCache(str(path), read_only=True)
    assert replay.get_or_compute("key", lambda: pytest.fail("replay called provider")) == "one observed completion"
    assert cache._pending == 0


def test_failed_validation_restores_pending_count_with_concurrent_new_work(tmp_path, monkeypatch):
    path = tmp_path / "cache.json"
    cache = JsonDiskCache(str(path), flush_every=0)
    cache.set("saved", "old")
    cache.flush()
    previous = path.read_bytes()
    cache.set("bad", {1: "one", "1": "two"})
    validating, release = threading.Event(), threading.Event()
    original = diskcache.loads_strict_json

    def blocked(payload):
        validating.set()
        assert release.wait(timeout=3)
        return original(payload)

    with monkeypatch.context() as patch:
        patch.setattr(diskcache, "loads_strict_json", blocked)
        with ThreadPoolExecutor(max_workers=1) as pool:
            job = pool.submit(cache.flush)
            try:
                assert validating.wait(timeout=3)
                cache.set("concurrent", "retained")
            finally:
                release.set()
            with pytest.raises(CacheWriteError):
                job.result(timeout=3)
    assert path.read_bytes() == previous and cache._pending == 2
    cache.set("bad", "corrected")
    cache.flush()
    assert JsonDiskCache(str(path)).snapshot() == {
        "saved": "old", "bad": "corrected", "concurrent": "retained",
    }
    assert cache._pending == 0
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600
