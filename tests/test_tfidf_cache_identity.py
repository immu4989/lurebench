"""Trained score replay must identify loaded bytes, not just a detector name."""

import hashlib
import io
from types import SimpleNamespace

import pytest

from lurebench.detectors import tfidf
from lurebench.detectors.cache import CachedDetector, ReplayDetector
from lurebench.diskcache import CacheReadError
from lurebench.schema import Lure

PROBE = Lure("synthetic", "Synthetic notes", 0, "human", "benign")


class SavedPipeline:
    classes_ = [0, 1]

    def __init__(self, score=.25):
        self.value = score

    def predict_proba(self, texts):
        return [[1. - self.value, self.value]]


def artifact(tmp_path, name="model.joblib", score=.25, task="fraud", compress=0):
    joblib = pytest.importorskip("joblib")
    path = tmp_path / name
    joblib.dump({"pipeline": SavedPipeline(score), "task": task}, path, compress=compress)
    return path


def test_replaced_model_cannot_silently_reuse_scores(tmp_path):
    path = artifact(tmp_path)
    cache_path = tmp_path / "scores.json"
    cached = CachedDetector(tfidf.TfidfLogisticDetector(str(path)), str(cache_path))
    assert cached.score(PROBE) == .25
    cached.flush()
    before = cache_path.read_bytes()
    artifact(tmp_path, score=.75)
    replacement = tfidf.TfidfLogisticDetector(str(path))
    with pytest.raises(CacheReadError):
        CachedDetector(replacement, str(cache_path))
    assert cache_path.read_bytes() == before


def test_same_bytes_at_new_path_preserve_identity_and_replay(tmp_path, monkeypatch):
    path = artifact(tmp_path)
    moved = tmp_path / "copy.joblib"
    moved.write_bytes(path.read_bytes())
    first = tfidf.TfidfLogisticDetector(str(path))
    second = tfidf.TfidfLogisticDetector(str(moved))
    assert first.cache_namespace == second.cache_namespace
    cache_path = tmp_path / "scores.json"
    cache = CachedDetector(first, str(cache_path))
    cache.score(PROBE)
    cache.flush()
    monkeypatch.setattr(second, "score", lambda record: pytest.fail("unexpected inference"))
    assert CachedDetector(second, str(cache_path)).score(PROBE) == .25
    replay = ReplayDetector(str(cache_path), name=first.name, task="fraud",
                            cache_namespace=first.cache_namespace)
    assert replay.score(PROBE) == .25


def test_legacy_name_only_cache_is_preserved_and_rejected(tmp_path):
    cache_path = tmp_path / "scores.json"
    legacy = SimpleNamespace(name="tfidf-logreg", task="fraud", score=lambda r: .25)
    cache = CachedDetector(legacy, str(cache_path))
    cache.score(PROBE)
    cache.flush()
    before = cache_path.read_bytes()
    detector = tfidf.TfidfLogisticDetector(str(artifact(tmp_path)))
    with pytest.raises(CacheReadError):
        CachedDetector(detector, str(cache_path))
    assert cache_path.read_bytes() == before


def test_injected_pipeline_requires_reviewed_identity_for_disk_cache(tmp_path):
    detector = tfidf.TfidfLogisticDetector.from_pipeline(SavedPipeline(), "fraud")
    with pytest.raises(ValueError, match="cache_context"):
        CachedDetector(detector, str(tmp_path / "scores.json"))
    assert CachedDetector(detector).score(PROBE) == .25
    assert not (tmp_path / "scores.json").exists()


def test_reviewed_context_task_and_class_order_separate_identities():
    identities = set()
    for context, task, classes in [("a" * 64, "fraud", [0, 1]),
                                    ("b" * 64, "fraud", [0, 1]),
                                    ("a" * 64, "provenance", [0, 1]),
                                    ("a" * 64, "fraud", [1, 0])]:
        pipe = SavedPipeline()
        pipe.classes_ = classes
        identities.add(tfidf.TfidfLogisticDetector.from_pipeline(
            pipe, task, cache_context=context,
        ).cache_namespace)
    assert len(identities) == 4


@pytest.mark.parametrize("value", ["", "wrong", "A" * 64, True, 42, "a" * 65])
def test_invalid_pins_rejected_before_file_read(monkeypatch, value):
    monkeypatch.setattr(tfidf, "read_regular_file", lambda *a, **kw: pytest.fail("unexpected read"))
    with pytest.raises(ValueError):
        tfidf.TfidfLogisticDetector("absent", expected_sha256=value)
    with pytest.raises(ValueError):
        tfidf.TfidfLogisticDetector.from_pipeline(SavedPipeline(), "fraud", cache_context=value)


def test_wrong_expected_hash_stops_before_deserialization(tmp_path, monkeypatch):
    joblib = pytest.importorskip("joblib")
    path = artifact(tmp_path)
    monkeypatch.setattr(joblib, "load", lambda *a, **kw: pytest.fail("unexpected deserialization"))
    with pytest.raises(ValueError, match="SHA-256"):
        tfidf.TfidfLogisticDetector(str(path), expected_sha256="0" * 64)


@pytest.mark.parametrize("compress", [0, 3])
def test_hash_binds_exact_deserialized_snapshot(tmp_path, monkeypatch, compress):
    joblib = pytest.importorskip("joblib")
    path = artifact(tmp_path, compress=compress)
    original = path.read_bytes()
    digest = hashlib.sha256(original).hexdigest()
    load = joblib.load

    def observed_load(stream):
        assert isinstance(stream, io.BytesIO)
        assert stream.getvalue() == original
        # Replacing the path cannot change the already captured model bytes.
        artifact(tmp_path, score=.9)
        return load(stream)

    monkeypatch.setattr(joblib, "load", observed_load)
    detector = tfidf.TfidfLogisticDetector(str(path), expected_sha256=digest)
    assert detector.model_sha256 == digest
    assert detector.score(PROBE) == .25


@pytest.mark.parametrize("kind", ["empty", "directory", "symlink", "oversize"])
def test_invalid_model_files_rejected_before_deserialization(tmp_path, monkeypatch, kind):
    joblib = pytest.importorskip("joblib")
    path = tmp_path / "invalid"
    if kind == "directory":
        path.mkdir()
    elif kind == "symlink":
        path.symlink_to(artifact(tmp_path))
    else:
        path.write_bytes(b"" if kind == "empty" else b"x" * 33)
    monkeypatch.setattr(tfidf, "MAX_MODEL_BYTES", 32)
    monkeypatch.setattr(joblib, "load", lambda *a, **kw: pytest.fail("unexpected deserialization"))
    with pytest.raises(ValueError):
        tfidf.TfidfLogisticDetector(str(path))


def test_runtime_version_change_invalidates_model_identity(tmp_path, monkeypatch):
    path = artifact(tmp_path)
    original = tfidf.TfidfLogisticDetector(str(path)).cache_namespace
    monkeypatch.setattr(tfidf, "_runtime_versions", lambda: {"synthetic": "changed"})
    changed = tfidf.TfidfLogisticDetector(str(path)).cache_namespace
    assert changed != original
