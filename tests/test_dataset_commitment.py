"""Dataset commitments must describe the exact bytes consumed by evaluation."""

import hashlib
import json
import os
from pathlib import Path

import pytest

from lurebench import schema
from lurebench.corpus_v2 import _load_and_gate
from lurebench.schema import load_jsonl, load_jsonl_with_digest


def payload(text):
    return (json.dumps({"id": "source-record", "text": text, "label": 0,
                        "source": "human", "typology": "benign"}) + "\n").encode()


def replace_after_legacy_hash(monkeypatch, path, replacement):
    """A deterministic file replacement in the legacy hash/load gap."""
    original_open = Path.open

    class Reader:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def read(self, size=-1):
            return self.stream.read(size)

        def __exit__(self, *args):
            self.stream.close()
            with original_open(path, "wb") as output:
                output.write(replacement)

    def opening(self, mode="r", *args, **kwargs):
        stream = original_open(self, mode, *args, **kwargs)
        return Reader(stream) if self == path and mode == "rb" else stream

    monkeypatch.setattr(Path, "open", opening)


def test_core_v2_commitment_matches_records_even_at_legacy_reopen_boundary(tmp_path, monkeypatch):
    path = tmp_path / "source.jsonl"
    original, replacement = payload("Original notes"), payload("Replacement notes")
    path.write_bytes(original)
    replace_after_legacy_hash(monkeypatch, path, replacement)
    records, metadata = _load_and_gate([str(path)])
    consumed = original if records[0].text == "Original notes" else replacement
    assert metadata["commitments"][0]["sha256"] == hashlib.sha256(consumed).hexdigest()


def test_container_report_digest_matches_consumed_records(tmp_path, monkeypatch):
    from lurebench.cli import main
    from lurebench.detectors import container

    observed = []

    class Detector:
        image_id = "sha256:" + "a" * 64
        memory = "512m"
        cpus = 1.0

        def __init__(self, *args, **kwargs):
            pass

        def score(self, record):
            observed.append(record.text)
            return .1

        def close(self):
            pass

    monkeypatch.setattr(container, "ContainerDetector", Detector)
    path, output = tmp_path / "source.jsonl", tmp_path / "evaluation.json"
    original, replacement = payload("Original notes"), payload("Replacement notes")
    path.write_bytes(original)
    replace_after_legacy_hash(monkeypatch, path, replacement)
    assert main(["container-eval", "--dataset", str(path), "--image", "synthetic",
                 "--out", str(output)]) == 0
    report = json.loads(output.read_text())
    consumed = original if observed == ["Original notes"] else replacement
    assert report["dataset"]["sha256"] == hashlib.sha256(consumed).hexdigest()
    assert report["dataset"]["record_count"] == 1


@pytest.mark.parametrize("ending", [b"\n", b"\r\n", b""])
def test_digest_commits_exact_source_bytes_not_reserialized_records(tmp_path, ending):
    path = tmp_path / "records.jsonl"
    line = json.loads(payload("café 東京"))
    line["future_extension"] = True
    raw = b"// private source annotation\r\n\n" + json.dumps(line, ensure_ascii=False).encode() + ending
    path.write_bytes(raw)
    records, digest = load_jsonl_with_digest(path, max_bytes=len(raw), max_record_bytes=len(raw))
    assert records == load_jsonl(path)
    assert records[0].text == "café 東京"
    assert digest == hashlib.sha256(raw).hexdigest()
    assert digest != hashlib.sha256(payload(records[0].text)).hexdigest()


@pytest.mark.parametrize("raw", [b"", b"\n\r\n", b"// only a comment\n"])
def test_empty_semantic_dataset_still_has_an_exact_source_commitment(tmp_path, raw):
    path = tmp_path / "empty.jsonl"
    path.write_bytes(raw)
    records, digest = load_jsonl_with_digest(path)
    assert records == []
    assert digest == hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize("argument", ["max_bytes", "max_record_bytes"])
@pytest.mark.parametrize("limit", [True, False, 0, -1, 1.5, "10"])
def test_invalid_limits_fail_before_open(tmp_path, monkeypatch, argument, limit):
    def forbidden(*args, **kwargs):
        pytest.fail("invalid limit reached filesystem open")

    monkeypatch.setattr(schema.os, "open", forbidden)
    with pytest.raises(ValueError, match="positive integers"):
        load_jsonl_with_digest(tmp_path / "missing", **{argument: limit})


def test_byte_limits_still_apply_before_a_digest_is_returned(tmp_path):
    path = tmp_path / "records.jsonl"
    raw = payload("Notes")
    path.write_bytes(raw)
    assert load_jsonl_with_digest(path, max_bytes=len(raw), max_record_bytes=len(raw))[0]
    with pytest.raises(ValueError, match="byte limit"):
        load_jsonl_with_digest(path, max_bytes=len(raw) - 1)
    with pytest.raises(ValueError, match="byte limit"):
        load_jsonl_with_digest(path, max_record_bytes=len(raw) - 1)


def test_malformed_late_record_produces_no_partial_result_or_private_error(tmp_path):
    path = tmp_path / "records.jsonl"
    path.write_bytes(payload("Notes") + b'{"private-secret":0,"private-secret":1}\n')
    with pytest.raises(ValueError, match="line 2") as error:
        load_jsonl_with_digest(path)
    assert "private-secret" not in str(error.value)
    assert error.value.__suppress_context__


def test_one_open_reads_and_hashes_the_same_bounded_lines(tmp_path, monkeypatch):
    path = tmp_path / "records.jsonl"
    raw = payload("Notes")
    path.write_bytes(raw)
    opened, requested = [], []
    original_open, original_fdopen = schema.os.open, schema.os.fdopen

    def opening(source, flags):
        opened.append((source, flags))
        return original_open(source, flags)

    class Reader:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()

        def fileno(self):
            return self.stream.fileno()

        def readline(self, size):
            requested.append(size)
            return self.stream.readline(size)

    monkeypatch.setattr(schema.os, "open", opening)
    monkeypatch.setattr(schema.os, "fdopen", lambda *args: Reader(original_fdopen(*args)))
    records, digest = load_jsonl_with_digest(path, max_bytes=len(raw), max_record_bytes=len(raw))
    assert len(records) == 1 and digest == hashlib.sha256(raw).hexdigest()
    assert len(opened) == 1
    assert requested == [len(raw) + 1, 1]
    if hasattr(os, "O_NOFOLLOW"):
        assert opened[0][1] & os.O_NOFOLLOW


def test_committed_loader_rejects_symlinks_without_changing_hub_loader(tmp_path):
    path, link = tmp_path / "blob", tmp_path / "link.jsonl"
    path.write_bytes(payload("Notes"))
    link.symlink_to(path)
    assert load_jsonl(link) == load_jsonl(path)
    with pytest.raises(ValueError, match="non-symlink"):
        load_jsonl_with_digest(link)
    parent = tmp_path / "linked-parent"
    parent.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError, match="non-symlink"):
        load_jsonl_with_digest(parent / "blob")


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFO test")
def test_nonregular_source_fails_before_open(tmp_path, monkeypatch):
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)

    def forbidden(*args):
        pytest.fail("nonregular committed dataset must not be opened")

    monkeypatch.setattr(schema.os, "open", forbidden)
    with pytest.raises(ValueError, match="regular"):
        load_jsonl_with_digest(fifo)
    with pytest.raises(ValueError, match="regular"):
        load_jsonl_with_digest(tmp_path)


def test_opened_replacement_is_rejected_before_content_read(tmp_path, monkeypatch):
    path, other = tmp_path / "source.jsonl", tmp_path / "other.jsonl"
    path.write_bytes(payload("Original notes"))
    other.write_bytes(payload("Replacement notes"))
    original_open = schema.os.open
    descriptors = []

    def substituted(source, flags):
        fd = original_open(other, flags)
        descriptors.append(fd)
        return fd

    monkeypatch.setattr(schema.os, "open", substituted)

    def forbidden(*args):
        pytest.fail("replacement must fail before content read")

    monkeypatch.setattr(schema.os, "fdopen", forbidden)
    with pytest.raises(ValueError, match="changed before reading"):
        load_jsonl_with_digest(path)
    with pytest.raises(OSError):
        os.fstat(descriptors[0])


@pytest.mark.parametrize("when", ["read", "close"])
@pytest.mark.parametrize("kind", ["rewrite", "replace"])
def test_observed_changes_abort_commitment_before_return(tmp_path, monkeypatch, when, kind):
    path = tmp_path / "source.jsonl"
    path.write_bytes(payload("Original notes"))
    initial = path.stat()
    original_fdopen = schema.os.fdopen

    def mutate():
        if kind == "rewrite":
            path.write_bytes(payload("Different data"))
        else:
            replacement = tmp_path / "replacement.jsonl"
            replacement.write_bytes(payload("Different data"))
            os.replace(replacement, path)
        os.utime(path, ns=(initial.st_atime_ns, initial.st_mtime_ns + 1_000_000_000))

    class Reader:
        def __init__(self, stream):
            self.stream = stream
            self.changed = False

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()
            if when == "close":
                mutate()

        def fileno(self):
            return self.stream.fileno()

        def readline(self, size):
            line = self.stream.readline(size)
            if when == "read" and not self.changed:
                self.changed = True
                mutate()
            return line

    monkeypatch.setattr(schema.os, "fdopen", lambda *args: Reader(original_fdopen(*args)))
    with pytest.raises(ValueError, match="changed"):
        load_jsonl_with_digest(path)


@pytest.mark.parametrize("raw", [payload("Notes") + b"not-json\n", b"", b"// only comment\n"])
def test_container_rejects_invalid_dataset_before_runtime_construction(tmp_path, monkeypatch, raw):
    from lurebench.cli import main
    from lurebench.detectors import container

    path, output = tmp_path / "source.jsonl", tmp_path / "report.json"
    path.write_bytes(raw)

    def forbidden(*args, **kwargs):
        pytest.fail("invalid source reached runtime construction")

    monkeypatch.setattr(container, "ContainerDetector", forbidden)
    assert main(["container-eval", "--dataset", str(path), "--image", "synthetic",
                 "--out", str(output)]) == 1
    assert not output.exists()
