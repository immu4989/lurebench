"""Input limits must constrain I/O, not only reject a fully allocated payload."""

import os
from pathlib import Path

import pytest

from lurebench import mandate


def read_small(path, monkeypatch):
    monkeypatch.setattr(mandate, "MAX_DOCUMENT_BYTES", 64)
    return mandate._read(path, "test")


@pytest.mark.parametrize("size", [0, 65, 1024 * 1024 * 1024])
def test_invalid_size_is_rejected_before_stream_allocation(tmp_path, monkeypatch, size):
    path = tmp_path / "input.json"
    with path.open("wb") as stream:
        stream.truncate(size)  # Sparse file: no large allocation in the test.

    def unexpected_stream(*args, **kwargs):
        pytest.fail("invalid-size file must not be read")

    monkeypatch.setattr(mandate.os, "fdopen", unexpected_stream)
    with pytest.raises(ValueError, match="bounded size"):
        read_small(path, monkeypatch)


def test_valid_input_uses_bounded_read(tmp_path, monkeypatch):
    path = tmp_path / "input.json"
    path.write_bytes(b"x" * 64)
    original = os.fdopen
    requested = []

    class Reader:
        def __init__(self, descriptor, mode):
            self.stream = original(descriptor, mode)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()

        def read(self, size):
            requested.append(size)
            return self.stream.read(size)

    monkeypatch.setattr(mandate.os, "fdopen", Reader)
    assert read_small(path, monkeypatch) == b"x" * 64
    assert requested == [65]


def test_growth_after_stat_is_bounded_and_rejected(tmp_path, monkeypatch):
    path = tmp_path / "input.json"
    path.write_bytes(b"x")
    original = os.fstat

    def grow_after_stat(descriptor):
        metadata = original(descriptor)
        with path.open("ab") as stream:
            stream.write(b"x" * 100)
        return metadata

    monkeypatch.setattr(mandate.os, "fstat", grow_after_stat)
    with pytest.raises(ValueError):
        read_small(path, monkeypatch)


def test_binary_source_bytes_are_not_newline_or_eof_translated(tmp_path, monkeypatch):
    path = tmp_path / "input.json"
    payload = b'{"line":1}\r\n\x1a\r\n'
    path.write_bytes(payload)
    assert read_small(path, monkeypatch) == payload


def test_generated_document_cannot_exceed_its_loader_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(mandate, "MAX_DOCUMENT_BYTES", 4)
    path = tmp_path / "output.json"
    with pytest.raises(ValueError, match="input limit"):
        mandate._write(path, {"too": "large"})
    assert not path.exists()


def test_descriptor_is_closed_after_stat_failure(tmp_path, monkeypatch):
    path = tmp_path / "input.json"
    path.write_bytes(b"x")
    original = os.fstat
    opened = []

    def fail_stat(descriptor):
        opened.append(descriptor)
        raise OSError("injected stat failure")

    monkeypatch.setattr(mandate.os, "fstat", fail_stat)
    with pytest.raises(OSError, match="injected"):
        read_small(path, monkeypatch)
    assert len(opened) == 1
    with pytest.raises(OSError):
        original(opened[0])


def test_symlink_is_not_followed(tmp_path, monkeypatch):
    source = tmp_path / "source.json"
    source.write_bytes(b"secret")
    link = tmp_path / "link.json"
    link.symlink_to(source)
    with pytest.raises(ValueError, match="non-symlink"):
        read_small(link, monkeypatch)


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="requires O_NOFOLLOW")
def test_replacement_with_symlink_before_open_is_rejected(tmp_path, monkeypatch):
    source = tmp_path / "input.json"
    source.write_bytes(b"safe")
    other = tmp_path / "other.json"
    other.write_bytes(b"secret")
    original = os.open

    def replace_then_open(path, flags):
        Path(path).unlink()
        Path(path).symlink_to(other)
        return original(path, flags)

    monkeypatch.setattr(mandate.os, "open", replace_then_open)
    with pytest.raises(OSError):
        read_small(source, monkeypatch)
