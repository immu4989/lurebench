import os
from pathlib import Path

import pytest

from lurebench import local_io


def test_exact_limit_and_empty_policy(tmp_path):
    path = tmp_path / "evidence"
    path.write_bytes(b"1234")
    assert local_io.read_regular_file(path, maximum=4) == b"1234"
    with pytest.raises(ValueError, match="bounded"):
        local_io.read_regular_file(path, maximum=3)
    path.write_bytes(b"")
    with pytest.raises(ValueError):
        local_io.read_regular_file(path, maximum=4)
    assert local_io.read_regular_file(path, maximum=4, allow_empty=True) == b""


@pytest.mark.parametrize("maximum", [True, 1.0, 0, -1, None])
def test_invalid_limit_rejected_before_source_access(tmp_path, maximum):
    with pytest.raises(ValueError, match="positive integer"):
        local_io.read_regular_file(tmp_path / "missing", maximum=maximum)


def test_oversize_rejected_before_fdopen(tmp_path, monkeypatch):
    path = tmp_path / "evidence"
    path.write_bytes(b"12345")

    def forbidden(*args, **kwargs):
        raise AssertionError("oversized source must not be read")

    monkeypatch.setattr(local_io.os, "fdopen", forbidden)
    with pytest.raises(ValueError, match="bounded"):
        local_io.read_regular_file(path, maximum=4)


@pytest.mark.parametrize("kind", ["symlink", "directory", "fifo"])
def test_nonregular_rejected(tmp_path, kind):
    path = tmp_path / "evidence"
    if kind == "symlink":
        target = tmp_path / "target"
        target.write_bytes(b"x")
        path.symlink_to(target)
    elif kind == "fifo":
        if not hasattr(os, "mkfifo"):
            pytest.skip("POSIX FIFO")
        os.mkfifo(path)
    else:
        path.mkdir()
    with pytest.raises(ValueError, match="regular"):
        local_io.read_regular_file(path, maximum=10)


def test_symlink_parent_rejected(tmp_path):
    root = tmp_path / "actual"
    root.mkdir()
    (root / "evidence").write_bytes(b"x")
    alias = tmp_path / "alias"
    alias.symlink_to(root, target_is_directory=True)
    with pytest.raises(ValueError, match="regular"):
        local_io.read_regular_file(alias / "evidence", maximum=10)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_private_permissions_checked_on_opened_file(tmp_path):
    path = tmp_path / "key"
    path.write_bytes(b"secret")
    path.chmod(0o644)
    with pytest.raises(ValueError, match="group or world"):
        local_io.read_regular_file(path, maximum=10, private=True)
    path.chmod(0o600)
    assert local_io.read_regular_file(path, maximum=10, private=True) == b"secret"


def test_fdopen_failure_closes_descriptor(tmp_path, monkeypatch):
    path = tmp_path / "evidence"
    path.write_bytes(b"x")
    original_close = os.close
    closed = []

    def close(fd):
        closed.append(fd)
        original_close(fd)

    def fail(*args, **kwargs):
        raise OSError("injected fdopen failure")

    monkeypatch.setattr(local_io.os, "close", close)
    monkeypatch.setattr(local_io.os, "fdopen", fail)
    with pytest.raises(OSError, match="injected"):
        local_io.read_regular_file(path, maximum=10)
    assert len(closed) == 1
    with pytest.raises(OSError):
        os.fstat(closed[0])


@pytest.mark.parametrize("mutation", ["grow", "shrink", "replace"])
def test_mutating_file_rejected_and_read_is_bounded(tmp_path, monkeypatch, mutation):
    path = tmp_path / "evidence"
    path.write_bytes(b"1234")
    original_fdopen = os.fdopen
    requests = []

    class Stream:
        def __init__(self, fd, mode):
            self.inner = original_fdopen(fd, mode)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.inner.close()

        def fileno(self):
            return self.inner.fileno()

        def read(self, amount):
            requests.append(amount)
            if mutation == "replace":
                replacement = tmp_path / "replacement"
                replacement.write_bytes(b"1234")
                replacement.replace(path)
            else:
                path.write_bytes(b"x" * (100 if mutation == "grow" else 1))
            return self.inner.read(amount)

    monkeypatch.setattr(local_io.os, "fdopen", Stream)
    with pytest.raises(ValueError, match="changed|bounded"):
        local_io.read_regular_file(path, maximum=8)
    assert requests == [9]


@pytest.mark.skipif(not hasattr(os, "O_NONBLOCK") or not hasattr(os, "mkfifo"),
                    reason="POSIX nonblocking FIFO")
def test_regular_path_replaced_with_fifo_before_open_does_not_block(tmp_path, monkeypatch):
    path = tmp_path / "evidence"
    path.write_bytes(b"x")
    original_open = os.open

    def replace(source, flags):
        path.unlink()
        os.mkfifo(path)
        assert flags & os.O_NONBLOCK
        return original_open(source, flags)

    monkeypatch.setattr(local_io.os, "open", replace)
    with pytest.raises(ValueError, match="regular"):
        local_io.read_regular_file(path, maximum=10)


def test_does_not_delegate_to_unbounded_path_read_bytes(tmp_path, monkeypatch):
    path = tmp_path / "evidence"
    path.write_bytes(b"bounded")

    def forbidden(*args):
        raise AssertionError("unbounded read_bytes is forbidden")

    monkeypatch.setattr(Path, "read_bytes", forbidden)
    assert local_io.read_regular_file(path, maximum=7) == b"bounded"


@pytest.mark.parametrize("module_name,function_name,bound", [
    ("permit", "_read_json", "MAX_ARTIFACT_BYTES"),
    ("identity", "_read", "MAX_BYTES"),
    ("revocation", "_read", "MAX_BYTES"),
    ("runtime", "_read_json", "MAX_RUNTIME_BYTES"),
    ("bom", "_read_bytes", "MAX_DOCUMENT_BYTES"),
    ("channel", "_read", "MAX_DOCUMENT_BYTES"),
    ("recall", "_read", "MAX_BYTES"),
])
def test_protocol_readers_reject_before_allocation(
    tmp_path, monkeypatch, module_name, function_name, bound,
):
    import importlib

    module = importlib.import_module(f"lurebench.{module_name}")
    monkeypatch.setattr(module, bound, 4)
    source = tmp_path / "oversize.json"
    source.write_bytes(b"12345")

    def forbidden(*args, **kwargs):
        raise AssertionError("oversize protocol input must never be read")

    monkeypatch.setattr(local_io.os, "fdopen", forbidden)
    with pytest.raises(ValueError, match="bounded"):
        getattr(module, function_name)(source, "test evidence")


def test_receipt_hash_preserves_empty_file_support(tmp_path):
    import hashlib

    from lurebench.receipts import sha256_file

    path = tmp_path / "empty"
    path.write_bytes(b"")
    assert sha256_file(path) == hashlib.sha256(b"").hexdigest()
