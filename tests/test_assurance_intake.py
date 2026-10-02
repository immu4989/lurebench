"""External assurance inputs share bounded regular-file intake, not stat/read races."""

import os
from pathlib import Path

import pytest

from lurebench import boundary, conformance, coverage, incident_response, invariant

READERS = [
    invariant._read, coverage._read, incident_response._read, boundary._read_suite,
    lambda path: conformance._read_external(path.parent, path.name, 4 * 1024 * 1024),
]


@pytest.mark.parametrize("reader", READERS)
def test_assurance_reads_do_not_use_unbounded_path_read_bytes(tmp_path, monkeypatch, reader):
    source = tmp_path / "evidence.json"
    source.write_bytes(b"{}")
    monkeypatch.setattr(Path, "read_bytes", lambda *a: pytest.fail("unbounded read"))
    assert reader(source) == b"{}"


@pytest.mark.parametrize("reader", READERS)
@pytest.mark.parametrize("kind", ["symlink", "fifo", "oversized"])
def test_external_assurance_rejects_unsafe_sources_before_content_read(tmp_path, monkeypatch, reader, kind):
    from lurebench import local_io

    source = tmp_path / "evidence.json"
    if kind == "symlink":
        target = tmp_path / "target"
        target.write_bytes(b"{}")
        source.symlink_to(target)
    elif kind == "fifo":
        if not hasattr(os, "mkfifo"):
            pytest.skip("POSIX FIFO")
        os.mkfifo(source)
    else:
        source.write_bytes(b"x" * (4 * 1024 * 1024 + 1))
    monkeypatch.setattr(local_io.os, "fdopen", lambda *a, **kw: pytest.fail("content read"))
    with pytest.raises(ValueError):
        reader(source)
