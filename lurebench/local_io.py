"""Bounded reads of local evidence; callers must trust parent directories.

No claim of an atomic filesystem snapshot. O_NOFOLLOW/O_NONBLOCK are used
where available, and opened objects are checked before any content read.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path


def _identity(info: os.stat_result) -> tuple:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def read_regular_file(
    path: Path, *, maximum: int, label: str = "evidence",
    private: bool = False, allow_empty: bool = False,
) -> bytes:
    """Read at most maximum+1 bytes and reject observed source changes."""
    if type(maximum) is not int or maximum < 1:
        raise ValueError("file byte limit must be a positive integer")
    source = Path(path)
    before = source.lstat()
    if not stat.S_ISREG(before.st_mode) or source.parent.is_symlink():
        raise ValueError(f"{label} must be a regular non-symlink local file")
    fd = os.open(
        source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0),
    )
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or _identity(opened) != _identity(before):
            raise ValueError(f"{label} changed or is not a regular file")
        if private and os.name == "posix" and opened.st_mode & 0o077:
            raise ValueError(f"{label} must not grant group or world access")
        minimum = 0 if allow_empty else 1
        if not minimum <= opened.st_size <= maximum:
            raise ValueError(f"{label} exceeds its bounded size")
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            payload = stream.read(maximum + 1)
            if (
                not minimum <= len(payload) <= maximum
                or len(payload) != opened.st_size
                or _identity(os.fstat(stream.fileno())) != _identity(opened)
            ):
                raise ValueError(f"{label} changed or exceeds its bounded size")
        if _identity(source.lstat()) != _identity(opened):
            raise ValueError(f"{label} path changed during reading")
        return payload
    finally:
        if fd >= 0:
            os.close(fd)
