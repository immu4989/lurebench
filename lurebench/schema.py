"""Dataset schema for LureBench records.

A LureBench dataset is a JSONL file with one :class:`Lure` per line. The schema
is deliberately small and provenance-aware so the same corpus supports both the
``fraud`` and ``provenance`` evaluation tasks.
"""

from __future__ import annotations

import json
import os
import stat
import tempfile
from dataclasses import asdict, dataclass, field
from numbers import Integral
from pathlib import Path
from typing import Iterable, Iterator, List, Optional

from .receipts import loads_strict_json

MAX_DATASET_BYTES = 256 * 1024 * 1024
# Historical public phishtext shards contain individual records above 16 MiB.
# Preserve intake compatibility while making the allocation ceiling explicit.
MAX_RECORD_BYTES = 32 * 1024 * 1024

# Fraud typologies covered by the benchmark. ``benign`` records are the negative
# class for the fraud-detection task.
TYPOLOGIES = {"phishing", "bec", "romance", "pig_butchering", "benign"}

# Provenance of the text.
SOURCES = {"ai", "human"}

# Delivery channel the lure imitates.
CHANNELS = {"email", "sms", "chat", "social", "voice_transcript"}


@dataclass
class Lure:
    """A single benchmark record.

    Attributes:
        id: Stable unique identifier (e.g. ``lb-000123``).
        text: The message text. Fraud samples are defanged (URLs replaced with
            ``<<link>>``, contacts with ``<<contact>>``) — see DATA.md.
        label: ``1`` for a fraud lure, ``0`` for benign. Target of the ``fraud`` task.
        source: ``ai`` or ``human``. Target of the ``provenance`` task.
        typology: One of :data:`TYPOLOGIES`.
        generator: Model id for AI text (e.g. ``gpt-4o``, ``deepseek-v3``), else ``None``.
        language: ISO 639-1 code.
        channel: One of :data:`CHANNELS`.
        persuasion: Cialdini-style persuasion tags (``urgency``, ``authority`` ...).
        meta: Free-form provenance/annotation metadata.
    """

    id: str
    text: str
    label: int
    source: str
    typology: str
    generator: Optional[str] = None
    language: str = "en"
    channel: str = "email"
    persuasion: List[str] = field(default_factory=list)
    meta: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("id", "text", "source", "typology", "language", "channel"):
            value = getattr(self, name)
            if not isinstance(value, str) or any(0xD800 <= ord(c) <= 0xDFFF for c in value):
                raise ValueError(f"{name} must be a Unicode string without lone surrogates")
        if not 1 <= len(self.id) <= 512 or any(ord(c) < 32 or ord(c) == 127 for c in self.id):
            raise ValueError("id must be a nonempty bounded string without controls")
        if not self.language:
            raise ValueError("language must be a nonempty string")
        if self.generator is not None and (not isinstance(self.generator, str)
                                          or not self.generator):
            raise ValueError("generator must be a nonempty string or None")
        if not isinstance(self.meta, dict):
            raise ValueError("meta must be an object")
        if not isinstance(self.persuasion, list) or any(not isinstance(tag, str) for tag in self.persuasion):
            raise ValueError("persuasion must be a list of strings")
        if isinstance(self.label, bool) or not isinstance(self.label, Integral) or self.label not in (0, 1):
            raise ValueError("label must be the integer 0 or 1, not a coerced value")
        self.label = int(self.label)
        if self.source not in SOURCES:
            raise ValueError("source must be ai or human")
        if self.typology not in TYPOLOGIES:
            raise ValueError("typology must be a supported fraud category or benign")
        if self.channel not in CHANNELS:
            raise ValueError("channel must be a supported delivery channel")
        # A benign record must not be labelled as a fraud lure, and vice versa.
        if self.typology == "benign" and self.label != 0:
            raise ValueError("typology 'benign' requires label 0")
        if self.typology != "benign" and self.label != 1:
            raise ValueError("fraud typology requires label 1")

    @classmethod
    def from_dict(cls, d: dict) -> "Lure":
        if not isinstance(d, dict):
            raise ValueError("record must be a JSON object")
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})

    def to_dict(self) -> dict:
        return asdict(self)


def load_jsonl(path: str | Path, *, max_bytes: int = MAX_DATASET_BYTES,
               max_record_bytes: int = MAX_RECORD_BYTES) -> List[Lure]:
    """Load a JSONL dataset into a list of :class:`Lure`."""
    return list(iter_jsonl(path, max_bytes=max_bytes, max_record_bytes=max_record_bytes))


def save_jsonl(records: Iterable[Lure], path: str | Path, *, max_bytes: int = MAX_DATASET_BYTES,
               max_record_bytes: int = MAX_RECORD_BYTES) -> None:
    """Atomically replace a dataset only after every record passes strict intake.

    Parent directories must be trusted; this is not a multi-writer transaction.
    """
    if any(type(limit) is not int or limit < 1 for limit in (max_bytes, max_record_bytes)):
        raise ValueError("dataset and record byte limits must be positive integers")
    destination = Path(path)
    if destination.is_symlink() or destination.parent.is_symlink():
        raise ValueError("dataset output must not be a symlink")
    if destination.exists() and not stat.S_ISREG(destination.stat().st_mode):
        raise ValueError("dataset output must be a regular file")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=destination.parent,
                                         prefix=".lure-dataset-", delete=False) as fh:
            temporary = Path(fh.name)
            total = 0
            for rec in records:
                # Dataclasses are mutable; validate again at the output boundary.
                checked = Lure.from_dict(rec.to_dict())
                line = (json.dumps(checked.to_dict(), ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
                total += len(line)
                if len(line) > max_record_bytes or total > max_bytes:
                    raise ValueError("dataset output exceeds a byte limit")
                loads_strict_json(line)  # reject ambiguous coerced metadata keys/depth
                fh.write(line)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temporary, destination)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def iter_jsonl(path: str | Path, *, max_bytes: int = MAX_DATASET_BYTES,
               max_record_bytes: int = MAX_RECORD_BYTES) -> Iterator[Lure]:
    """Stream bounded strict JSONL from an opened regular file.

    Local symlinks are allowed for Hub-cache compatibility; this is not the
    stronger non-symlink evidence-artifact trust boundary. Finish iteration to
    check the complete input before using it for expensive evaluation.
    """
    if any(type(limit) is not int or limit < 1 for limit in (max_bytes, max_record_bytes)):
        raise ValueError("dataset and record byte limits must be positive integers")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    try:
        initial = os.fstat(fd)
        if not stat.S_ISREG(initial.st_mode) or initial.st_size > max_bytes:
            raise ValueError("dataset must be a regular file within the byte limit")
        with os.fdopen(fd, "rb") as fh:
            fd = -1
            total = lineno = 0
            while True:
                line = fh.readline(min(max_record_bytes, max_bytes - total) + 1)
                if not line:
                    break
                total += len(line)
                lineno += 1
                if len(line) > max_record_bytes or total > max_bytes:
                    raise ValueError(f"dataset line {lineno} exceeds a byte limit")
                try:
                    stripped = line.decode("utf-8").strip()
                    if stripped and not stripped.startswith("//"):
                        yield Lure.from_dict(loads_strict_json(stripped.encode("utf-8")))
                except (ValueError, TypeError):
                    # Do not echo labels, nested metadata keys, or message text.
                    raise ValueError(f"dataset line {lineno} is not a valid Lure record") from None
            final = os.fstat(fh.fileno())
            if (total != initial.st_size or final.st_size != initial.st_size
                    or final.st_mtime_ns != initial.st_mtime_ns
                    or final.st_ctime_ns != initial.st_ctime_ns):
                raise ValueError("dataset changed during iteration")
    finally:
        if fd >= 0:
            os.close(fd)
