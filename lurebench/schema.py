"""Dataset schema for LureBench records.

A LureBench dataset is a JSONL file with one :class:`Lure` per line. The schema
is deliberately small and provenance-aware so the same corpus supports both the
``fraud`` and ``provenance`` evaluation tasks.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, List, Optional

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
        if self.label not in (0, 1):
            raise ValueError(f"{self.id}: label must be 0 or 1, got {self.label!r}")
        if self.source not in SOURCES:
            raise ValueError(f"{self.id}: source must be one of {sorted(SOURCES)}, got {self.source!r}")
        if self.typology not in TYPOLOGIES:
            raise ValueError(f"{self.id}: typology must be one of {sorted(TYPOLOGIES)}, got {self.typology!r}")
        if self.channel not in CHANNELS:
            raise ValueError(f"{self.id}: channel must be one of {sorted(CHANNELS)}, got {self.channel!r}")
        # A benign record must not be labelled as a fraud lure, and vice versa.
        if self.typology == "benign" and self.label != 0:
            raise ValueError(f"{self.id}: typology 'benign' requires label 0")
        if self.typology != "benign" and self.label != 1:
            raise ValueError(f"{self.id}: fraud typology {self.typology!r} requires label 1")

    @classmethod
    def from_dict(cls, d: dict) -> "Lure":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})

    def to_dict(self) -> dict:
        return asdict(self)


def load_jsonl(path: str | Path) -> List[Lure]:
    """Load a JSONL dataset into a list of :class:`Lure`."""
    records: List[Lure] = []
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            try:
                records.append(Lure.from_dict(json.loads(line)))
            except (json.JSONDecodeError, ValueError, TypeError) as exc:
                raise ValueError(f"{path}:{lineno}: {exc}") from exc
    return records


def save_jsonl(records: Iterable[Lure], path: str | Path) -> None:
    """Write an iterable of :class:`Lure` to JSONL."""
    with open(path, "w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec.to_dict(), ensure_ascii=False) + "\n")


def iter_jsonl(path: str | Path) -> Iterator[Lure]:
    """Stream a JSONL dataset without loading it all into memory."""
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("//"):
                yield Lure.from_dict(json.loads(line))
