"""A column-mapped adapter for tabular corpora (CSV / JSONL).

Most public phishing datasets are a table with a text column and a label column.
``GenericAdapter`` maps such a file into the ``Lure`` schema without writing a
bespoke adapter. Use it programmatically from a build script; wire more specific
adapters when a source needs custom parsing.

Example:

    GenericAdapter(
        source_id="greco-kaggle",
        text_col="body",
        label_col="label", label_true={"1", "phishing"},
        source="human",              # or a column name via source_col
        typology_fraud="phishing",
        generator="chatgpt",
        homepage="https://www.kaggle.com/datasets/francescogreco97/...",
    ).parse("emails.csv")
"""

from __future__ import annotations

import csv
import json
from typing import Iterator, Optional, Set

from ..schema import Lure
from .base import Adapter, defang, detokenize


class GenericAdapter(Adapter):
    def __init__(
        self,
        source_id: str,
        text_col: str,
        label_col: str,
        label_true: Set[str],
        typology_fraud: str = "phishing",
        typology_benign: str = "benign",
        source: str = "human",
        source_col: Optional[str] = None,
        generator: Optional[str] = None,
        language: str = "en",
        language_col: Optional[str] = None,
        channel: str = "email",
        detokenize: bool = False,
        homepage: str = "",
        license: str = "unknown — verify upstream",
        citation: str = "",
    ) -> None:
        self.source_id = source_id
        self._detokenize = detokenize
        self.text_col = text_col
        self.label_col = label_col
        self.label_true = {v.lower() for v in label_true}
        self.typology_fraud = typology_fraud
        self.typology_benign = typology_benign
        self._source = source
        self.source_col = source_col
        self.generator = generator
        self._language = language
        self.language_col = language_col
        self.channel = channel
        self.homepage = homepage
        self.license = license
        self.citation = citation

    def _rows(self, path: str) -> Iterator[dict]:
        if path.endswith((".jsonl", ".ndjson")):
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        yield json.loads(line)
        else:  # csv / tsv
            delimiter = "\t" if path.endswith(".tsv") else ","
            with open(path, "r", encoding="utf-8", newline="") as fh:
                yield from csv.DictReader(fh, delimiter=delimiter)

    def parse(self, path: str) -> Iterator[Lure]:
        for i, row in enumerate(self._rows(path)):
            text = (str(row.get(self.text_col, "")) or "").strip()
            if not text:
                continue
            if self._detokenize:
                text = detokenize(text)
            raw_label = str(row.get(self.label_col, "")).strip().lower()
            is_fraud = raw_label in self.label_true
            source = str(row.get(self.source_col)).strip().lower() if self.source_col else self._source
            if source not in ("ai", "human"):
                source = self._source
            language = (
                str(row.get(self.language_col, self._language)).strip().lower()[:2]
                if self.language_col
                else self._language
            )
            yield Lure(
                id=f"{self.source_id}-{i:05d}",
                text=defang(text),
                label=1 if is_fraud else 0,
                source=source,
                typology=self.typology_fraud if is_fraud else self.typology_benign,
                generator=self.generator if (is_fraud and source == "ai") else (self.generator if source == "ai" else None),
                language=language or "en",
                channel=self.channel,
                meta={"source_id": self.source_id},
            )
