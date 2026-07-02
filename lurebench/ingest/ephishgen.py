"""Adapter for the E-PhishGen / E-PhishLLM corpus (Pajola et al., ACM AISec 2025).

Source format (``ephishLLM.json``) is a list of objects:

    {"Subject": "...", "Body": "...", "type": 0|1, "Language": "en"|"it"}

where ``type`` is ``1`` for phishing and ``0`` for legitimate. All records are
LLM-generated, so provenance is ``ai``.

Repository: https://github.com/pajola/e-phishGen  (verify LICENSE before release)
"""

from __future__ import annotations

import json
from typing import Iterator

from ..schema import Lure
from .base import Adapter, defang


class EPhishGenAdapter(Adapter):
    source_id = "ephishgen"
    homepage = "https://github.com/pajola/e-phishGen"
    license = "see repository LICENSE — verify before redistribution"
    citation = "Pajola et al., E-PhishGen: Unlocking Novel Research in Phishing Email Detection, ACM AISec 2025"

    def __init__(self, generator: str = "ephishgen-llm") -> None:
        self.generator = generator

    def parse(self, path: str) -> Iterator[Lure]:
        with open(path, "r", encoding="utf-8") as fh:
            rows = json.load(fh)
        for i, row in enumerate(rows):
            subject = (row.get("Subject") or "").strip()
            body = (row.get("Body") or "").strip()
            text = f"{subject}\n\n{body}".strip() if subject else body
            if not text:
                continue
            is_phish = int(row.get("type", 1)) == 1
            language = (row.get("Language") or "en").strip().lower()[:2] or "en"
            yield Lure(
                id=f"ephishgen-{i:05d}",
                text=defang(text),
                label=1 if is_phish else 0,
                source="ai",
                typology="phishing" if is_phish else "benign",
                generator=self.generator,
                language=language,
                channel="email",
                meta={"source_id": self.source_id},
            )
