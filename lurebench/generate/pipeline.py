"""Generation pipeline: raw text -> defanged, provenance-logged, review-pending Lure.

Enforces the controlled-generation protocol regardless of engine:
  1. defang every text (URLs/contacts -> placeholders),
  2. validate against the schema,
  3. stamp provenance (meta.generation) and a review status,
  4. screen for anything that must go to a human before release.

Nothing here approves data. Records land as ``review: "pending"`` (or ``"flagged"``);
only :func:`promote` (called after a human sets ``"approved"``) yields shard-ready rows.
"""

from __future__ import annotations

import re
from typing import List, Sequence, Tuple

from ..ingest.base import defang, dedupe
from ..schema import Lure
from .base import GenerationSpec, Generator

# Signals that a record must not auto-release: any live-looking link/contact that
# survived defang, or an over-long message that may carry more than a lure should.
_LIVE_URL = re.compile(r"https?://|www\.", re.I)
_LIVE_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_LIVE_PHONE = re.compile(r"(?<!\w)\+?\d[\d\s().-]{8,}\d(?!\w)")
_MAX_TOKENS = 400


def generate_records(
    generator: Generator,
    spec: GenerationSpec,
    n: int,
    start_index: int = 0,
) -> List[Lure]:
    """Run an engine and normalize its output into review-pending ``Lure`` records."""
    spec.validate()
    texts = generator.generate(spec, n)
    records: List[Lure] = []
    for i, raw in enumerate(texts):
        text = defang((raw or "").strip())
        if not text:
            continue
        records.append(
            Lure(
                id=f"gen-{spec.typology}-{start_index + i:06d}",
                text=text,
                label=1,
                source="ai",
                typology=spec.typology,
                generator=spec.generator,
                language=spec.language,
                channel=spec.channel,
                persuasion=list(spec.persuasion),
                meta={
                    "source_id": "controlled-generation",
                    "generation": {"engine": generator.name, "spec": spec.as_meta()},
                    "review": "pending",
                },
            )
        )
    return dedupe(records)


def screen(records: Sequence[Lure]) -> Tuple[List[Lure], List[Lure]]:
    """Split records into (clean-pending, flagged-for-human) per protocol step 3.

    A flagged record has its ``meta.review`` set to ``"flagged"`` and a reason.
    Flagging is conservative: it routes to a human, it does not delete.
    """
    clean: List[Lure] = []
    flagged: List[Lure] = []
    for rec in records:
        reasons = []
        if _LIVE_URL.search(rec.text):
            reasons.append("undefanged url")
        if _LIVE_EMAIL.search(rec.text):
            reasons.append("undefanged email")
        if _LIVE_PHONE.search(rec.text):
            reasons.append("phone-like number")
        if len(rec.text.split()) > _MAX_TOKENS:
            reasons.append("over-length")
        if reasons:
            rec.meta["review"] = "flagged"
            rec.meta["review_reasons"] = reasons
            flagged.append(rec)
        else:
            clean.append(rec)
    return clean, flagged


def promote(records: Sequence[Lure]) -> List[Lure]:
    """Return only human-approved records (``meta.review == "approved"``)."""
    return [r for r in records if r.meta.get("review") == "approved"]
