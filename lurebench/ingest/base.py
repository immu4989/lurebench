"""Ingestion base: adapters normalize an external corpus into ``Lure`` records.

An adapter reads a **locally-downloaded** source file and yields schema-valid
``Lure`` objects. Adapters never fetch or re-host source data; redistribution is
governed by each source's license (see ``docs/sources.md``).

Shared helpers here handle the two things every adapter needs: defanging and
normalized-hash deduplication.
"""

from __future__ import annotations

import hashlib
import re
from abc import ABC, abstractmethod
from typing import Iterable, Iterator, List

from ..schema import Lure

_HTML_RE = re.compile(r"(?<!<)<(?!<)[^<>]{1,80}>(?!>)")  # HTML tags, but not our <<placeholders>>
_URL_RE = re.compile(r"(https?://\S+|www\.\S+)", re.I)
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_MSG_HANDLE_RE = re.compile(r"(t\.me/\S+|wa\.me/\S+|whatsapp:\s*\S+|telegram:\s*\S+)", re.I)
# Bare domains (no scheme) with a recognizable TLD — catches "Mail.com", "evil.ru".
_BARE_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|info|biz|io|co|ru|cn|xyz|top|link|click|us|uk|de|fr|online|site|shop|app)\b",
    re.I,
)
_PHONE_RE = re.compile(r"(?<!\w)\+?\d[\d\s().-]{8,}\d(?!\w)")


def defang(text: str) -> str:
    """Replace links and contact hand-offs with placeholders. Idempotent.

    Order matters: strip HTML first, then full URLs, then emails (which contain a
    domain) before bare domains, so ``user@evil.com`` becomes ``<<contact>>`` rather
    than ``user@<<link>>``.
    """
    text = _HTML_RE.sub(" ", text)
    text = _URL_RE.sub("<<link>>", text)
    text = _EMAIL_RE.sub("<<contact>>", text)
    text = _MSG_HANDLE_RE.sub("<<contact>>", text)
    text = _BARE_DOMAIN_RE.sub("<<link>>", text)
    text = _PHONE_RE.sub("<<contact>>", text)
    return text


_TLDS = "com|net|org|info|biz|io|co|ru|cn|xyz|top|link|click|us|uk|de|fr|online|site|shop|app"
_SPACED_SCHEME_RE = re.compile(r"\b(https?)\s*:\s*/\s*/\s*", re.I)
_SPACED_DOMAIN_RE = re.compile(rf"\b([a-z0-9-]+)\s+\.\s+(?=(?:{_TLDS})\b)", re.I)
_SPACE_BEFORE_PUNCT_RE = re.compile(r"\s+([.,;:!?%)\]}])")
_SPACE_AFTER_OPEN_RE = re.compile(r"([(\[{])\s+")
_MULTISPACE_RE = re.compile(r"[ \t]{2,}")


def detokenize(text: str) -> str:
    """Restore natural prose from pre-tokenized text (spaces around punctuation).

    Some public corpora ship tokenized ("word . com", "http : / /") — a spacing
    style that is itself a human-vs-AI tell and that splits URLs so defang misses
    them. This rejoins schemes/domains and removes spaces before punctuation.
    Bounded to TLD-suffixed tokens so legit words ("net income") are untouched.
    """
    text = _SPACED_SCHEME_RE.sub(r"\1://", text)
    text = _SPACED_DOMAIN_RE.sub(r"\1.", text)
    text = _SPACE_BEFORE_PUNCT_RE.sub(r"\1", text)
    text = _SPACE_AFTER_OPEN_RE.sub(r"\1", text)
    text = _MULTISPACE_RE.sub(" ", text)
    return text


def norm_key(text: str) -> str:
    """Whitespace/case-normalized SHA1 used for cross-source dedup."""
    normalized = re.sub(r"\s+", " ", text.lower()).strip()
    return hashlib.sha1(normalized.encode("utf-8")).hexdigest()


def dedupe(records: Iterable[Lure]) -> List[Lure]:
    """Drop later records whose normalized text was already seen."""
    seen: set[str] = set()
    out: List[Lure] = []
    for rec in records:
        key = norm_key(rec.text)
        if key in seen:
            continue
        seen.add(key)
        out.append(rec)
    return out


class Adapter(ABC):
    #: Short id stamped into ``meta.source_id`` on every emitted record.
    source_id: str = "adapter"
    homepage: str = ""
    license: str = "unknown — verify upstream"
    citation: str = ""

    @abstractmethod
    def parse(self, path: str) -> Iterator[Lure]:
        """Yield schema-valid, defanged ``Lure`` records from a local file."""
        raise NotImplementedError
