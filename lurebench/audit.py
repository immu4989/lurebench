"""Cross-split leakage audit using dependency-free word-shingle similarity."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Dict, List, Sequence, Set, Tuple

from .schema import Lure

_WORD = re.compile(r"[\w']+", re.UNICODE)


def shingles(text: str, size: int = 5) -> Set[str]:
    words = _WORD.findall(text.casefold())
    if len(words) < size:
        return {" ".join(words)} if words else set()
    return {" ".join(words[i:i + size]) for i in range(len(words) - size + 1)}


def jaccard(left: Set[str], right: Set[str]) -> float:
    union = left | right
    return len(left & right) / len(union) if union else 1.0


def family_id(record: Lure) -> str:
    """Return an explicit lineage id when a shard supplies one, else the record id."""
    for key in ("family_id", "scenario_id", "parent_id", "seed_id"):
        value = record.meta.get(key)
        if value:
            return str(value)
    return record.id


@dataclass(frozen=True)
class LeakagePair:
    left_split: str
    left_id: str
    right_split: str
    right_id: str
    similarity: float


@dataclass
class LeakageAudit:
    threshold: float
    shingle_size: int
    split_sizes: Dict[str, int]
    family_overlaps: List[Tuple[str, str, str]]
    near_duplicates: List[LeakagePair]

    @property
    def passed(self) -> bool:
        return not self.family_overlaps and not self.near_duplicates

    def as_dict(self) -> dict:
        value = asdict(self)
        value["passed"] = self.passed
        return value


def audit_splits(
    splits: Dict[str, Sequence[Lure]], threshold: float = 0.8, shingle_size: int = 5
) -> LeakageAudit:
    """Find explicit-family overlap and near-duplicate text across split boundaries.

    An inverted shingle index limits comparisons to pairs sharing at least one
    shingle, avoiding a full quadratic scan for ordinary corpora.
    """
    if not 0.0 <= threshold <= 1.0:
        raise ValueError("threshold must be between 0 and 1")
    prepared: Dict[str, List[Tuple[Lure, Set[str]]]] = {
        name: [(record, shingles(record.text, shingle_size)) for record in records]
        for name, records in splits.items()
    }
    owners: Dict[str, str] = {}
    overlaps: Set[Tuple[str, str, str]] = set()
    for split, records in splits.items():
        for record in records:
            fid = family_id(record)
            previous = owners.setdefault(fid, split)
            if previous != split:
                overlaps.add((fid, previous, split))

    pairs: List[LeakagePair] = []
    names = list(splits)
    for i, left_name in enumerate(names):
        for right_name in names[i + 1:]:
            index: Dict[str, Set[int]] = {}
            for idx, (_, tokens) in enumerate(prepared[right_name]):
                for token in tokens:
                    index.setdefault(token, set()).add(idx)
            seen: Set[Tuple[int, int]] = set()
            for left_idx, (left, left_tokens) in enumerate(prepared[left_name]):
                candidates: Set[int] = set()
                for token in left_tokens:
                    candidates.update(index.get(token, ()))
                for right_idx in candidates:
                    key = (left_idx, right_idx)
                    if key in seen:
                        continue
                    seen.add(key)
                    right, right_tokens = prepared[right_name][right_idx]
                    similarity = jaccard(left_tokens, right_tokens)
                    if similarity >= threshold:
                        pairs.append(LeakagePair(
                            left_name, left.id, right_name, right.id, round(similarity, 6)
                        ))
    pairs.sort(key=lambda pair: (-pair.similarity, pair.left_id, pair.right_id))
    return LeakageAudit(
        threshold=threshold,
        shingle_size=shingle_size,
        split_sizes={name: len(records) for name, records in splits.items()},
        family_overlaps=sorted(overlaps),
        near_duplicates=pairs,
    )
