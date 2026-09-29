"""Cross-split leakage audit using dependency-free word-shingle similarity."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Dict, List, Sequence, Set, Tuple

from .lineage import LINEAGE_FIELDS, lineage_components
from .probability import validate_threshold
from .schema import Lure

_WORD = re.compile(r"[\w']+", re.UNICODE)


def shingles(text: str, size: int = 5) -> Set[str]:
    if type(size) is not int or not 1 <= size <= 20:
        raise ValueError("shingle size must be an integer between 1 and 20")
    words = _WORD.findall(text.casefold())
    if len(words) < size:
        return {" ".join(words)} if words else set()
    return {" ".join(words[i:i + size]) for i in range(len(words) - size + 1)}


def jaccard(left: Set[str], right: Set[str]) -> float:
    union = left | right
    return len(left & right) / len(union) if union else 1.0


def family_id(record: Lure) -> str:
    """Return an explicit lineage id when a shard supplies one, else the record id."""
    for key in LINEAGE_FIELDS:
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
    threshold = validate_threshold(threshold)
    # Validate even for empty splits, before the per-record shingling loop.
    shingles("", shingle_size)
    if len(splits) < 2 or any(not isinstance(name, str) or not name.strip() for name in splits):
        raise ValueError("audit requires at least two named splits")
    prepared: Dict[str, List[Tuple[Lure, Set[str]]]] = {
        name: [(record, shingles(record.text, shingle_size)) for record in records]
        for name, records in splits.items()
    }
    owners: Dict[str, Set[str]] = {}
    overlaps: Set[Tuple[str, str, str]] = set()
    # A repeated ID across splits is itself leakage; retain one representative
    # only for component construction, while checking all declarations below.
    unique = {}
    for records in splits.values():
        for record in records:
            previous = unique.get(record.id)
            if previous is not None and any(previous.meta.get(key) != record.meta.get(key)
                                            for key in LINEAGE_FIELDS):
                raise ValueError("repeated record ID has conflicting lineage annotations")
            unique.setdefault(record.id, record)
    components = lineage_components(list(unique.values()))
    for split, records in splits.items():
        for record in records:
            fid = components[record.id]
            previous = owners.setdefault(fid, set())
            for other in previous:
                if other != split:
                    overlaps.add((fid, other, split))
            previous.add(split)

    pairs: List[LeakagePair] = []
    names = list(splits)
    for i, left_name in enumerate(names):
        for right_name in names[i + 1:]:
            index: Dict[str, Set[int]] = {}
            empty: Set[int] = set()
            for idx, (_, tokens) in enumerate(prepared[right_name]):
                if not tokens:
                    empty.add(idx)
                for token in tokens:
                    index.setdefault(token, set()).add(idx)
            for left, left_tokens in prepared[left_name]:
                # At zero even disjoint pairs qualify. Empty/empty has Jaccard
                # one by the public metric's convention and has no index term.
                candidates = (set(range(len(prepared[right_name]))) if threshold == 0
                              else set(empty) if not left_tokens else set())
                for token in left_tokens:
                    candidates.update(index.get(token, ()))
                for right_idx in candidates:
                    right, right_tokens = prepared[right_name][right_idx]
                    similarity = jaccard(left_tokens, right_tokens)
                    if similarity >= threshold:
                        pairs.append(LeakagePair(
                            left_name, left.id, right_name, right.id, round(similarity, 6)
                        ))
    pairs.sort(key=lambda pair: (-pair.similarity, pair.left_split, pair.right_split,
                                 pair.left_id, pair.right_id))
    return LeakageAudit(
        threshold=threshold,
        shingle_size=shingle_size,
        split_sizes={name: len(records) for name, records in splits.items()},
        family_overlaps=sorted(overlaps),
        near_duplicates=pairs,
    )
