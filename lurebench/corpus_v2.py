"""Leakage-resistant, provenance-committed corpus construction for core v2.

This module is intentionally separate from :mod:`lurebench.corpus`: v1 split
membership is frozen and must not be silently rewritten. The v2 builder groups
declared families and near-duplicate text before assigning whole clusters to a
split, then audits the result and fails closed on any boundary leakage.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Sequence, Set, Tuple

from .audit import LeakageAudit, audit_splits, jaccard, shingles
from .corpus import gate
from .ingest.base import norm_key
from .schema import Lure, load_jsonl

SCHEMA = "https://github.com/immu4989/lurebench/spec/core-v2-build/v1"
DEFAULT_WEIGHTS = {"train": 0.7, "validation": 0.1, "test": 0.1, "heldout": 0.1}
_FAMILY_FIELDS = ("family_id", "scenario_id", "parent_id", "seed_id")
_PROFILE_FIELDS = ("label", "source", "typology", "language", "channel")


class _DisjointSet:
    def __init__(self, size: int) -> None:
        self.parent = list(range(size))
        self.rank = [0] * size

    def find(self, item: int) -> int:
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def union(self, left: int, right: int) -> bool:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root == right_root:
            return False
        if self.rank[left_root] < self.rank[right_root]:
            left_root, right_root = right_root, left_root
        self.parent[right_root] = left_root
        if self.rank[left_root] == self.rank[right_root]:
            self.rank[left_root] += 1
        return True


@dataclass(frozen=True)
class Cluster:
    id: str
    records: Tuple[Lure, ...]


@dataclass
class CoreV2Build:
    train: List[Lure]
    validation: List[Lure]
    test: List[Lure]
    heldout: List[Lure]
    weights: Dict[str, float]
    similarity_threshold: float
    shingle_size: int
    source_commitments: List[dict]
    n_loaded: int
    n_before_exact_dedup: int
    n_after_exact_dedup: int
    dropped_pending: int
    dropped_flagged: int
    duplicate_exact: int
    cluster_count: int
    largest_cluster: int
    explicit_family_unions: int
    near_duplicate_unions: int
    near_duplicate_candidates: int
    audit: LeakageAudit
    cluster_assignments: Dict[str, str] = field(repr=False)

    @property
    def n(self) -> int:
        return len(self.train) + len(self.validation) + len(self.test) + len(self.heldout)

    def splits(self) -> Dict[str, List[Lure]]:
        return {
            "train": self.train,
            "validation": self.validation,
            "test": self.test,
            "heldout": self.heldout,
        }


def _sha256_file(path: Path) -> str:
    if path.is_symlink():
        raise ValueError(f"refusing symbolic-link source: {path}")
    if not path.is_file():
        raise FileNotFoundError(path)
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_weights(weights: Mapping[str, float]) -> Dict[str, float]:
    if set(weights) != set(DEFAULT_WEIGHTS):
        raise ValueError(f"split weights must contain exactly {sorted(DEFAULT_WEIGHTS)}")
    result = {name: float(weights[name]) for name in DEFAULT_WEIGHTS}
    if any(not math.isfinite(value) or value <= 0 for value in result.values()):
        raise ValueError("every split weight must be finite and greater than zero")
    if not math.isclose(sum(result.values()), 1.0, rel_tol=0, abs_tol=1e-12):
        raise ValueError("split weights must sum to one")
    return result


def _load_and_gate(source_paths: Sequence[str]) -> Tuple[List[Lure], dict]:
    if not source_paths:
        raise ValueError("at least one source is required")
    records: List[Lure] = []
    pending = flagged = loaded = 0
    commitments = []
    seen_source_digests: Set[str] = set()
    for index, raw_path in enumerate(source_paths, 1):
        path = Path(raw_path)
        digest = _sha256_file(path)
        if digest in seen_source_digests:
            raise ValueError("the same source content was supplied more than once")
        seen_source_digests.add(digest)
        source_records = load_jsonl(path)
        loaded += len(source_records)
        kept, source_pending, source_flagged = gate(source_records)
        pending += source_pending
        flagged += source_flagged
        records.extend(kept)
        commitments.append(
            {
                "source": f"source-{index:04d}",
                "sha256": digest,
                "loaded_records": len(source_records),
                "kept_records": len(kept),
            }
        )
    if not records:
        raise ValueError("no records remain after the review gate")
    return records, {
        "loaded": loaded,
        "pending": pending,
        "flagged": flagged,
        "commitments": commitments,
    }


def _exact_deduplicate(records: Iterable[Lure]) -> Tuple[List[Lure], int]:
    """Deduplicate deterministically and reject contradictory identical text."""
    by_id: Dict[str, dict] = {}
    by_text: Dict[str, List[Lure]] = defaultdict(list)
    for record in records:
        serialized = record.to_dict()
        previous = by_id.setdefault(record.id, serialized)
        if previous != serialized:
            raise ValueError(f"record id {record.id!r} refers to conflicting records")
        by_text[norm_key(record.text)].append(record)

    kept: List[Lure] = []
    duplicates = 0
    for text_hash in sorted(by_text):
        candidates_by_id = {record.id: record for record in by_text[text_hash]}
        candidates = [candidates_by_id[key] for key in sorted(candidates_by_id)]
        signatures = {(record.label, record.source, record.typology) for record in candidates}
        if len(signatures) != 1:
            ids = ", ".join(record.id for record in candidates[:5])
            raise ValueError(
                f"normalized-identical text has contradictory labels/provenance: {ids}"
            )
        kept.append(candidates[0])
        duplicates += len(by_text[text_hash]) - 1
    kept.sort(key=lambda record: record.id)
    return kept, duplicates


def _declared_family(record: Lure) -> str | None:
    for key in _FAMILY_FIELDS:
        value = record.meta.get(key)
        if value is not None and str(value).strip():
            return str(value)
    return None


def cluster_records(
    records: Sequence[Lure], *, threshold: float = 0.8, shingle_size: int = 5
) -> Tuple[List[Cluster], dict]:
    """Form transitive clusters from explicit lineage and shingle similarity."""
    if not 0 < threshold <= 1:
        raise ValueError("similarity threshold must be greater than zero and at most one")
    if not isinstance(shingle_size, int) or not 1 <= shingle_size <= 20:
        raise ValueError("shingle size must be an integer between 1 and 20")
    if not records:
        raise ValueError("cannot cluster an empty corpus")

    dsu = _DisjointSet(len(records))
    family_owner: Dict[str, int] = {}
    family_unions = 0
    for index, record in enumerate(records):
        family = _declared_family(record)
        if family is not None:
            owner = family_owner.setdefault(family, index)
            family_unions += int(dsu.union(owner, index))

    prepared = [shingles(record.text, shingle_size) for record in records]
    inverted: Dict[str, Set[int]] = defaultdict(set)
    candidate_pairs = 0
    similarity_unions = 0
    for right_index, right_tokens in enumerate(prepared):
        candidates: Set[int] = set()
        for token in right_tokens:
            candidates.update(inverted[token])
        for left_index in sorted(candidates):
            candidate_pairs += 1
            if jaccard(prepared[left_index], right_tokens) >= threshold:
                similarity_unions += int(dsu.union(left_index, right_index))
        for token in right_tokens:
            inverted[token].add(right_index)

    members: Dict[int, List[Lure]] = defaultdict(list)
    for index, record in enumerate(records):
        members[dsu.find(index)].append(record)

    clusters: List[Cluster] = []
    for grouped_records in members.values():
        ordered = tuple(sorted(grouped_records, key=lambda record: record.id))
        commitment = "\n".join(
            f"{record.id}\0{norm_key(record.text)}" for record in ordered
        ).encode("utf-8")
        cluster_id = "cluster-" + hashlib.sha256(commitment).hexdigest()[:24]
        clusters.append(Cluster(cluster_id, ordered))
    clusters.sort(key=lambda cluster: cluster.id)
    return clusters, {
        "explicit_family_unions": family_unions,
        "near_duplicate_unions": similarity_unions,
        "near_duplicate_candidates": candidate_pairs,
    }


def _record_features(record: Lure) -> Counter:
    features = Counter({("records", "all"): 1})
    for field_name in _PROFILE_FIELDS:
        features[(field_name, str(getattr(record, field_name)))] += 1
    return features


def _cluster_features(cluster: Cluster) -> Counter:
    result: Counter = Counter()
    for record in cluster.records:
        result.update(_record_features(record))
    return result


def assign_clusters(clusters: Sequence[Cluster], weights: Mapping[str, float]) -> Dict[str, str]:
    """Deterministically minimize split imbalance while keeping clusters intact."""
    checked_weights = _validate_weights(weights)
    if len(clusters) < len(checked_weights):
        raise ValueError("at least four independent clusters are required for four splits")

    cluster_counts = {cluster.id: _cluster_features(cluster) for cluster in clusters}
    totals: Counter = Counter()
    for counts in cluster_counts.values():
        totals.update(counts)
    current = {split: Counter() for split in checked_weights}
    assignments: Dict[str, str] = {}

    def incremental_cost(split: str, counts: Counter) -> float:
        cost = 0.0
        for feature, addition in counts.items():
            target = totals[feature] * checked_weights[split]
            before = current[split][feature]
            scale = max(float(totals[feature]), 1.0)
            feature_weight = 2.0 if feature == ("records", "all") else 1.0
            cost += feature_weight * (
                ((before + addition - target) ** 2 - (before - target) ** 2) / scale
            )
        return cost

    ordered = sorted(clusters, key=lambda cluster: (-len(cluster.records), cluster.id))
    for cluster in ordered:
        counts = cluster_counts[cluster.id]
        ranked = []
        for split in checked_weights:
            tie_material = f"core-v2:{cluster.id}:{split}".encode("utf-8")
            tie_break = hashlib.sha256(tie_material).hexdigest()
            ranked.append((incremental_cost(split, counts), tie_break, split))
        split = min(ranked)[2]
        assignments[cluster.id] = split
        current[split].update(counts)

    if set(assignments.values()) != set(checked_weights):
        raise ValueError("stratified assignment produced an empty split; add more diverse clusters")
    return assignments


def build_core_v2(
    source_paths: Sequence[str],
    *,
    threshold: float = 0.8,
    shingle_size: int = 5,
    weights: Mapping[str, float] = DEFAULT_WEIGHTS,
) -> CoreV2Build:
    """Gate, validate, deduplicate, cluster, stratify, and audit a v2 corpus."""
    checked_weights = _validate_weights(weights)
    loaded, source_info = _load_and_gate(source_paths)
    deduped, duplicate_exact = _exact_deduplicate(loaded)
    clusters, cluster_stats = cluster_records(
        deduped, threshold=threshold, shingle_size=shingle_size
    )
    assignments = assign_clusters(clusters, checked_weights)
    split_records: Dict[str, List[Lure]] = {name: [] for name in checked_weights}
    record_assignments: Dict[str, str] = {}
    for cluster in clusters:
        split = assignments[cluster.id]
        split_records[split].extend(cluster.records)
        for record in cluster.records:
            record_assignments[record.id] = cluster.id
    for records in split_records.values():
        records.sort(key=lambda record: record.id)

    audit = audit_splits(split_records, threshold=threshold, shingle_size=shingle_size)
    if not audit.passed:
        raise RuntimeError("internal error: clustered v2 build failed its boundary-leakage audit")

    return CoreV2Build(
        train=split_records["train"],
        validation=split_records["validation"],
        test=split_records["test"],
        heldout=split_records["heldout"],
        weights=checked_weights,
        similarity_threshold=threshold,
        shingle_size=shingle_size,
        source_commitments=source_info["commitments"],
        n_loaded=source_info["loaded"],
        n_before_exact_dedup=len(loaded),
        n_after_exact_dedup=len(deduped),
        dropped_pending=source_info["pending"],
        dropped_flagged=source_info["flagged"],
        duplicate_exact=duplicate_exact,
        cluster_count=len(clusters),
        largest_cluster=max(len(cluster.records) for cluster in clusters),
        explicit_family_unions=cluster_stats["explicit_family_unions"],
        near_duplicate_unions=cluster_stats["near_duplicate_unions"],
        near_duplicate_candidates=cluster_stats["near_duplicate_candidates"],
        audit=audit,
        cluster_assignments=record_assignments,
    )


def _jsonl_bytes(records: Sequence[Lure]) -> bytes:
    return b"".join(
        (json.dumps(record.to_dict(), ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
        for record in records
    )


def _profile(records: Sequence[Lure]) -> dict:
    profile = {field_name: Counter() for field_name in _PROFILE_FIELDS}
    for record in records:
        for field_name in _PROFILE_FIELDS:
            profile[field_name][str(getattr(record, field_name))] += 1
    return {
        "records": len(records),
        **{field_name: dict(sorted(counts.items())) for field_name, counts in profile.items()},
    }


def _write_exclusive(path: Path, content: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, mode)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def write_core_v2(build: CoreV2Build, out_dir: str, heldout_path: str) -> Dict[str, str]:
    """Write public splits separately from the mode-0600 held-out evaluator shard."""
    out = Path(out_dir)
    heldout = Path(heldout_path)
    resolved_out = out.resolve(strict=False)
    resolved_heldout = heldout.resolve(strict=False)
    if resolved_heldout == resolved_out or resolved_out in resolved_heldout.parents:
        raise ValueError("held-out data must be outside the public output directory")
    if heldout.exists() or heldout.is_symlink():
        raise FileExistsError(f"held-out output already exists: {heldout}")
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise FileExistsError(f"public output directory must be new or empty: {out}")
    out.mkdir(parents=True, exist_ok=True)

    payloads = {
        "train": _jsonl_bytes(build.train),
        "validation": _jsonl_bytes(build.validation),
        "test": _jsonl_bytes(build.test),
        "heldout": _jsonl_bytes(build.heldout),
    }
    paths: Dict[str, str] = {}
    for split in ("train", "validation", "test"):
        path = out / f"{split}.jsonl"
        _write_exclusive(path, payloads[split], 0o644)
        paths[split] = str(path)
    _write_exclusive(heldout, payloads["heldout"], 0o600)
    paths["heldout"] = str(heldout)

    manifest = {
        "schema": SCHEMA,
        "schema_version": 1,
        "builder": "lurebench-core-v2",
        "parameters": {
            "weights": build.weights,
            "near_duplicate_threshold": build.similarity_threshold,
            "word_shingle_size": build.shingle_size,
            "assignment": "deterministic_cluster_stratification_v1",
        },
        "review_gate": {
            "loaded": build.n_loaded,
            "kept_before_exact_dedup": build.n_before_exact_dedup,
            "dropped_pending": build.dropped_pending,
            "dropped_flagged": build.dropped_flagged,
        },
        "deduplication": {
            "normalized_exact_duplicates_removed": build.duplicate_exact,
            "records_after_exact_dedup": build.n_after_exact_dedup,
        },
        "clustering": {
            "clusters": build.cluster_count,
            "largest_cluster": build.largest_cluster,
            "explicit_family_unions": build.explicit_family_unions,
            "near_duplicate_unions": build.near_duplicate_unions,
            "candidate_pairs_compared": build.near_duplicate_candidates,
        },
        "sources": build.source_commitments,
        "splits": {
            split: {
                "sha256": hashlib.sha256(payload).hexdigest(),
                "profile": _profile(build.splits()[split]),
                "publication": "private_evaluator_only" if split == "heldout" else "public",
            }
            for split, payload in payloads.items()
        },
        "boundary_audit": build.audit.as_dict(),
        "constraints": [
            "heldout_records_and_labels_must_not_be_published",
            "test_must_not_be_used_for_model_or_threshold_selection",
            "source_commitments_identify_bytes_not_redistribution_rights",
        ],
    }
    manifest_bytes = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode("utf-8")
    manifest_path = out / "manifest.json"
    _write_exclusive(manifest_path, manifest_bytes, 0o644)
    paths["manifest"] = str(manifest_path)
    return paths
