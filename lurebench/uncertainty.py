"""Offline record-weighted percentile intervals over whole declared groups.

Grouping is supplied evidence, not a discovered independence relationship. No
model is fitted, threshold selected, missing score imputed, or provider called.
"""

from __future__ import annotations

import hashlib
import math
import random
from collections.abc import Mapping
from pathlib import Path

from .metrics import validate_binary_labels
from .probability import validate_score, validate_threshold

MAX_RECORDS = 50_000
MAX_REPLICATES = 10_000
MAX_WORK = 50_000_000  # records * replicates, before any random draws
METRICS = ("accuracy", "mcc", "recall", "fpr", "auc", "answer_coverage",
           "positive_answer_coverage", "negative_answer_coverage")


def _identifier(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 1024 or any(
        ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value
    ):
        raise ValueError("identifiers must be bounded strings without controls")


def _configuration(records, replicates, confidence, seed):
    confidence = validate_threshold(confidence)
    if type(replicates) is not int or not 1 <= replicates <= MAX_REPLICATES:
        raise ValueError("replicates must be an integer from 1 through 10000")
    if not 0 < confidence < 1 or type(seed) is not int or not 0 <= seed < 2**64:
        raise ValueError("confidence or seed is outside the supported range")
    if not 1 <= records <= MAX_RECORDS or records * replicates > MAX_WORK:
        raise ValueError("uncertainty analysis exceeds its record or resampling work limit")
    return confidence


def _statistics(rows, weights, threshold):
    """Weighted expansion-equivalent metrics, with ascending scores and tied ranks.

    None scores come last. Integer multiplicities avoid ever materializing the
    potentially much larger resampled rows of unequal-sized clusters.
    """
    tp = fp = tn = fn = ap = an = 0
    smaller_negatives = twice_u = tie_positive = tie_negative = 0
    previous = None
    for truth, score, group in rows:
        weight = weights[group]
        if score is None:
            if truth:
                ap += weight
            else:
                an += weight
            continue
        if previous != score:
            twice_u += tie_positive * (2 * smaller_negatives + tie_negative)
            smaller_negatives += tie_negative
            tie_positive = tie_negative = 0
            previous = score
        if truth:
            tie_positive += weight
            if score >= threshold:
                tp += weight
            else:
                fn += weight
        else:
            tie_negative += weight
            if score >= threshold:
                fp += weight
            else:
                tn += weight
    twice_u += tie_positive * (2 * smaller_negatives + tie_negative)
    positive, negative = tp + fn, tn + fp
    answered = positive + negative
    total = answered + ap + an
    denominator = (tp + fp) * positive * negative * (tn + fn)
    return {
        "accuracy": (tp + tn) / answered if answered else None,
        "mcc": (tp * tn - fp * fn) / math.sqrt(denominator) if denominator else None,
        "recall": tp / positive if positive else None,
        "fpr": fp / negative if negative else None,
        "auc": twice_u / (2 * positive * negative) if positive and negative else None,
        "answer_coverage": answered / total if total else None,
        "positive_answer_coverage": positive / (positive + ap) if positive + ap else None,
        "negative_answer_coverage": negative / (negative + an) if negative + an else None,
    }, {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "abstained_positive": ap, "abstained_negative": an}


def bootstrap_uncertainty(
    truths: Mapping[str, int], scores: Mapping[str, float | None], *,
    groups: Mapping[str, str] | None = None, threshold: float = .5,
    replicates: int = 2000, confidence: float = .95, seed: int = 4989,
) -> dict:
    """Resample K complete groups with replacement K times per replicate.

    Omitting groups explicitly assumes record-level units. All records, including
    abstentions and wholly abstaining groups, participate. Performance metrics
    remain conditional on answered records; coverage describes all records.
    Metrics with zero denominators are undefined, including degenerate MCC.
    """
    from .receipts import canonical_json

    if not isinstance(truths, Mapping) or not isinstance(scores, Mapping):
        raise ValueError("targets and scores must be mappings")
    confidence = _configuration(len(truths), replicates, confidence, seed)
    if set(truths) != set(scores):
        raise ValueError("targets and scores must cover identical record IDs")
    for key in truths:
        _identifier(key)
    if groups is not None:
        if not isinstance(groups, Mapping) or set(groups) != set(truths):
            raise ValueError("groups must cover exactly the record IDs")
        for value in groups.values():
            _identifier(value)
    validate_binary_labels(list(truths.values()))
    threshold = validate_threshold(threshold)
    # Detach effective inputs once. IDs/groups are hashed but never disclosed.
    inputs = [{"id": key, "target": int(truths[key]), "score": validate_score(scores[key]),
               "group": groups[key] if groups is not None else key} for key in sorted(truths)]
    labels = sorted({item["group"] for item in inputs})
    positions = {label: index for index, label in enumerate(labels)}
    rows = sorted(((item["target"], item["score"], positions[item["group"]]) for item in inputs),
                  key=lambda row: (row[1] is None, row[1] if row[1] is not None else 0))
    sizes = [0] * len(labels)
    positive_units, negative_units, answered_units = set(), set(), set()
    for truth, score, group in rows:
        sizes[group] += 1
        (positive_units if truth else negative_units).add(group)
        if score is not None:
            answered_units.add(group)
    estimate, counts = _statistics(rows, [1] * len(labels), threshold)
    draws = {name: [] for name in METRICS}
    executed = 0
    minimum_records = maximum_records = None
    if len(labels) >= 2:
        rng = random.Random(seed)
        for _ in range(replicates):
            weights = [0] * len(labels)
            for _ in labels:
                weights[rng.randrange(len(labels))] += 1
            result, _ = _statistics(rows, weights, threshold)
            n = sum(size * weight for size, weight in zip(sizes, weights, strict=True))
            minimum_records = n if minimum_records is None else min(n, minimum_records)
            maximum_records = n if maximum_records is None else max(n, maximum_records)
            executed += 1
            for name, value in result.items():
                if value is not None:
                    draws[name].append(value)
    intervals = {}
    for name in METRICS:
        values = sorted(draws[name])
        status = ("undefined_estimate" if estimate[name] is None else
                  "insufficient_resampling_units" if len(labels) < 2 else
                  "no_defined_replicates" if not values else "available")
        lower = upper = None
        if status == "available":
            alpha = (1 - confidence) / 2
            lower = values[int(alpha * len(values))]
            upper = values[min(len(values) - 1, math.ceil((1 - alpha) * len(values)) - 1)]
        intervals[name] = {
            "estimate": estimate[name], "lower": lower, "upper": upper, "status": status,
            "defined_replicates": len(values), "undefined_replicates": executed - len(values),
            "conditional_on_defined": bool(executed - len(values)),
        }
    unit = "record" if groups is None else "declared_group"
    effective = {"profile": "lurebench-uncertainty-effective-inputs-v1",
                 "resampling_unit": unit, "threshold": threshold, "records": inputs}
    return {
        "schema_version": 1, "analysis": "detector_cluster_uncertainty",
        "method": "whole_group_percentile_v1", "resampling_unit": unit,
        "threshold": threshold, "confidence": confidence, "seed": seed,
        "requested_replicates": replicates, "executed_replicates": executed,
        "input_fingerprint": {"profile": effective["profile"],
                              "sha256": hashlib.sha256(canonical_json(effective)).hexdigest()},
        "sample": {"records": len(rows), "resampling_units": len(labels),
                   "smallest_unit_records": min(sizes), "largest_unit_records": max(sizes),
                   "largest_unit_fraction": max(sizes) / len(rows),
                   "units_with_positive_records": len(positive_units),
                   "units_with_negative_records": len(negative_units),
                   "units_with_answered_records": len(answered_units), "decision_counts": counts},
        "replicate_records": {"minimum": minimum_records, "maximum": maximum_records},
        "metrics": intervals,
        "limitations": [
            "requires_independent_representative_resampling_units_not_proven_by_annotations",
            "record_weighted_metrics_not_equal_group_weighted_metrics",
            "performance_is_conditional_on_answered_records_not_missing_outcome_imputation",
            "percentile_intervals_are_nominal_not_finite_sample_coverage_guarantees",
            "few_or_dominant_groups_and_boundary_estimates_can_give_misleading_intervals",
            "undefined_replicates_are_excluded_and_reported_not_replaced_with_zero",
            "not_simultaneous_intervals_or_adjusted_for_selection_and_repeated_inspection",
            "no_refitting_threshold_selection_distribution_shift_or_label_error_correction",
            "fingerprints_are_not_anonymization_or_input_authentication",
        ],
    }


def run_cached_uncertainty(
    dataset: Path, cache: Path, *, detector_name: str, task: str,
    cache_namespace: str | None = None, resampling_unit: str = "lineage",
    threshold: float = .5, replicates: int = 2000, confidence: float = .95, seed: int = 4989,
) -> dict:
    """Replay an existing score cache; missing entries fail without live fallback."""
    from .detectors.cache import ReplayDetector
    from .harness import TASK_TARGET
    from .lineage import lineage_components
    from .schema import load_jsonl_with_digest

    if task not in ("fraud", "provenance") or resampling_unit not in ("lineage", "record"):
        raise ValueError("unsupported task or resampling unit")
    records, dataset_digest = load_jsonl_with_digest(dataset)
    _configuration(len(records), replicates, confidence, seed)
    if len({record.id for record in records}) != len(records):
        raise ValueError("uncertainty requires unique record IDs")
    groups = lineage_components(records) if resampling_unit == "lineage" else None
    replay = ReplayDetector(str(cache), name=detector_name, task=task, cache_namespace=cache_namespace)
    plan = replay.plan(records)
    if not plan["replay_complete"]:
        raise ValueError("uncertainty cache is incomplete; no live fallback")
    report = bootstrap_uncertainty(
        {r.id: TASK_TARGET[task](r) for r in records}, {r.id: replay.score(r) for r in records},
        groups=groups, threshold=threshold, replicates=replicates, confidence=confidence, seed=seed,
    )
    report["source"] = {"task": task, "detector": replay.name, "cache_namespace": cache_namespace,
                        "grouping": resampling_unit, "dataset_sha256": dataset_digest,
                        "cache_coverage": plan}
    return report


def verify_cached_uncertainty(dataset: Path, cache: Path, report_path: Path, **configuration) -> dict:
    """Reproduce all fields from independently supplied controls, not report controls."""
    from .local_io import read_regular_file
    from .receipts import canonical_json, loads_strict_json

    raw = read_regular_file(report_path, maximum=64 * 1024, label="uncertainty report")
    supplied = loads_strict_json(raw)
    if (not isinstance(supplied, dict) or type(supplied.get("schema_version")) is not int
            or supplied["schema_version"] != 1
            or supplied.get("analysis") != "detector_cluster_uncertainty"):
        raise ValueError("expected a version 1 uncertainty report")
    expected = run_cached_uncertainty(dataset, cache, **configuration)
    return {
        "schema_version": 1, "verification": "local_cached_uncertainty_reproduction",
        "matches_replay": canonical_json(supplied) == canonical_json(expected),
        "supplied_report_sha256": hashlib.sha256(raw).hexdigest(),
        "replayed_report_canonical_sha256": hashlib.sha256(canonical_json(expected)).hexdigest(),
        "input_fingerprint": expected["input_fingerprint"],
        "limitations": ["same_implementation_reproduction_not_independent_statistical_validation",
                        "does_not_authenticate_inputs_or_prove_independence_or_preregistration"],
    }
