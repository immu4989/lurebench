"""Validation-only threshold selection, calibration diagnostics and uncertainty."""

from __future__ import annotations

import hashlib
import json
import math
import random
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Callable, List, Optional, Sequence, Tuple

from .metrics import Metrics, evaluate


@dataclass(frozen=True)
class ReliabilityBin:
    lower: float
    upper: float
    count: int
    mean_score: Optional[float]
    positive_rate: Optional[float]


@dataclass(frozen=True)
class CalibrationMetrics:
    brier: float
    expected_calibration_error: float
    bins: List[ReliabilityBin]


@dataclass(frozen=True)
class ConfidenceInterval:
    estimate: float
    lower: float
    upper: float
    confidence: float
    replicates: int


@dataclass(frozen=True)
class DecisionPolicy:
    schema_version: int
    policy_id: str
    detector: str
    task: str
    threshold: float
    objective: str
    target_fpr: Optional[float]
    validation_records: int
    validation_sha256: str
    created_at: str

    def as_dict(self) -> dict:
        return asdict(self)

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(self.as_dict(), handle, indent=2, sort_keys=True)
            handle.write("\n")

    @classmethod
    def load(cls, path: str) -> "DecisionPolicy":
        with open(path, encoding="utf-8") as handle:
            return cls(**json.load(handle))


def calibration_metrics(
    y_true: Sequence[int], scores: Sequence[float], n_bins: int = 10
) -> CalibrationMetrics:
    if len(y_true) != len(scores):
        raise ValueError("y_true and scores length mismatch")
    if not y_true:
        raise ValueError("calibration requires at least one record")
    if n_bins < 1:
        raise ValueError("n_bins must be positive")
    if any(score < 0.0 or score > 1.0 for score in scores):
        raise ValueError("scores must be probabilities in [0, 1]")
    brier = sum((score - truth) ** 2 for truth, score in zip(y_true, scores)) / len(y_true)
    buckets: List[List[Tuple[int, float]]] = [[] for _ in range(n_bins)]
    for truth, score in zip(y_true, scores):
        index = min(int(score * n_bins), n_bins - 1)
        buckets[index].append((truth, score))
    bins: List[ReliabilityBin] = []
    ece = 0.0
    for index, bucket in enumerate(buckets):
        count = len(bucket)
        mean = sum(score for _, score in bucket) / count if count else None
        rate = sum(truth for truth, _ in bucket) / count if count else None
        if count:
            ece += count / len(y_true) * abs(float(mean) - float(rate))
        bins.append(ReliabilityBin(
            lower=index / n_bins,
            upper=(index + 1) / n_bins,
            count=count,
            mean_score=mean,
            positive_rate=rate,
        ))
    return CalibrationMetrics(brier=brier, expected_calibration_error=ece, bins=bins)


def select_threshold(
    y_true: Sequence[int],
    scores: Sequence[float],
    objective: str = "max_mcc",
    target_fpr: Optional[float] = None,
) -> Tuple[float, Metrics]:
    """Select a realizable threshold on validation scores only.

    ``max_mcc`` maximizes MCC. ``target_fpr`` maximizes recall while satisfying
    the supplied false-positive budget. Ties prefer the higher threshold.
    """
    if len(y_true) != len(scores) or not y_true:
        raise ValueError("non-empty y_true and scores of equal length required")
    if objective not in {"max_mcc", "target_fpr"}:
        raise ValueError("objective must be 'max_mcc' or 'target_fpr'")
    if objective == "target_fpr" and (target_fpr is None or not 0 <= target_fpr <= 1):
        raise ValueError("target_fpr objective requires target_fpr in [0, 1]")
    candidates = sorted({float(score) for score in scores}, reverse=True)
    candidates.insert(0, math.nextafter(candidates[0], math.inf))
    feasible: List[Tuple[float, Metrics]] = []
    for threshold in candidates:
        predictions = [int(score >= threshold) for score in scores]
        metrics = evaluate(y_true, predictions, scores)
        if objective == "max_mcc" or metrics.fpr <= float(target_fpr):
            feasible.append((threshold, metrics))
    if objective == "max_mcc":
        return max(feasible, key=lambda item: (item[1].mcc, item[1].recall, item[0]))
    return max(feasible, key=lambda item: (item[1].recall, item[1].mcc, item[0]))


def bootstrap_ci(
    values: Sequence[Tuple[int, float]],
    statistic: Callable[[Sequence[int], Sequence[float]], float],
    replicates: int = 2000,
    confidence: float = 0.95,
    seed: int = 4989,
) -> ConfidenceInterval:
    """Paired percentile bootstrap over ``(truth, score)`` observations."""
    if not values:
        raise ValueError("bootstrap requires observations")
    if replicates < 1 or not 0 < confidence < 1:
        raise ValueError("invalid bootstrap configuration")
    truths = [item[0] for item in values]
    scores = [item[1] for item in values]
    estimate = statistic(truths, scores)
    rng = random.Random(seed)
    draws: List[float] = []
    for _ in range(replicates):
        sample = [values[rng.randrange(len(values))] for _ in values]
        result = statistic([item[0] for item in sample], [item[1] for item in sample])
        if math.isfinite(result):
            draws.append(result)
    if not draws:
        raise ValueError("statistic was undefined for every bootstrap replicate")
    draws.sort()
    alpha = (1.0 - confidence) / 2.0
    low = draws[max(0, int(alpha * len(draws)))]
    high = draws[min(len(draws) - 1, math.ceil((1 - alpha) * len(draws)) - 1)]
    return ConfidenceInterval(estimate, low, high, confidence, len(draws))


def build_policy(
    detector: str,
    task: str,
    record_ids: Sequence[str],
    y_true: Sequence[int],
    scores: Sequence[float],
    objective: str = "max_mcc",
    target_fpr: Optional[float] = None,
) -> Tuple[DecisionPolicy, Metrics]:
    threshold, metrics = select_threshold(y_true, scores, objective, target_fpr)
    digest = hashlib.sha256("\n".join(record_ids).encode("utf-8")).hexdigest()
    identity = hashlib.sha256(
        f"{detector}\0{task}\0{objective}\0{target_fpr}\0{digest}".encode("utf-8")
    ).hexdigest()[:12]
    policy = DecisionPolicy(
        schema_version=1,
        policy_id=f"{detector}-{identity}",
        detector=detector,
        task=task,
        threshold=threshold,
        objective=objective,
        target_fpr=target_fpr,
        validation_records=len(record_ids),
        validation_sha256=digest,
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    return policy, metrics
