"""Validation-only threshold selection, calibration diagnostics and uncertainty."""

from __future__ import annotations

import hashlib
import json
import math
import random
from bisect import bisect_left
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Callable, List, Optional, Sequence, Tuple

from .metrics import Metrics, evaluate

RISK_CONTROL_METHOD = "learn_then_test_fixed_sequence_exact_binomial_v1"


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
class RiskControl:
    """Finite-sample evidence attached to a risk-controlled policy."""

    method: str
    risk: str
    confidence: float
    validation_negatives: int
    false_positives: int
    empirical_fpr: float
    upper_confidence_bound: float
    hypothesis_p_value: float
    threshold_grid_size: int


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
    evaluation_sha256: Optional[str] = None
    validation_true_positives: Optional[int] = None
    validation_recall: Optional[float] = None
    risk_control: Optional[RiskControl] = None

    def as_dict(self) -> dict:
        payload = asdict(self)
        if self.evaluation_sha256 is None:
            payload.pop("evaluation_sha256")
        if self.validation_true_positives is None:
            payload.pop("validation_true_positives")
        if self.validation_recall is None:
            payload.pop("validation_recall")
        if self.risk_control is None:
            payload.pop("risk_control")
        return payload

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(self.as_dict(), handle, indent=2, sort_keys=True)
            handle.write("\n")

    @classmethod
    def load(cls, path: str) -> "DecisionPolicy":
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
        if payload.get("risk_control") is not None:
            payload["risk_control"] = RiskControl(**payload["risk_control"])
        return cls(**payload)


def binomial_cdf(events: int, trials: int, probability: float) -> float:
    """Return ``P[X <= events]`` for ``X ~ Binomial(trials, probability)``.

    The implementation starts at a binomial mode, assigns it unit weight, and
    recurs toward both tails before normalizing with ``math.fsum``. Starting at
    the mode avoids underflow; normalization avoids cancellation in log-gamma
    formulas for large samples while keeping LureBench's core dependency-free.
    """
    if trials < 0 or events < -1 or events > trials:
        raise ValueError("invalid binomial event count")
    if not 0 <= probability <= 1:
        raise ValueError("binomial probability must be in [0, 1]")
    if events < 0:
        return 0.0
    if events == trials or probability == 0:
        return 1.0
    if probability == 1:
        return 0.0

    mode = min(trials, math.floor((trials + 1) * probability))
    weights = [(mode, 1.0)]

    term = 1.0
    for index in range(mode, 0, -1):
        term *= (index / (trials - index + 1)) * ((1 - probability) / probability)
        if term == 0.0:
            break
        weights.append((index - 1, term))

    term = 1.0
    for index in range(mode, trials):
        term *= ((trials - index) / (index + 1)) * (probability / (1 - probability))
        if term == 0.0:
            break
        weights.append((index + 1, term))

    normalizer = math.fsum(weight for _, weight in weights)
    lower_tail = math.fsum(weight for index, weight in weights if index <= events)
    return min(1.0, max(0.0, lower_tail / normalizer))


def clopper_pearson_upper(
    events: int, trials: int, confidence: float = 0.95
) -> float:
    """Exact one-sided Clopper-Pearson upper confidence bound."""
    if trials < 1 or events < 0 or events > trials:
        raise ValueError("events must be between zero and a positive trial count")
    if not 0 < confidence < 1:
        raise ValueError("confidence must be in (0, 1)")
    if events == trials:
        return 1.0
    alpha = 1.0 - confidence
    lower, upper = 0.0, 1.0
    for _ in range(64):
        midpoint = (lower + upper) / 2.0
        if binomial_cdf(events, trials, midpoint) > alpha:
            lower = midpoint
        else:
            upper = midpoint
    return upper


def minimum_zero_event_sample(target_fpr: float, confidence: float = 0.95) -> int:
    """Minimum negatives needed to control ``target_fpr`` after zero errors."""
    if not 0 < target_fpr < 1:
        raise ValueError("target_fpr must be in (0, 1)")
    if not 0 < confidence < 1:
        raise ValueError("confidence must be in (0, 1)")
    return math.ceil(math.log1p(-confidence) / math.log1p(-target_fpr))


def select_risk_controlled_threshold(
    y_true: Sequence[int],
    scores: Sequence[float],
    target_fpr: float,
    confidence: float = 0.95,
    threshold_grid_size: int = 1001,
) -> Tuple[float, Metrics, RiskControl]:
    """Select the least-strict threshold with finite-sample FPR control.

    Hypotheses are tested from strict to permissive on a predeclared unit-interval
    grid. Each exact binomial test asks whether the population FPR exceeds the
    target; testing stops at the first non-rejection. This is the fixed-sequence
    Learn-then-Test construction, so threshold search does not silently multiply
    the stated type-I error.

    The guarantee assumes the validation negatives are representative i.i.d.
    draws from the deployment distribution. It does not survive distribution
    shift, label error, detector changes, or reuse of the validation set to choose
    the model or grid.
    """
    if len(y_true) != len(scores) or not y_true:
        raise ValueError("non-empty y_true and scores of equal length required")
    if any(truth not in (0, 1) for truth in y_true):
        raise ValueError("risk control requires binary labels")
    if any(score < 0.0 or score > 1.0 for score in scores):
        raise ValueError("scores must be probabilities in [0, 1]")
    if not 0 < target_fpr < 1:
        raise ValueError("risk-controlled FPR requires target_fpr in (0, 1)")
    if not 0 < confidence < 1:
        raise ValueError("confidence must be in (0, 1)")
    if not 2 <= threshold_grid_size <= 100_001:
        raise ValueError("threshold_grid_size must be between 2 and 100001")

    negative_scores = sorted(
        float(score) for truth, score in zip(y_true, scores, strict=True) if truth == 0
    )
    n_negative = len(negative_scores)
    if not n_negative:
        raise ValueError("risk-controlled FPR requires validation negatives")
    if n_negative == len(y_true):
        raise ValueError("risk-controlled policy requires validation positives to measure utility")

    alpha = 1.0 - confidence
    low, high = -1, n_negative
    while high - low > 1:
        midpoint = (low + high) // 2
        if binomial_cdf(midpoint, n_negative, target_fpr) <= alpha:
            low = midpoint
        else:
            high = midpoint
    max_allowed_false_positives = low
    if max_allowed_false_positives < 0:
        minimum = minimum_zero_event_sample(target_fpr, confidence)
        raise ValueError(
            f"cannot control FPR <= {target_fpr:g} at {confidence:.1%} confidence with "
            f"{n_negative} validation negatives; at least {minimum} are required even "
            "with zero false positives"
        )

    selected: Optional[Tuple[float, int]] = None
    denominator = threshold_grid_size - 1
    for index in range(denominator, -1, -1):
        threshold = index / denominator
        false_positives = n_negative - bisect_left(negative_scores, threshold)
        if false_positives > max_allowed_false_positives:
            break
        selected = (threshold, false_positives)
    if selected is None:  # possible when one or more negatives receive score 1.0
        raise ValueError(
            "no threshold on the predeclared [0, 1] grid controls the requested FPR"
        )

    threshold, false_positives = selected
    predictions = [int(score >= threshold) for score in scores]
    metrics = evaluate(y_true, predictions, scores)
    p_value = binomial_cdf(false_positives, n_negative, target_fpr)
    upper_bound = clopper_pearson_upper(false_positives, n_negative, confidence)
    assurance = RiskControl(
        method=RISK_CONTROL_METHOD,
        risk="false_positive_rate",
        confidence=confidence,
        validation_negatives=n_negative,
        false_positives=false_positives,
        empirical_fpr=metrics.fpr,
        upper_confidence_bound=upper_bound,
        hypothesis_p_value=p_value,
        threshold_grid_size=threshold_grid_size,
    )
    return threshold, metrics, assurance


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
    brier = sum(
        (score - truth) ** 2 for truth, score in zip(y_true, scores, strict=True)
    ) / len(y_true)
    buckets: List[List[Tuple[int, float]]] = [[] for _ in range(n_bins)]
    for truth, score in zip(y_true, scores, strict=True):
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
    confidence: float = 0.95,
    threshold_grid_size: int = 1001,
) -> Tuple[DecisionPolicy, Metrics]:
    if not (len(record_ids) == len(y_true) == len(scores)) or not record_ids:
        raise ValueError("record_ids, y_true and scores must have the same non-zero length")
    risk_control = None
    if objective == "risk_controlled_fpr":
        if target_fpr is None:
            raise ValueError("risk_controlled_fpr requires target_fpr")
        threshold, metrics, risk_control = select_risk_controlled_threshold(
            y_true,
            scores,
            target_fpr=target_fpr,
            confidence=confidence,
            threshold_grid_size=threshold_grid_size,
        )
    else:
        threshold, metrics = select_threshold(y_true, scores, objective, target_fpr)
    digest = hashlib.sha256("\n".join(record_ids).encode("utf-8")).hexdigest()
    evaluation = hashlib.sha256()
    for record_id, truth, score in zip(record_ids, y_true, scores, strict=True):
        row = json.dumps(
            {"id": record_id, "label": int(truth), "score_hex": float(score).hex()},
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        evaluation.update(row.encode("utf-8") + b"\n")
    evaluation_digest = evaluation.hexdigest()
    if risk_control is None:
        identity_material = f"{detector}\0{task}\0{objective}\0{target_fpr}\0{digest}"
    else:
        identity_material = (
            f"{detector}\0{task}\0{objective}\0{target_fpr}\0{confidence}\0"
            f"{threshold_grid_size}\0{digest}\0{evaluation_digest}"
        )
    identity = hashlib.sha256(identity_material.encode("utf-8")).hexdigest()[:12]
    policy = DecisionPolicy(
        schema_version=2 if risk_control is not None else 1,
        policy_id=f"{detector}-{identity}",
        detector=detector,
        task=task,
        threshold=threshold,
        objective=objective,
        target_fpr=target_fpr,
        validation_records=len(record_ids),
        validation_sha256=digest,
        created_at=datetime.now(timezone.utc).isoformat(),
        evaluation_sha256=evaluation_digest if risk_control is not None else None,
        validation_true_positives=metrics.tp if risk_control is not None else None,
        validation_recall=metrics.recall if risk_control is not None else None,
        risk_control=risk_control,
    )
    return policy, metrics
