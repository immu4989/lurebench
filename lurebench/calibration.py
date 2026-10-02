"""Validation-only threshold selection, calibration diagnostics and uncertainty."""

from __future__ import annotations

import hashlib
import json
import math
import os
import random
import re
import stat
import tempfile
from bisect import bisect_left
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Optional, Sequence, Tuple

from .local_io import read_regular_file
from .metrics import Metrics, evaluate, mcc_from_confusion, validate_binary_labels
from .probability import validate_threshold

RISK_CONTROL_METHOD = "learn_then_test_fixed_sequence_exact_binomial_v1"
MAX_POLICY_BYTES = 64 * 1024
MAX_POLICY_RECORDS = 10_000_000


def _validate_observations(y_true, scores):
    if len(y_true) != len(scores):
        raise ValueError("y_true and scores length mismatch")
    validate_binary_labels(y_true)
    return [validate_threshold(score) for score in scores]


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
    requested_replicates: int = 0
    undefined_replicates: int = 0
    conditional_on_defined: bool = False


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
        """Validate before atomic replacement; retain the previous file on failure."""
        _validate_policy(self)
        payload = (json.dumps(self.as_dict(), indent=2, sort_keys=True,
                              allow_nan=False) + "\n").encode("utf-8")
        if len(payload) > MAX_POLICY_BYTES:
            raise ValueError("decision policy exceeds its bounded size")
        target = Path(path)
        if target.parent.is_symlink() or target.is_symlink() or (
            target.exists() and not stat.S_ISREG(target.lstat().st_mode)
        ):
            raise ValueError("policy output must be a regular non-symlink file")
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="wb", dir=target.parent, delete=False,
                                             prefix=f".{target.name}.", suffix=".tmp") as handle:
                temporary = Path(handle.name)
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, target)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    @classmethod
    def load(cls, path: str, *, expected_sha256: str | None = None) -> "DecisionPolicy":
        from .receipts import loads_strict_json

        if expected_sha256 is not None and (
            not isinstance(expected_sha256, str)
            or not re.fullmatch(r"[a-f0-9]{64}", expected_sha256)
        ):
            raise ValueError("policy pin must be a lowercase SHA-256 digest")
        raw = read_regular_file(
            Path(path), maximum=MAX_POLICY_BYTES, label="decision policy",
        )
        if expected_sha256 is not None and hashlib.sha256(raw).hexdigest() != expected_sha256:
            raise ValueError("decision policy digest mismatch")
        payload = loads_strict_json(raw)
        if not isinstance(payload, dict):
            raise ValueError("decision policy must be a JSON object")
        try:
            if payload.get("risk_control") is not None:
                if not isinstance(payload["risk_control"], dict):
                    raise ValueError("risk_control must be an object")
                payload["risk_control"] = RiskControl(**payload["risk_control"])
            policy = cls(**payload)
        except TypeError:
            raise ValueError("policy has missing or unsupported fields") from None
        _validate_policy(policy)
        return policy


def _validate_policy(policy: DecisionPolicy) -> None:
    """Check exported policy structure and count arithmetic, not its authenticity."""
    if type(policy.schema_version) is not int or policy.schema_version not in (1, 2):
        raise ValueError("unsupported policy schema")
    for value in (policy.policy_id, policy.detector, policy.objective):
        if not isinstance(value, str) or not 1 <= len(value) <= 256 or any(
            ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value
        ):
            raise ValueError("policy identities must be bounded strings without controls")
    if policy.task not in ("fraud", "provenance"):
        raise ValueError("unsupported policy task")
    validate_threshold(policy.threshold)
    if type(policy.validation_records) is not int or not 1 <= policy.validation_records <= MAX_POLICY_RECORDS:
        raise ValueError("policy validation count is invalid")
    if not isinstance(policy.validation_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", policy.validation_sha256):
        raise ValueError("policy validation digest is invalid")
    if not isinstance(policy.created_at, str):
        raise ValueError("policy timestamp must be a string")
    if policy.created_at:
        try:
            timestamp = datetime.fromisoformat(policy.created_at.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("policy timestamp is invalid") from None
        if timestamp.tzinfo is None:
            raise ValueError("policy timestamp requires a timezone")
    elif policy.schema_version == 2:
        raise ValueError("schema v2 requires a timestamp")
    if policy.target_fpr is not None:
        validate_threshold(policy.target_fpr)
    if policy.schema_version == 1:
        if policy.objective not in ("max_mcc", "target_fpr"):
            raise ValueError("unsupported empirical objective")
        if policy.objective == "target_fpr" and policy.target_fpr is None:
            raise ValueError("empirical target policy requires target_fpr")
        if any(value is not None for value in (
            policy.risk_control, policy.evaluation_sha256, policy.validation_true_positives,
            policy.validation_recall,
        )):
            raise ValueError("schema v1 cannot carry v2 risk-control evidence")
        return
    if policy.objective != "risk_controlled_fpr" or policy.target_fpr is None or not 0 < policy.target_fpr < 1:
        raise ValueError("schema v2 requires a risk-controlled objective and open-interval target")
    if not isinstance(policy.evaluation_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", policy.evaluation_sha256):
        raise ValueError("policy evaluation digest is invalid")
    control = policy.risk_control
    if not isinstance(control, RiskControl) or control.method != RISK_CONTROL_METHOD or control.risk != "false_positive_rate":
        raise ValueError("unsupported risk-control evidence")
    confidence = validate_threshold(control.confidence)
    if not 0 < confidence < 1:
        raise ValueError("confidence must be strictly between zero and one")
    for value in (control.empirical_fpr, control.upper_confidence_bound, control.hypothesis_p_value):
        validate_threshold(value)
    if type(control.threshold_grid_size) is not int or not 2 <= control.threshold_grid_size <= 100_001:
        raise ValueError("invalid threshold grid size")
    position = policy.threshold * (control.threshold_grid_size - 1)
    if not math.isclose(position, round(position), rel_tol=0., abs_tol=1e-10):
        raise ValueError("threshold is not on the declared grid")
    if type(control.validation_negatives) is not int or not 1 <= control.validation_negatives < policy.validation_records:
        raise ValueError("risk-controlled policy requires both validation classes")
    if type(control.false_positives) is not int or not 0 <= control.false_positives <= control.validation_negatives:
        raise ValueError("invalid false-positive count")
    positives = policy.validation_records - control.validation_negatives
    if type(policy.validation_true_positives) is not int or not 0 <= policy.validation_true_positives <= positives:
        raise ValueError("invalid true-positive count")
    validate_threshold(policy.validation_recall)
    expected_p = binomial_cdf(control.false_positives, control.validation_negatives, policy.target_fpr)
    expected_upper = clopper_pearson_upper(control.false_positives, control.validation_negatives, confidence)
    for actual, expected in (
        (control.empirical_fpr, control.false_positives / control.validation_negatives),
        (policy.validation_recall, policy.validation_true_positives / positives),
        (control.hypothesis_p_value, expected_p),
        (control.upper_confidence_bound, expected_upper),
    ):
        if not math.isclose(actual, expected, rel_tol=0., abs_tol=1e-12):
            raise ValueError("risk-control evidence is inconsistent with declared counts")
    if expected_p > 1 - confidence + 1e-12 or expected_upper > policy.target_fpr + 1e-12:
        raise ValueError("declared counts do not establish the target FPR bound")


def binomial_cdf(events: int, trials: int, probability: float) -> float:
    """Return ``P[X <= events]`` for ``X ~ Binomial(trials, probability)``.

    The implementation starts at a binomial mode, assigns it unit weight, and
    recurs toward both tails before normalizing with ``math.fsum``. Starting at
    the mode avoids underflow; normalization avoids cancellation in log-gamma
    formulas for large samples while keeping LureBench's core dependency-free.
    """
    if type(trials) is not int or type(events) is not int:
        raise ValueError("binomial counts must be integers")
    if trials < 0 or events < -1 or events > trials:
        raise ValueError("invalid binomial event count")
    probability = validate_threshold(probability)
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
    if type(trials) is not int or type(events) is not int:
        raise ValueError("binomial counts must be integers")
    if trials < 1 or events < 0 or events > trials:
        raise ValueError("events must be between zero and a positive trial count")
    confidence = validate_threshold(confidence)
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
    target_fpr = validate_threshold(target_fpr)
    confidence = validate_threshold(confidence)
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
    scores = _validate_observations(y_true, scores)
    target_fpr = validate_threshold(target_fpr)
    confidence = validate_threshold(confidence)
    if not 0 < target_fpr < 1:
        raise ValueError("risk-controlled FPR requires target_fpr in (0, 1)")
    if not 0 < confidence < 1:
        raise ValueError("confidence must be in (0, 1)")
    if type(threshold_grid_size) is not int or not 2 <= threshold_grid_size <= 100_001:
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
    scores = _validate_observations(y_true, scores)
    if not y_true:
        raise ValueError("calibration requires at least one record")
    if type(n_bins) is not int or not 1 <= n_bins <= 10_000:
        raise ValueError("n_bins must be an integer between 1 and 10000")
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
    scores = _validate_observations(y_true, scores)
    if objective not in {"max_mcc", "target_fpr"}:
        raise ValueError("objective must be 'max_mcc' or 'target_fpr'")
    if objective == "target_fpr":
        target_fpr = validate_threshold(target_fpr)
    ranked = sorted(zip(scores, y_true, strict=True), key=lambda item: -item[0])
    positives = sum(y_true)
    negatives = len(y_true) - positives
    tp = fp = 0
    best = None

    def consider(threshold):
        nonlocal best
        fpr = fp / negatives if negatives else 0.0
        if objective == "target_fpr" and fpr > target_fpr:
            return
        recall = tp / positives if positives else 0.0
        mcc = mcc_from_confusion(tp, fp, negatives - fp, positives - tp)
        key = ((mcc, recall, threshold) if objective == "max_mcc"
               else (recall, mcc, threshold))
        if best is None or key > best[0]:
            best = (key, threshold)

    if ranked[0][0] < 1:
        consider(math.nextafter(float(ranked[0][0]), math.inf))
    index = 0
    while index < len(ranked):
        threshold = ranked[index][0]
        # Tied observations move together: no intermediate state is realizable.
        while index < len(ranked) and ranked[index][0] == threshold:
            truth = ranked[index][1]
            tp += truth
            fp += 1 - truth
            index += 1
        consider(float(threshold))
    if best is None:
        raise ValueError("no threshold in [0, 1] satisfies the requested FPR budget")
    threshold = best[1]
    predictions = [int(score >= threshold) for score in scores]
    return threshold, evaluate(y_true, predictions, scores)


def bootstrap_ci(
    values: Sequence[Tuple[int, float]],
    statistic: Callable[[Sequence[int], Sequence[float]], float],
    replicates: int = 2000,
    confidence: float = 0.95,
    seed: int = 4989,
) -> ConfidenceInterval:
    """Paired percentile bootstrap over ``(truth, score)`` observations.

    Undefined resamples are disclosed; resulting quantiles are conditional on
    defined statistics, not an unconditional coverage guarantee.
    """
    if not values:
        raise ValueError("bootstrap requires observations")
    confidence = validate_threshold(confidence)
    if type(replicates) is not int or replicates < 1 or not 0 < confidence < 1:
        raise ValueError("invalid bootstrap configuration")
    truths = [item[0] for item in values]
    scores = [item[1] for item in values]
    scores = _validate_observations(truths, scores)
    values = list(zip(truths, scores, strict=True))
    estimate = statistic(truths, scores)
    if not math.isfinite(estimate):
        raise ValueError("statistic is undefined on the observed sample")
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
    undefined = replicates - len(draws)
    return ConfidenceInterval(
        estimate, low, high, confidence, len(draws), replicates, undefined, bool(undefined),
    )


def validate_risk_control_groups(
    record_ids: Sequence[str], y_true: Sequence[int], groups: Mapping[str, str] | None,
) -> None:
    """Reject known negative-class clustering; passing does not prove i.i.d. data.

    The exact binomial FPR procedure is record-level, not cluster-adjusted. This
    guard does not sample representatives, relabel the estimand, or repair data.
    """
    if groups is None:
        return
    if len(record_ids) != len(y_true) or len(set(record_ids)) != len(record_ids):
        raise ValueError("risk-control records must have unique IDs aligned with labels")
    validate_binary_labels(y_true)
    if not isinstance(groups, Mapping) or set(groups) != set(record_ids):
        raise ValueError("risk-control groups must cover exactly the validation record IDs")
    if any(not isinstance(value, str) or not 1 <= len(value) <= 1024 or any(
        ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value
    ) for value in groups.values()):
        raise ValueError("risk-control group identifiers must be bounded strings without controls")
    negative_groups = [groups[key] for key, label in zip(record_ids, y_true, strict=True) if label == 0]
    if len(set(negative_groups)) != len(negative_groups):
        raise ValueError(
            "risk-controlled FPR cannot treat repeated negative-class lineage as independent; "
            "supply an independently designed validation sample or use an empirical objective"
        )


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
    *, groups: Mapping[str, str] | None = None,
) -> Tuple[DecisionPolicy, Metrics]:
    if not (len(record_ids) == len(y_true) == len(scores)) or not record_ids:
        raise ValueError("record_ids, y_true and scores must have the same non-zero length")
    if len(record_ids) > MAX_POLICY_RECORDS:
        raise ValueError("policy validation record limit exceeded")
    if (
        any(not isinstance(value, str) or not 1 <= len(value) <= 1024
            or any(ord(char) < 32 or ord(char) == 127 or 0xD800 <= ord(char) <= 0xDFFF
                   for char in value)
            for value in record_ids)
        or len(set(record_ids)) != len(record_ids)
    ):
        raise ValueError("policy record IDs must be unique bounded strings without controls")
    if (
        not isinstance(detector, str) or not 1 <= len(detector) <= 256
        or any(ord(char) < 32 or ord(char) == 127 or 0xD800 <= ord(char) <= 0xDFFF
               for char in detector)
        or task not in ("fraud", "provenance")
    ):
        raise ValueError("policy detector identity or task is invalid")
    risk_control = None
    if objective == "risk_controlled_fpr":
        validate_risk_control_groups(record_ids, y_true, groups)
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
        policy_id=f"{detector[:243]}-{identity}",
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
    _validate_policy(policy)
    return policy, metrics
