"""Evaluation harness: run a detector over a dataset and score it.

The harness picks the ground-truth target based on the detector's task:

  * ``fraud``      target = ``lure.label``            (1 = fraud, 0 = benign)
  * ``provenance`` target = ``1 if lure.source == 'ai' else 0``

This split matters: a machine-generated-text detector (e.g. Binoculars) answers
the ``provenance`` question, while a content-safety model (e.g. Llama Guard) or a
spam filter answers the ``fraud`` question. Scoring them against the wrong target
is the most common way this literature reports misleading numbers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence

from .calibration import (
    ConfidenceInterval,
    UndefinedBootstrapStatistic,
    bootstrap_ci,
    validate_bootstrap_configuration,
)
from .metrics import (
    Metrics,
    confusion,
    evaluate,
    mcc_from_confusion,
    roc_auc,
    validate_binary_labels,
)
from .probability import validate_score, validate_threshold
from .schema import Lure, copy_lures

TASK_TARGET: Dict[str, Callable[[Lure], int]] = {
    "fraud": lambda lure: lure.label,
    "provenance": lambda lure: 1 if lure.source == "ai" else 0,
}


def _resolve_task(detector, task: Optional[str]) -> str:
    selected = getattr(detector, "task", "fraud") if task is None else task
    if not isinstance(selected, str) or selected not in TASK_TARGET:
        raise ValueError("task must be fraud or provenance")
    return selected


def _prepare_records(dataset: Sequence[Lure], task: str):
    """Validate and detach all inputs before any detector callback.

    Capture targets and IDs separately from the mutable copies passed to the
    detector. This is ordinary object isolation, not an in-process sandbox or
    an atomic snapshot of caller data mutated concurrently during preparation.
    """
    return [(record, record.id, TASK_TARGET[task](record)) for record in copy_lures(dataset)]


def collect_scores(detector, dataset: Sequence[Lure], task: Optional[str] = None):
    """Return answered IDs, captured targets, and scores from isolated records."""
    task = _resolve_task(detector, task)
    prepared = _prepare_records(dataset, task)
    ids: List[str] = []
    y_true: List[int] = []
    scores: List[float] = []
    for lure, record_id, truth in prepared:
        score = validate_score(detector.score(lure))
        if score is not None:
            ids.append(record_id)
            y_true.append(truth)
            scores.append(score)
    return ids, y_true, scores


@dataclass(frozen=True)
class MetricIntervalResult:
    status: str
    interval: Optional[ConfidenceInterval]
    requested_replicates: int
    executed_replicates: int


@dataclass
class Report:
    detector: str
    task: str
    threshold: float
    metrics: Metrics
    n_skipped: int = 0
    observations: Optional[List[tuple[int, float]]] = None
    n_abstained_positive: int = 0
    n_abstained_negative: int = 0
    record_scores: Optional[List[Optional[float]]] = None

    def decision_counts(self) -> dict:
        """Export all six outcomes without silently dropping abstentions."""
        self.coverage_summary()  # reject inconsistent manually constructed reports
        if self.task not in TASK_TARGET or not isinstance(self.detector, str) or not (
            1 <= len(self.detector) <= 256
        ) or any(ord(c) < 32 or ord(c) == 127 for c in self.detector):
            raise ValueError("decision-count detector identity or task is invalid")
        counts = {"tp": self.metrics.tp, "fp": self.metrics.fp,
                  "tn": self.metrics.tn, "fn": self.metrics.fn,
                  "abstained_positive": self.n_abstained_positive,
                  "abstained_negative": self.n_abstained_negative}
        if any(type(n) is not int or not 0 <= n <= 10_000_000 for n in counts.values()):
            raise ValueError("decision counts exceed the export contract")
        return {
            "schema_version": 1, "task": self.task, "detector": self.detector,
            "threshold": validate_threshold(self.threshold), "counts": counts,
        }

    def coverage_summary(self) -> dict:
        """Disclose class-specific missingness and binary-completion bounds.

        Bounds describe arbitrary binary resolutions of missing predictions,
        not confidence intervals or a recommended deployment abstention policy.
        """
        if (
            type(self.n_skipped) is not int or self.n_skipped < 0
            or type(self.n_abstained_positive) is not int or self.n_abstained_positive < 0
            or type(self.n_abstained_negative) is not int or self.n_abstained_negative < 0
            or self.n_skipped != self.n_abstained_positive + self.n_abstained_negative
        ):
            raise ValueError("report abstention accounting is inconsistent")
        m = self.metrics
        positive_answered = m.tp + m.fn
        negative_answered = m.tn + m.fp
        positive_total = positive_answered + self.n_abstained_positive
        negative_total = negative_answered + self.n_abstained_negative
        total = positive_total + negative_total

        def bounds(observed, missing, denominator):
            if not denominator:
                return None
            return {"lower": observed / denominator,
                    "upper": (observed + missing) / denominator}

        def cohort(answered, missing):
            size = answered + missing
            return {"records": size, "answered": answered, "abstained": missing,
                    "answer_coverage": answered / size if size else None}

        return {
            "records": total, "answered": m.n, "abstained": self.n_skipped,
            "answer_coverage": m.n / total if total else None,
            "by_class": {
                "positive": cohort(positive_answered, self.n_abstained_positive),
                "negative": cohort(negative_answered, self.n_abstained_negative),
            },
            "binary_completion_bounds": {
                "accuracy": bounds(m.tp + m.tn, self.n_skipped, total),
                "recall": bounds(m.tp, self.n_abstained_positive, positive_total),
                "fpr": bounds(m.fp, self.n_abstained_negative, negative_total),
            },
            "limitations": [
                "headline_metrics_are_conditional_on_answered_records",
                "bounds_are_logical_binary_completions_not_statistical_confidence_intervals",
                "no_claim_about_missingness_randomness_or_deployment_abstention_policy",
            ],
        }

    def summary_line(self) -> str:
        m = self.metrics
        auc = f"{m.auc:.3f}" if m.auc is not None else "  -  "
        return (
            f"{self.detector:<22} task={self.task:<10} "
            f"MCC={m.mcc:+.3f}  TPR={m.recall:.3f}  FPR={m.fpr:.3f}  "
            f"F1={m.f1:.3f}  AUC={auc}  n={m.n}  abstained={self.n_skipped}"
        )

    def confidence_intervals(
        self, replicates: int = 2000, confidence: float = 0.95, seed: int = 4989
    ) -> Dict[str, ConfidenceInterval]:
        validate_bootstrap_configuration(replicates, confidence, seed, len(self.observations or []))
        observations = self._interval_observations()
        if not observations:
            raise ValueError("report has no scored observations")
        return {
            name: bootstrap_ci(
                observations, statistic, replicates=replicates,
                confidence=confidence, seed=seed,
            )
            for name, statistic in self._bootstrap_statistics().items()
        }

    def _interval_observations(self):
        observations = [(truth, validate_threshold(score)) for truth, score in (self.observations or [])]
        validate_binary_labels([truth for truth, _ in observations])
        return observations

    def _bootstrap_statistics(self):
        threshold = validate_threshold(self.threshold)
        def metric(name: str):
            def statistic(truths, scores):
                predictions = [int(score >= threshold) for score in scores]
                tp, fp, tn, fn = confusion(truths, predictions)
                # These three statistics need no sorting or threshold sweep.
                # Retain the legacy zero-denominator convention exactly.
                if name == "mcc":
                    return mcc_from_confusion(tp, fp, tn, fn)
                if name == "recall":
                    return tp / (tp + fn) if tp + fn else 0.0
                return fp / (fp + tn) if fp + tn else 0.0
            return statistic

        def auc(truths, scores):
            value = roc_auc(truths, scores)
            return float("nan") if value is None else value

        return {"mcc": metric("mcc"), "recall": metric("recall"),
                "fpr": metric("fpr"), "auc": auc}

    def confidence_interval_results(
        self, replicates: int = 2000, confidence: float = 0.95, seed: int = 4989,
    ) -> Dict[str, MetricIntervalResult]:
        """Legacy scored-record intervals with explicit per-metric availability.

        Unlike confidence_intervals, missing statistics do not discard other
        intervals. Invalid inputs and unexpected calculation failures still raise.
        Fewer than two answered observations produces no interval. Legacy zero-
        denominator metric conventions remain; use uncertainty-cached for the
        strict, full-population, declared-lineage uncertainty contract.
        """
        validate_bootstrap_configuration(replicates, confidence, seed, len(self.observations or []))
        observations = self._interval_observations()
        results = {}
        for name, statistic in self._bootstrap_statistics().items():
            if len(observations) < 2:
                status = "no_scored_observations" if not observations else "insufficient_observations"
                results[name] = MetricIntervalResult(status, None, replicates, 0)
                continue
            try:
                interval = bootstrap_ci(observations, statistic, replicates, confidence, seed)
            except UndefinedBootstrapStatistic as exc:
                executed = replicates if exc.status == "no_defined_replicates" else 0
                results[name] = MetricIntervalResult(exc.status, None, replicates, executed)
            else:
                results[name] = MetricIntervalResult("available", interval, replicates, replicates)
        return results


def run(
    detector,
    dataset: Sequence[Lure],
    threshold: float = 0.5,
    task: Optional[str] = None,
) -> Report:
    """Score ``detector`` over ``dataset``.

    Args:
        detector: An object exposing ``score(lure) -> float in [0, 1]`` and an
            optional ``task`` / ``name`` attribute.
        dataset: Sequence of :class:`Lure`, copied and validated before callbacks.
        threshold: Decision threshold applied to the score.
        task: Override the detector's declared task (``fraud`` or ``provenance``).
    """
    threshold = validate_threshold(threshold)
    task = _resolve_task(detector, task)
    prepared = _prepare_records(dataset, task)

    y_true: List[int] = []
    y_pred: List[int] = []
    scores: List[float] = []
    skipped = 0
    skipped_positive = skipped_negative = 0
    record_scores: List[Optional[float]] = []

    for lure, _, truth in prepared:
        score = validate_score(detector.score(lure))
        record_scores.append(score)
        if score is None:  # detector abstains on this record
            skipped += 1
            if truth == 1:
                skipped_positive += 1
            else:
                skipped_negative += 1
            continue
        scores.append(score)
        y_pred.append(int(score >= threshold))
        y_true.append(truth)

    metrics = evaluate(y_true, y_pred, scores)
    return Report(
        detector=getattr(detector, "name", detector.__class__.__name__),
        task=task,
        threshold=threshold,
        metrics=metrics,
        n_skipped=skipped,
        observations=list(zip(y_true, scores, strict=True)),
        n_abstained_positive=skipped_positive,
        n_abstained_negative=skipped_negative,
        record_scores=record_scores,
    )
