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

from .calibration import ConfidenceInterval, bootstrap_ci
from .metrics import Metrics, evaluate, roc_auc
from .probability import validate_score, validate_threshold
from .schema import Lure

TASK_TARGET: Dict[str, Callable[[Lure], int]] = {
    "fraud": lambda lure: lure.label,
    "provenance": lambda lure: 1 if lure.source == "ai" else 0,
}


def collect_scores(detector, dataset: Sequence[Lure], task: Optional[str] = None):
    """Return answered record ids, targets and scores for reusable analysis."""
    task = task or getattr(detector, "task", "fraud")
    if task not in TASK_TARGET:
        raise ValueError(f"unknown task {task!r}; expected one of {sorted(TASK_TARGET)}")
    target = TASK_TARGET[task]
    ids: List[str] = []
    y_true: List[int] = []
    scores: List[float] = []
    for lure in dataset:
        score = validate_score(detector.score(lure))
        if score is not None:
            ids.append(lure.id)
            y_true.append(target(lure))
            scores.append(score)
    return ids, y_true, scores


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
        if not self.observations:
            raise ValueError("report has no scored observations")

        def metric(name: str):
            def statistic(truths, scores):
                predictions = [int(score >= self.threshold) for score in scores]
                return float(getattr(evaluate(truths, predictions, scores), name))
            return statistic

        def auc(truths, scores):
            value = roc_auc(truths, scores)
            return float("nan") if value is None else value

        statistics = {"mcc": metric("mcc"), "recall": metric("recall"),
                      "fpr": metric("fpr"), "auc": auc}
        return {
            name: bootstrap_ci(
                self.observations, statistic, replicates=replicates,
                confidence=confidence, seed=seed,
            )
            for name, statistic in statistics.items()
        }


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
        dataset: Sequence of :class:`Lure`.
        threshold: Decision threshold applied to the score.
        task: Override the detector's declared task (``fraud`` or ``provenance``).
    """
    threshold = validate_threshold(threshold)
    task = task or getattr(detector, "task", "fraud")
    if task not in TASK_TARGET:
        raise ValueError(f"unknown task {task!r}; expected one of {sorted(TASK_TARGET)}")
    target = TASK_TARGET[task]

    y_true: List[int] = []
    y_pred: List[int] = []
    scores: List[float] = []
    skipped = 0
    skipped_positive = skipped_negative = 0
    record_scores: List[Optional[float]] = []

    for lure in dataset:
        score = validate_score(detector.score(lure))
        record_scores.append(score)
        if score is None:  # detector abstains on this record
            skipped += 1
            if target(lure) == 1:
                skipped_positive += 1
            else:
                skipped_negative += 1
            continue
        scores.append(score)
        y_pred.append(int(score >= threshold))
        y_true.append(target(lure))

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
