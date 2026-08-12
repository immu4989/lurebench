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
        score = detector.score(lure)
        if score is not None:
            ids.append(lure.id)
            y_true.append(target(lure))
            scores.append(float(score))
    return ids, y_true, scores


@dataclass
class Report:
    detector: str
    task: str
    threshold: float
    metrics: Metrics
    n_skipped: int = 0
    observations: Optional[List[tuple[int, float]]] = None

    def summary_line(self) -> str:
        m = self.metrics
        auc = f"{m.auc:.3f}" if m.auc is not None else "  -  "
        return (
            f"{self.detector:<22} task={self.task:<10} "
            f"MCC={m.mcc:+.3f}  TPR={m.recall:.3f}  FPR={m.fpr:.3f}  "
            f"F1={m.f1:.3f}  AUC={auc}  n={m.n}"
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
    task = task or getattr(detector, "task", "fraud")
    if task not in TASK_TARGET:
        raise ValueError(f"unknown task {task!r}; expected one of {sorted(TASK_TARGET)}")
    target = TASK_TARGET[task]

    y_true: List[int] = []
    y_pred: List[int] = []
    scores: List[float] = []
    skipped = 0

    for lure in dataset:
        score = detector.score(lure)
        if score is None:  # detector abstains on this record
            skipped += 1
            continue
        score = float(score)
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
    )
