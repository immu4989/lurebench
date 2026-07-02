"""Detection metrics.

Implemented in pure Python so the core benchmark has no third-party dependency.
MCC is the headline metric because it is robust to the class imbalance typical of
fraud corpora and is the metric used by the LLM-phishing detection literature.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from typing import List, Optional, Sequence, Tuple


@dataclass
class Metrics:
    n: int
    tp: int
    fp: int
    tn: int
    fn: int
    accuracy: float
    precision: float
    recall: float          # a.k.a. TPR / detection rate
    fpr: float             # false-positive rate
    f1: float
    mcc: float             # Matthews correlation coefficient (headline)
    auc: Optional[float] = None

    def as_dict(self) -> dict:
        return asdict(self)


def _safe_div(a: float, b: float) -> float:
    return a / b if b else 0.0


def confusion(y_true: Sequence[int], y_pred: Sequence[int]) -> Tuple[int, int, int, int]:
    tp = fp = tn = fn = 0
    for t, p in zip(y_true, y_pred):
        if p == 1 and t == 1:
            tp += 1
        elif p == 1 and t == 0:
            fp += 1
        elif p == 0 and t == 0:
            tn += 1
        else:
            fn += 1
    return tp, fp, tn, fn


def mcc_from_confusion(tp: int, fp: int, tn: int, fn: int) -> float:
    num = (tp * tn) - (fp * fn)
    den = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return num / den if den else 0.0


def roc_auc(y_true: Sequence[int], scores: Sequence[float]) -> Optional[float]:
    """Rank-based ROC AUC (Mann-Whitney U) with tie handling.

    Returns ``None`` when only one class is present.
    """
    paired = sorted(zip(scores, y_true), key=lambda x: x[0])
    n = len(paired)
    ranks = [0.0] * n
    i = 0
    while i < n:
        j = i
        while j < n and paired[j][0] == paired[i][0]:
            j += 1
        avg_rank = (i + 1 + j) / 2.0  # 1-based ranks i+1 .. j, averaged over ties
        for k in range(i, j):
            ranks[k] = avg_rank
        i = j
    n_pos = sum(1 for _, t in paired if t == 1)
    n_neg = n - n_pos
    if n_pos == 0 or n_neg == 0:
        return None
    sum_pos_ranks = sum(r for r, (_, t) in zip(ranks, paired) if t == 1)
    return (sum_pos_ranks - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg)


def evaluate(
    y_true: Sequence[int],
    y_pred: Sequence[int],
    scores: Optional[Sequence[float]] = None,
) -> Metrics:
    """Compute the full metric bundle from labels, predictions and optional scores."""
    if len(y_true) != len(y_pred):
        raise ValueError("y_true and y_pred length mismatch")
    tp, fp, tn, fn = confusion(y_true, y_pred)
    n = len(y_true)
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    fpr = _safe_div(fp, fp + tn)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    return Metrics(
        n=n,
        tp=tp,
        fp=fp,
        tn=tn,
        fn=fn,
        accuracy=_safe_div(tp + tn, n),
        precision=precision,
        recall=recall,
        fpr=fpr,
        f1=f1,
        mcc=mcc_from_confusion(tp, fp, tn, fn),
        auc=roc_auc(y_true, scores) if scores is not None else None,
    )
