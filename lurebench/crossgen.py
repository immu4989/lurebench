"""Cross-generator (leave-one-generator-out) provenance evaluation.

This operationalizes LureBench's headline finding: once human and AI lures are
distribution-matched, a detector trained on some generators barely beats chance on
a *held-out* generator it never trained on. Because that is a train-and-evaluate
loop, it applies to trainable detectors (``tfidf-logreg`` by default).

Point it at a dataset that contains both ``source="human"`` records (the negative
class) and ``source="ai"`` records from two or more generators (the positive
class). On a distribution-matched paired set the AUC falls toward the 0.5 chance
line; on a naively-assembled corpus it stays near 1.0 (the confound).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import List, Optional, Sequence

from .metrics import evaluate
from .schema import Lure
from .splits import ai_generators


@dataclass
class FoldResult:
    held_out: str
    auc: Optional[float]
    balanced_accuracy: float
    recall: float          # of held-out generator's AI lures flagged as AI
    fpr: float             # of human lures wrongly flagged as AI
    n_test_ai: int
    n_test_human: int

    def as_dict(self) -> dict:
        return asdict(self)


def cross_generator_provenance(
    records: Sequence[Lure],
    detector_cls=None,
    threshold: float = 0.5,
    human_holdout_k: int = 5,
) -> List[FoldResult]:
    """Leave-one-generator-out provenance eval. One :class:`FoldResult` per generator.

    For each generator ``g``: train the detector on human + AI-from-other-generators,
    then test on ``g``'s AI lures (recall) plus a held-out slice of human lures (FPR).

    Args:
        records: human (negatives) + AI-from->=2-generators (positives).
        detector_cls: a detector class exposing ``.train(records, task="provenance")``
            and ``.score(lure)``. Defaults to ``TfidfLogisticDetector``.
        threshold: decision threshold for recall/FPR (AUC and balanced-accuracy are
            reported alongside and are more robust to a mis-set threshold).
        human_holdout_k: 1/k of human records are held out for the FPR estimate.
    """
    if detector_cls is None:
        from .detectors.tfidf import TfidfLogisticDetector

        detector_cls = TfidfLogisticDetector

    gens = ai_generators(records)
    if len(gens) < 2:
        raise ValueError(
            f"leave-one-generator-out needs >= 2 AI generators, found {gens}. "
            "The dataset must contain source='ai' records from multiple generators."
        )
    human = [r for r in records if r.source == "human"]
    ai = [r for r in records if r.source == "ai" and r.generator]
    if not human:
        raise ValueError("no source='human' records to use as the negative class")

    # Index-based human holdout: these records often all come from a corpus train
    # split, so the corpus id-hash can't provide a holdout here.
    human_tr = [r for i, r in enumerate(human) if i % human_holdout_k != 0]
    human_te = [r for i, r in enumerate(human) if i % human_holdout_k == 0]

    results: List[FoldResult] = []
    for g in gens:
        ai_tr = [r for r in ai if r.generator != g]
        ai_te = [r for r in ai if r.generator == g]
        det = detector_cls.train(human_tr + ai_tr, task="provenance")

        test = human_te + ai_te
        y_true = [0] * len(human_te) + [1] * len(ai_te)
        scores = [float(det.score(r)) for r in test]
        y_pred = [int(s >= threshold) for s in scores]
        m = evaluate(y_true, y_pred, scores)
        results.append(
            FoldResult(
                held_out=g,
                auc=m.auc,
                balanced_accuracy=m.balanced_accuracy,
                recall=m.recall,
                fpr=m.fpr,
                n_test_ai=len(ai_te),
                n_test_human=len(human_te),
            )
        )
    return results


def render_markdown(results: Sequence[FoldResult], dataset_label: str) -> str:
    lines = [
        "# Cross-generator provenance (leave-one-generator-out)\n",
        "AUC and balanced accuracy are threshold-independent. 0.5 = chance. A drop "
        "toward 0.5 means AI-vs-human authorship does not generalize to the held-out "
        "generator.\n",
        f"_Trained/evaluated on **{dataset_label}**._\n",
        "| Held-out generator | AUC | balanced acc | recall | FPR | test AI |",
        "|---|---|---|---|---|---|",
    ]
    for r in results:
        auc = f"{r.auc:.3f}" if r.auc is not None else " - "
        lines.append(
            f"| `{r.held_out}` | {auc} | {r.balanced_accuracy:.3f} | "
            f"{r.recall:.2f} | {r.fpr:.2f} | {r.n_test_ai} |"
        )
    return "\n".join(lines)
