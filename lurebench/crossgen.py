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

import hashlib
from dataclasses import asdict, dataclass
from typing import List, Optional, Sequence

from .lineage import lineage_components
from .metrics import evaluate
from .probability import DetectorAbstainedError, validate_score, validate_threshold
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
    split_mode: str = "legacy_index"
    n_train_ai: int = 0
    n_train_human: int = 0
    train_lineage_components: int = 0
    test_lineage_components: int = 0
    overlapping_lineage_components: int = 0

    def as_dict(self) -> dict:
        return asdict(self)


def cross_generator_provenance(
    records: Sequence[Lure],
    detector_cls=None,
    threshold: float = 0.5,
    human_holdout_k: int = 5,
    split_mode: str = "lineage_disjoint",
) -> List[FoldResult]:
    """Leave-one-generator-out provenance eval. One :class:`FoldResult` per generator.

    By default hold out declared lineage components in addition to generator
    identity: only held-out-family records enter evaluation, and none enter
    training. Historical index splits are available explicitly for reproduction.

    Args:
        records: human (negatives) + AI-from->=2-generators (positives).
        detector_cls: a detector class exposing ``.train(records, task="provenance")``
            and ``.score(lure)``. Defaults to ``TfidfLogisticDetector``.
        threshold: decision threshold for recall/FPR (AUC and balanced-accuracy are
            reported alongside and are more robust to a mis-set threshold).
        human_holdout_k: 1/k of human records are held out for the FPR estimate.
        split_mode: lineage_disjoint (default) or historical legacy_index.
    """
    threshold = validate_threshold(threshold)
    if type(human_holdout_k) is not int or not 2 <= human_holdout_k <= 100:
        raise ValueError("human_holdout_k must be an integer between 2 and 100")
    if split_mode not in ("lineage_disjoint", "legacy_index"):
        raise ValueError("unsupported cross-generator split mode")
    components = lineage_components(records)
    if any(r.source == "ai" and not r.generator for r in records):
        raise ValueError("every AI record requires a generator identity")

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

    # Versioned component hash does not inherit any corpus train/test assignment.
    if split_mode == "legacy_index":
        human_tr = [r for i, r in enumerate(human) if i % human_holdout_k != 0]
        human_te = [r for i, r in enumerate(human) if i % human_holdout_k == 0]
        held_families = set()
    else:
        held_families = {family for family in set(components.values()) if int.from_bytes(
            hashlib.sha256(("lurebench-logo-lineage-v1\0" + family).encode("utf-8")).digest(),
            "big",
        ) % human_holdout_k == 0}
        human_tr = [r for r in human if components[r.id] not in held_families]
        human_te = [r for r in human if components[r.id] in held_families]

    folds = []
    for g in gens:
        ai_tr = [r for r in ai if r.generator != g and (
            split_mode == "legacy_index" or components[r.id] not in held_families)]
        ai_te = [r for r in ai if r.generator == g and (
            split_mode == "legacy_index" or components[r.id] in held_families)]
        if not all((human_tr, human_te, ai_tr, ai_te)):
            raise ValueError("each fold requires both classes in training and test; no training started")
        train, test = human_tr + ai_tr, human_te + ai_te
        if split_mode == "lineage_disjoint":
            train, test = sorted(train, key=lambda r: r.id), sorted(test, key=lambda r: r.id)
        folds.append((g, train, test, len(ai_tr), len(ai_te)))

    if detector_cls is None:
        from .detectors.tfidf import TfidfLogisticDetector

        detector_cls = TfidfLogisticDetector

    results: List[FoldResult] = []
    for g, train, test, n_train_ai, n_test_ai in folds:
        det = detector_cls.train(train, task="provenance")
        y_true = [int(r.source == "ai") for r in test]
        scores = [validate_score(det.score(r)) for r in test]
        if any(score is None for score in scores):
            raise DetectorAbstainedError("cross-generator evaluation requires complete scores")
        y_pred = [int(s >= threshold) for s in scores]
        m = evaluate(y_true, y_pred, scores)
        results.append(
            FoldResult(
                held_out=g,
                auc=m.auc,
                balanced_accuracy=m.balanced_accuracy,
                recall=m.recall,
                fpr=m.fpr,
                n_test_ai=n_test_ai,
                n_test_human=len(human_te),
                split_mode=split_mode, n_train_ai=n_train_ai, n_train_human=len(human_tr),
                train_lineage_components=len({components[r.id] for r in train}),
                test_lineage_components=len({components[r.id] for r in test}),
                overlapping_lineage_components=len({components[r.id] for r in train}
                                                   & {components[r.id] for r in test}),
            )
        )
    return results


def render_markdown(results: Sequence[FoldResult], dataset_label: str) -> str:
    lines = [
        "# Cross-generator provenance (leave-one-generator-out)\n",
        "AUC measures ranking without selecting a decision threshold. Balanced accuracy, "
        "recall, and FPR depend on the supplied threshold. Values near 0.5 do not by "
        "themselves prove equivalence to chance or population non-generalization.\n",
        f"_Trained/evaluated on **{dataset_label}**._\n",
        "| Held-out generator | AUC | balanced acc | recall | FPR | test AI | split | lineage overlaps |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in results:
        auc = f"{r.auc:.3f}" if r.auc is not None else " - "
        lines.append(
            f"| `{r.held_out}` | {auc} | {r.balanced_accuracy:.3f} | "
            f"{r.recall:.2f} | {r.fpr:.2f} | {r.n_test_ai} | {r.split_mode} | "
            f"{r.overlapping_lineage_components} |"
        )
    lines.append("\nDeclared-lineage separation is not a semantic deduplication or independence "
                 "guarantee. Legacy index splits can share seed families across train/test. "
                 "Overlapping folds are not independent replicates.")
    return "\n".join(lines)
