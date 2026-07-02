"""Leaderboard generation.

Runs detectors over a dataset and renders results as Markdown + JSON. Beyond the
headline metrics, it computes the slices that make LureBench worth having:

  * fraud detectors -> detection rate (recall) per fraud typology
  * provenance detectors -> detection rate per generator

A detector that looks fine overall but misses ``pig_butchering`` or collapses on
one generator is exactly what these slices surface.
"""

from __future__ import annotations

import json
from typing import Callable, Dict, List, Optional, Sequence

from .detectors import get_detector
from .harness import TASK_TARGET, run
from .schema import Lure

FRAUD_TYPOLOGIES = ["phishing", "bec", "romance", "pig_butchering"]


def _recall_on_subset(
    detector, subset: Sequence[Lure], target: Callable[[Lure], int], threshold: float
) -> Optional[float]:
    positives = [r for r in subset if target(r) == 1]
    if not positives:
        return None
    hits = 0
    for rec in positives:
        score = detector.score(rec)
        if score is not None and float(score) >= threshold:
            hits += 1
    return hits / len(positives)


def evaluate_detectors(
    dataset: Sequence[Lure],
    detector_names: Sequence[str],
    threshold: float = 0.5,
) -> List[dict]:
    """Return one result entry per detector (or an error entry if it can't run)."""
    results: List[dict] = []
    for name in detector_names:
        # A single detector failing (missing extra, gated model, no API key,
        # network error, scoring exception) must never take down the whole
        # leaderboard, so everything from construction through scoring is guarded.
        try:
            detector = get_detector(name)
            task = getattr(detector, "task", "fraud")
            report = run(detector, dataset, threshold=threshold, task=task)
            target = TASK_TARGET[task]
            slices: Dict[str, Optional[float]] = {}

            if task == "fraud":
                for typ in FRAUD_TYPOLOGIES:
                    subset = [r for r in dataset if r.typology == typ]
                    slices[typ] = _recall_on_subset(detector, subset, target, threshold)
            else:  # provenance
                generators = sorted(
                    {r.generator for r in dataset if r.source == "ai" and r.generator}
                )
                for gen in generators:
                    subset = [r for r in dataset if r.generator == gen]
                    slices[gen] = _recall_on_subset(detector, subset, target, threshold)

            results.append(
                {
                    "detector": report.detector,
                    "task": report.task,
                    "threshold": threshold,
                    "metrics": report.metrics.as_dict(),
                    "slices": slices,
                }
            )
        except Exception as exc:  # noqa: BLE001 - deliberately resilient
            results.append({"detector": name, "error": f"{type(exc).__name__}: {exc}"})
    return results


def _fmt(value: Optional[float], places: int = 3) -> str:
    return f"{value:.{places}f}" if isinstance(value, (int, float)) else " - "


def render_markdown(results: Sequence[dict], dataset_label: str, n_records: int) -> str:
    ok = [r for r in results if "error" not in r]
    lines: List[str] = []
    lines.append("# Leaderboard\n")
    lines.append(
        "MCC is the headline metric. Detection rate (recall) and FPR matter because a "
        "fraud detector is only useful at a tolerable false-positive rate.\n"
    )
    lines.append(f"_Generated from **{dataset_label}** ({n_records} records)._\n")

    fraud = [r for r in ok if r["task"] == "fraud"]
    prov = [r for r in ok if r["task"] == "provenance"]

    if fraud:
        lines.append("## Task: `fraud` (lure vs. benign)\n")
        lines.append("| Detector | MCC | TPR | FPR | F1 | AUC |")
        lines.append("|---|---|---|---|---|---|")
        for r in fraud:
            m = r["metrics"]
            lines.append(
                f"| `{r['detector']}` | {_fmt(m['mcc'])} | {_fmt(m['recall'])} | "
                f"{_fmt(m['fpr'])} | {_fmt(m['f1'])} | {_fmt(m['auc'])} |"
            )
        lines.append("\n### Detection rate by fraud typology\n")
        header = "| Detector | " + " | ".join(f"`{t}`" for t in FRAUD_TYPOLOGIES) + " |"
        lines.append(header)
        lines.append("|---" * (len(FRAUD_TYPOLOGIES) + 1) + "|")
        for r in fraud:
            cells = " | ".join(_fmt(r["slices"].get(t)) for t in FRAUD_TYPOLOGIES)
            lines.append(f"| `{r['detector']}` | {cells} |")
        lines.append("")

    if prov:
        lines.append("## Task: `provenance` (AI vs. human)\n")
        lines.append("| Detector | MCC | TPR | FPR | F1 | AUC |")
        lines.append("|---|---|---|---|---|---|")
        for r in prov:
            m = r["metrics"]
            lines.append(
                f"| `{r['detector']}` | {_fmt(m['mcc'])} | {_fmt(m['recall'])} | "
                f"{_fmt(m['fpr'])} | {_fmt(m['f1'])} | {_fmt(m['auc'])} |"
            )
        lines.append("")

    skipped = [r for r in results if "error" in r]
    if skipped:
        lines.append("## Not run\n")
        for r in skipped:
            lines.append(f"- `{r['detector']}`: {r['error'].splitlines()[0]}")
        lines.append("")

    return "\n".join(lines)


def write_json(results: Sequence[dict], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(list(results), fh, indent=2)
