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
import os
import re
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from .detectors import get_detector
from .detectors.cache import CachedDetector, prewarm
from .harness import TASK_TARGET, run
from .schema import Lure

FRAUD_TYPOLOGIES = ["phishing", "bec", "romance", "pig_butchering"]


def _recall_on_subset(
    detector, subset: Sequence[Lure], target: Callable[[Lure], int], threshold: float
) -> Optional[float]:
    """Recall on one slice, over the records the detector actually scored.

    Abstentions are excluded from the denominator rather than counted as misses,
    which is what :func:`~lurebench.harness.run` does for the headline metrics. The
    two must agree: when they did not, a detector that abstained on half the corpus
    reported a perfect overall TPR next to a mediocre per-slice recall, and the
    contradiction was the only hint that anything was wrong. The abstention count
    is reported alongside, so a high-recall number over a small denominator is
    visible rather than flattering.
    """
    positives = [r for r in subset if target(r) == 1]
    if not positives:
        return None
    hits = scored = 0
    for rec in positives:
        score = detector.score(rec)
        if score is None:
            continue
        scored += 1
        if float(score) >= threshold:
            hits += 1
    return (hits / scored) if scored else None


def parse_detector_spec(spec) -> Tuple[str, dict, Optional[str]]:
    """Parse a detector spec into ``(name, kwargs, display_name)``.

    Accepts a plain name, a ``(name, kwargs)`` pair, or the string form
    ``name@engine/model`` used on the command line. The model id keeps its own
    slashes, so everything after the first ``/`` is the model::

        "tfidf-logreg"                            -> ("tfidf-logreg", {}, None)
        "llm-judge@mistral"                       -> ("llm-judge", {"engine": "mistral"}, ...)
        "llm-judge@openrouter/openai/gpt-5-nano"  -> ("llm-judge",
              {"engine": "openrouter", "model": "openai/gpt-5-nano"}, ...)

    A display name is returned whenever a model is pinned, so a leaderboard can
    carry one row per model instead of several rows with the same label.
    """
    if isinstance(spec, (tuple, list)):
        name, kwargs = spec[0], dict(spec[1] or {})
        model = kwargs.get("model")
        display = f"{name} ({model})" if model else None
        return name, kwargs, display
    if "@" not in spec:
        return spec, {}, None
    name, _, rest = spec.partition("@")
    engine, _, model = rest.partition("/")
    kwargs = {"engine": engine}
    if model:
        kwargs["model"] = model
    return name, kwargs, f"{name} ({model or engine})"


def evaluate_detectors(
    dataset: Sequence[Lure],
    detector_names: Sequence,
    threshold: float = 0.5,
    task: Optional[str] = None,
    cache_dir: Optional[str] = None,
    workers: int = 8,
) -> List[dict]:
    """Return one result entry per detector (or an error entry if it can't run).

    ``task`` (``"fraud"`` or ``"provenance"``) overrides each detector's default task
    so a single dataset can be scored on either question.

    Each entry of ``detector_names`` may be a plain name, a ``(name, kwargs)`` pair,
    or a ``name@engine/model`` spec (see :func:`parse_detector_spec`), so one call
    can score several models of the same detector.

    ``cache_dir`` turns on on-disk score caching and concurrent pre-warming, which
    is what makes an API-backed detector practical here: without it the harness
    issues one blocking request per record. Results are identical either way.
    """
    results: List[dict] = []
    for spec in detector_names:
        # A single detector failing (missing extra, gated model, no API key,
        # network error, scoring exception) must never take down the whole
        # leaderboard, so everything from construction through scoring is guarded.
        name, kwargs, display = parse_detector_spec(spec)
        try:
            detector = get_detector(name, **kwargs)
            if display:
                detector.name = display
            if cache_dir:
                safe = re.sub(r"[^A-Za-z0-9._-]+", "_", getattr(detector, "name", name))
                detector = CachedDetector(detector, os.path.join(cache_dir, f"{safe}.json"))
                prewarm(detector, dataset, workers=workers)
            t = task or getattr(detector, "task", "fraud")
            report = run(detector, dataset, threshold=threshold, task=t)
            target = TASK_TARGET[t]
            slices: Dict[str, Optional[float]] = {}

            if t == "fraud":
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
                    # Carried so the reader can see the denominator: metrics are
                    # computed only over records the detector was willing to score.
                    "n_records": len(dataset),
                    "n_skipped": report.n_skipped,
                }
            )
        except Exception as exc:  # noqa: BLE001 - deliberately resilient
            results.append(
                {"detector": display or name, "error": f"{type(exc).__name__}: {exc}"}
            )
    return results


def _fmt(value: Optional[float], places: int = 3) -> str:
    return f"{value:.{places}f}" if isinstance(value, (int, float)) else " - "


def _scored(result: dict) -> str:
    """Render the denominator: how many records the detector actually scored.

    An LLM-backed detector can decline or fail to answer, and every metric beside
    this column is computed only over the records it did answer. Without this, a
    detector that abstains on half the corpus is indistinguishable from one that
    handled all of it.
    """
    n = result.get("n_records")
    skipped = result.get("n_skipped") or 0
    if not n:
        return " - "
    return f"{n - skipped}/{n}" + (f" ({skipped} abstained)" if skipped else "")


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
        lines.append("| Detector | MCC | TPR | FPR | F1 | AUC | scored |")
        lines.append("|---|---|---|---|---|---|---|")
        for r in fraud:
            m = r["metrics"]
            lines.append(
                f"| `{r['detector']}` | {_fmt(m['mcc'])} | {_fmt(m['recall'])} | "
                f"{_fmt(m['fpr'])} | {_fmt(m['f1'])} | {_fmt(m['auc'])} | {_scored(r)} |"
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
        lines.append("AUC and balanced accuracy are the honest read (0.5 = chance).\n")
        lines.append("| Detector | AUC | bal-acc | MCC | TPR | FPR | scored |")
        lines.append("|---|---|---|---|---|---|---|")
        for r in prov:
            m = r["metrics"]
            lines.append(
                f"| `{r['detector']}` | {_fmt(m['auc'])} | {_fmt(m.get('balanced_accuracy'))} | "
                f"{_fmt(m['mcc'])} | {_fmt(m['recall'])} | {_fmt(m['fpr'])} | {_scored(r)} |"
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
