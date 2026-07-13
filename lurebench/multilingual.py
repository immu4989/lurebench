"""Cross-lingual evaluation: how well does a detector hold up under a language shift?

Fraud detectors are overwhelmingly trained on English. But fraud is not — the same
lure is sent in Spanish, Portuguese, Chinese, and dozens of other languages, and the
populations most targeted by some scams are not English-first. This module measures
the gap directly: take a detector and a multilingual set of lures, and report the
detection recall *per language*. A detector that catches 96% of English lures and 5%
of the same-typology lures in another language has a deployment gap its English
benchmark score will never show.

The metric here is **recall on positives** (fraud lures flagged at the threshold), so
it needs only labelled lures per language — no per-language benign set — which keeps
the evaluation honest and easy to reproduce.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import List, Sequence

from .generate.base import language_name
from .schema import Lure

# Structural artifacts a detector can key on regardless of language — chiefly the
# defang placeholders every generated lure carries. Stripping them separates genuine
# (content-based) detection from "this text contained a URL".
_ARTIFACT_RE = re.compile(r"<<(?:link|contact)>>")


def strip_artifacts(text: str) -> str:
    return _ARTIFACT_RE.sub(" ", text)


@dataclass
class LanguageResult:
    language: str            # ISO 639-1 code
    language_name: str
    n: int                   # number of fraud lures in this language
    detected: int            # flagged at the threshold
    recall: float
    mean_score: float
    n_skipped: int = 0       # detector returned None (e.g. missing dependency)

    def summary_line(self) -> str:
        return (
            f"{self.language_name:<20} ({self.language})  "
            f"recall {self.recall:.2f}  ({self.detected}/{self.n})  "
            f"mean score {self.mean_score:.2f}"
        )


def cross_lingual_detection(
    detector,
    records: Sequence[Lure],
    threshold: float = 0.5,
    control_artifacts: bool = False,
) -> List[LanguageResult]:
    """Per-language fraud-detection recall for ``detector`` over ``records``.

    Only fraud lures (``label == 1``) are scored. Results are sorted with English
    first (the usual training language, the baseline to compare against), then by
    descending sample count. With ``control_artifacts=True``, defang placeholders are
    stripped before scoring, so language-invariant artifacts can't inflate recall.
    """
    by_lang: dict = {}
    for r in records:
        if r.label != 1:
            continue
        by_lang.setdefault(r.language, []).append(r)

    results: List[LanguageResult] = []
    for lang, recs in by_lang.items():
        detected = 0
        skipped = 0
        score_sum = 0.0
        scored = 0
        for r in recs:
            if control_artifacts:
                r = replace(r, text=strip_artifacts(r.text))
            s = detector.score(r)
            if s is None:
                skipped += 1
                continue
            s = float(s)
            score_sum += s
            scored += 1
            if s >= threshold:
                detected += 1
        n = scored
        results.append(
            LanguageResult(
                language=lang,
                language_name=language_name(lang),
                n=n,
                detected=detected,
                recall=(detected / n) if n else 0.0,
                mean_score=(score_sum / n) if n else 0.0,
                n_skipped=skipped,
            )
        )

    results.sort(key=lambda x: (x.language != "en", -x.n))
    return results


def render_markdown(results: Sequence[LanguageResult], detector_name: str) -> str:
    lines = [
        f"# Cross-lingual detection — `{detector_name}`\n",
        "Fraud-detection recall per language (fraction of lures flagged). A large drop "
        "from English is a deployment gap the English benchmark score hides.\n",
        "| Language | Code | Lures | Recall | Mean score |",
        "|---|---|---|---|---|",
    ]
    for r in results:
        lines.append(
            f"| {r.language_name} | `{r.language}` | {r.n} | "
            f"{r.recall:.2f} | {r.mean_score:.2f} |"
        )
    return "\n".join(lines)


def render_comparison(
    detector,
    records: Sequence[Lure],
    detector_name: str,
    threshold: float = 0.5,
) -> str:
    """Recall per language, raw vs artifact-controlled (defang placeholders stripped).

    A recall that holds raw but collapses once placeholders are removed is not
    cross-lingual detection — it is the detector keying on a language-invariant
    artifact (a URL became ``<<link>>``). This side-by-side view surfaces that.
    """
    raw = {r.language: r for r in cross_lingual_detection(detector, records, threshold)}
    ctrl = {r.language: r for r in
            cross_lingual_detection(detector, records, threshold, control_artifacts=True)}
    lines = [
        f"# Cross-lingual detection — `{detector_name}`\n",
        "Recall per language, **raw** vs **artifact-controlled** (defang placeholders "
        "stripped). A recall that holds raw but collapses once the placeholder is removed "
        "is an artifact, not detection.\n",
        "| Language | Code | Lures | Recall (raw) | Recall (artifact-controlled) |",
        "|---|---|---|---|---|",
    ]
    for lang, r in raw.items():
        c = ctrl.get(lang)
        lines.append(
            f"| {r.language_name} | `{lang}` | {r.n} | {r.recall:.2f} | "
            f"{c.recall:.2f} |"
        )
    return "\n".join(lines)
