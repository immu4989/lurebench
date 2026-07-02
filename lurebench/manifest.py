"""Dataset composition manifest.

Ships next to every shard so imbalance is visible rather than hidden. Counts the
realized ``typology x source x generator x language`` cells plus headline totals.
"""

from __future__ import annotations

from collections import Counter
from typing import Dict, List, Sequence

from .schema import Lure


def build_manifest(records: Sequence[Lure]) -> dict:
    n = len(records)
    n_fraud = sum(1 for r in records if r.label == 1)
    n_ai = sum(1 for r in records if r.source == "ai")

    by_typology: Counter = Counter(r.typology for r in records)
    by_source: Counter = Counter(r.source for r in records)
    by_generator: Counter = Counter(r.generator for r in records if r.generator)
    by_language: Counter = Counter(r.language for r in records)

    cells: Dict[str, int] = Counter()
    for r in records:
        key = f"{r.typology}|{r.source}|{r.generator or 'na'}|{r.language}"
        cells[key] += 1

    return {
        "n": n,
        "n_fraud": n_fraud,
        "n_benign": n - n_fraud,
        "fraud_ratio": round(n_fraud / n, 4) if n else 0.0,
        "n_ai": n_ai,
        "n_human": n - n_ai,
        "ai_ratio": round(n_ai / n, 4) if n else 0.0,
        "by_typology": dict(by_typology),
        "by_source": dict(by_source),
        "by_generator": dict(by_generator),
        "by_language": dict(by_language),
        "cells": dict(cells),
    }


def check_balance(manifest: dict) -> List[str]:
    """Return human-readable warnings when v1 balance targets are violated."""
    warnings: List[str] = []
    fr = manifest.get("fraud_ratio", 0.0)
    if not (0.45 <= fr <= 0.55):
        warnings.append(f"fraud_ratio {fr:.2f} outside target 0.45-0.55")

    fraud_typs = {"phishing", "bec", "romance", "pig_butchering"}
    typ_counts = {k: v for k, v in manifest.get("by_typology", {}).items() if k in fraud_typs}
    total_fraud = sum(typ_counts.values())
    if total_fraud:
        for typ in fraud_typs:
            share = typ_counts.get(typ, 0) / total_fraud
            if share < 0.15:
                warnings.append(f"typology '{typ}' is {share:.0%} of fraud (target >= 15%)")
            elif share > 0.35:
                warnings.append(f"typology '{typ}' is {share:.0%} of fraud (target <= 35%)")
    return warnings
