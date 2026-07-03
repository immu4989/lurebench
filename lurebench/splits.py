"""Cross-generator splits for generalization evaluation.

A random train/test split lets a detector win by memorizing a generator's style,
because near-identical lures land on both sides. A **leave-one-generator-out**
(LOGO) split removes that shortcut: the held-out generator's AI lures are test-only,
so recall on them measures true cross-generator generalization.
"""

from __future__ import annotations

from typing import List, Sequence, Tuple

from .schema import Lure


def ai_generators(records: Sequence[Lure]) -> List[str]:
    """Sorted list of distinct generator ids among AI records."""
    return sorted({r.generator for r in records if r.source == "ai" and r.generator})


def leave_one_generator_out(
    records: Sequence[Lure], held_out: str
) -> Tuple[List[Lure], List[Lure]]:
    """Split so ``held_out``'s AI records are test-only (never in train).

    train = every record except AI lures from ``held_out``.
    test  = AI lures from ``held_out``.
    """
    train: List[Lure] = []
    test: List[Lure] = []
    for r in records:
        if r.source == "ai" and r.generator == held_out:
            test.append(r)
        else:
            train.append(r)
    return train, test
