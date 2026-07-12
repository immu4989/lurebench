"""Adversarial robustness harness.

The question companies and regulators actually need answered: not "how good is my
fraud detector on clean data?" but "does it survive an attacker who can perturb or
rewrite the lure?" This takes the lures a detector currently catches, applies an
attack, and measures how many now slip through — the attack success rate.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import List, Sequence

from .attacks.base import Attack
from .harness import TASK_TARGET
from .schema import Lure


@dataclass
class RobustnessReport:
    detector: str
    attack: str
    task: str
    n_positives: int
    n_detected_clean: int
    n_detected_after: int
    clean_recall: float
    attacked_recall: float
    attack_success_rate: float   # of lures caught before, fraction that now evade

    def summary_line(self) -> str:
        return (
            f"{self.detector:<16} vs {self.attack:<18} "
            f"ASR={self.attack_success_rate:.2f}  "
            f"recall {self.clean_recall:.2f}->{self.attacked_recall:.2f}  "
            f"(caught {self.n_detected_clean}->{self.n_detected_after} of {self.n_positives})"
        )

    def as_dict(self) -> dict:
        from dataclasses import asdict

        return asdict(self)


def run_robustness(
    detector,
    dataset: Sequence[Lure],
    attack: Attack,
    threshold: float = 0.5,
    task: str = "fraud",
) -> RobustnessReport:
    """Apply ``attack`` to the positives ``detector`` catches; measure evasion."""
    target = TASK_TARGET[task]
    positives = [r for r in dataset if target(r) == 1]

    detected: List[Lure] = []
    for r in positives:
        s = detector.score(r)
        if s is not None and float(s) >= threshold:
            detected.append(r)

    still = 0
    for r in detected:
        attacked = replace(r, text=attack.apply(r.text))
        s = detector.score(attacked)
        if s is not None and float(s) >= threshold:
            still += 1

    n_pos = len(positives)
    return RobustnessReport(
        detector=getattr(detector, "name", detector.__class__.__name__),
        attack=attack.name,
        task=task,
        n_positives=n_pos,
        n_detected_clean=len(detected),
        n_detected_after=still,
        clean_recall=len(detected) / n_pos if n_pos else 0.0,
        attacked_recall=still / n_pos if n_pos else 0.0,
        attack_success_rate=(1 - still / len(detected)) if detected else 0.0,
    )


def render_markdown(reports: Sequence[RobustnessReport], dataset_label: str) -> str:
    lines = [
        "# Adversarial robustness\n",
        "Attack success rate (ASR) = of the lures a detector caught on clean text, the "
        "fraction that evade after the attack. Higher ASR = more brittle.\n",
        f"_Evaluated on **{dataset_label}**._\n",
        "| Detector | Attack | ASR | clean recall | attacked recall | caught |",
        "|---|---|---|---|---|---|",
    ]
    for r in reports:
        lines.append(
            f"| `{r.detector}` | `{r.attack}` | {r.attack_success_rate:.2f} | "
            f"{r.clean_recall:.2f} | {r.attacked_recall:.2f} | "
            f"{r.n_detected_clean}→{r.n_detected_after} |"
        )
    return "\n".join(lines)
