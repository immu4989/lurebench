"""Adversarial robustness harness.

The question companies and regulators actually need answered: not "how good is my
fraud detector on clean data?" but "does it survive an attacker who can perturb or
rewrite the lure?" This takes the lures a detector currently catches, applies an
attack, and measures how many now slip through — the attack success rate.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import List, Optional, Sequence

from .attacks.base import Attack
from .harness import TASK_TARGET
from .probability import validate_score, validate_threshold
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
    attack_success_rate: Optional[float]  # undefined with missing outcomes or no eligible lures
    n_abstained_clean: int = 0
    n_abstained_after: int = 0
    n_evaded: int = 0
    attack_success_rate_lower: Optional[float] = None
    attack_success_rate_upper: Optional[float] = None

    def asr_label(self) -> str:
        if self.attack_success_rate is not None:
            return f"{self.attack_success_rate:.2f}"
        if self.attack_success_rate_lower is not None:
            return (
                f"inconclusive [{self.attack_success_rate_lower:.2f}, "
                f"{self.attack_success_rate_upper:.2f}]"
            )
        return "n/a (no eligible lures)"

    def summary_line(self) -> str:
        return (
            f"{self.detector:<16} vs {self.attack:<18} "
            f"ASR={self.asr_label()}  "
            f"recall {self.clean_recall:.2f}->{self.attacked_recall:.2f}  "
            f"(caught {self.n_detected_clean}->{self.n_detected_after} of {self.n_positives}; "
            f"abstained clean/after={self.n_abstained_clean}/{self.n_abstained_after})"
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
    threshold = validate_threshold(threshold)
    if task not in TASK_TARGET:
        raise ValueError("unsupported robustness task")
    target = TASK_TARGET[task]
    positives = [r for r in dataset if target(r) == 1]

    detected: List[Lure] = []
    clean_abstained = 0
    for r in positives:
        s = validate_score(detector.score(r))
        if s is None:
            clean_abstained += 1
        elif s >= threshold:
            detected.append(r)

    still = evaded = after_abstained = 0
    for r in detected:
        attacked = replace(r, text=attack.apply(r.text))
        s = validate_score(detector.score(attacked))
        if s is None:
            after_abstained += 1
        elif s >= threshold:
            still += 1
        else:
            evaded += 1

    n_pos = len(positives)
    lower = evaded / len(detected) if detected else None
    upper = (evaded + after_abstained) / len(detected) if detected else None
    return RobustnessReport(
        detector=getattr(detector, "name", detector.__class__.__name__),
        attack=attack.name,
        task=task,
        n_positives=n_pos,
        n_detected_clean=len(detected),
        n_detected_after=still,
        clean_recall=len(detected) / n_pos if n_pos else 0.0,
        attacked_recall=still / n_pos if n_pos else 0.0,
        attack_success_rate=lower if after_abstained == 0 else None,
        n_abstained_clean=clean_abstained,
        n_abstained_after=after_abstained,
        n_evaded=evaded,
        attack_success_rate_lower=lower,
        attack_success_rate_upper=upper,
    )


def render_markdown(reports: Sequence[RobustnessReport], dataset_label: str) -> str:
    lines = [
        "# Adversarial robustness\n",
        "Attack success rate (ASR) = of the lures a detector caught on clean text, the "
        "fraction that evade after the attack. Higher ASR = more brittle.\n",
        "Abstentions are unknown, not evasion. With missing attacked outcomes, "
        "ASR is inconclusive and brackets give logical lower/upper bounds, not "
        "confidence intervals. No eligible clean detections means ASR is undefined. "
        "Recall columns are observed detection fractions over all positive records, "
        "including clean abstentions; attacked scores cover only clean detections.\n",
        f"_Evaluated on **{dataset_label}**._\n",
        "| Detector | Attack | ASR | clean recall | attacked recall | caught | abstained clean/after |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in reports:
        lines.append(
            f"| `{r.detector}` | `{r.attack}` | {r.asr_label()} | "
            f"{r.clean_recall:.2f} | {r.attacked_recall:.2f} | "
            f"{r.n_detected_clean}→{r.n_detected_after} | "
            f"{r.n_abstained_clean}/{r.n_abstained_after} |"
        )
    return "\n".join(lines)
