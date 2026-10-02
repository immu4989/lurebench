"""Create a synthetic, offline panel example in a new directory.

The fixed scores illustrate the reporting contract, not detector performance.
No model is constructed, downloaded, trained, or contacted.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from types import SimpleNamespace

from lurebench.detectors.cache import CachedDetector
from lurebench.panel import run_cached_panel
from lurebench.schema import Lure, save_jsonl


def run_demo(output: Path) -> dict:
    output = Path(output)
    # Refuse existing output, including symlinks. Never overwrite an experiment.
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    records = [Lure(
        id=f"synthetic-{i:02}", text=f"Synthetic reporting fixture number {i}; not a real message.",
        label=int(i < 8), source="human", typology="phishing" if i < 8 else "benign",
        meta={"family_id": f"family-{i // 2}", "synthetic": True},
    ) for i in range(16)]
    save_jsonl(records, output / "messages.jsonl")
    descriptors = []
    for name in ("baseline", "improved", "selective"):
        def score(record, profile=name):
            index = int(record.id.rsplit("-", 1)[1])
            if profile == "baseline":
                return .1
            if profile == "selective" and index % 2:
                return None
            return .9 if record.label else .1

        # Explicit fixture callbacks, not real detector measurements. Label-based
        # scores are deliberate here and must never become a benchmark result.
        detector_name = f"synthetic-{name}"
        cache = CachedDetector(SimpleNamespace(name=detector_name, task="fraud", score=score),
                               str(output / f"{name}.json"), flush_every=0)
        for record in records:
            cache.score(record)
        cache.flush()
        descriptors.append({"id": name, "name": detector_name, "cache": f"{name}.json",
                            "threshold": .5})
    plan = {"schema_version": 1, "task": "fraud", "pairing_unit": "lineage",
            "baseline": descriptors[0], "candidates": descriptors[1:]}
    plan_path = output / "plan.json"
    plan_path.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    report = run_cached_panel(output / "messages.jsonl", plan_path)
    report["demonstration"] = {
        "synthetic": True, "scores": "fixed_label_based_fixtures_not_model_predictions",
        "purpose": "exercise_replay_lineage_missingness_and_family_adjustment",
        "not_evidence_of_detector_performance": True,
    }
    (output / "report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8",
    )
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="new directory in a trusted parent")
    args = parser.parse_args(argv)
    run_demo(args.out)
    print("Created synthetic panel demonstration; not measured detector performance.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
