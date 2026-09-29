"""Reproduce both lineage-disjoint and historical splits without provider calls.

Run from the repository root. Output is a new file; existing reports are never
overwritten. Hashes record observed local inputs/source, not signed provenance.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import platform
from pathlib import Path

from lurebench.crossgen import cross_generator_provenance
from lurebench.local_io import read_regular_file
from lurebench.schema import load_jsonl

DATASETS = (
    "data/full/paired/human.jsonl", "data/full/paired/deepseek-v4-pro.jsonl",
    "data/full/paired/glm-4.6.jsonl", "data/full/paired/mistral-large-latest.jsonl",
)
SOURCES = (
    "lurebench/crossgen.py", "lurebench/lineage.py", "lurebench/metrics.py",
    "lurebench/probability.py", "lurebench/schema.py", "lurebench/detectors/tfidf.py",
    "lurebench/harness.py", "scripts/eval_lineage_provenance.py",
)


def digest(path):
    return hashlib.sha256(read_regular_file(
        Path(path), maximum=256 * 1024 * 1024, label="study input",
    )).hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, help="new aggregate JSON report path")
    args = parser.parse_args(argv)
    destination = Path(args.out)
    if destination.exists() or destination.is_symlink():
        raise ValueError("study report already exists; choose a new path")
    if not destination.parent.is_dir() or destination.parent.is_symlink():
        raise ValueError("output parent must be an existing trusted directory")
    pins = {path: digest(path) for path in DATASETS + SOURCES}
    records = [record for path in DATASETS for record in load_jsonl(path)]
    parsed = hashlib.sha256()
    for record in sorted(records, key=lambda record: record.id):
        parsed.update(json.dumps(record.to_dict(), ensure_ascii=True, sort_keys=True,
                                 separators=(",", ":"), allow_nan=False).encode("utf-8") + b"\n")
    results = {}
    for mode in ("lineage_disjoint", "legacy_index"):
        results[mode] = [fold.as_dict() for fold in cross_generator_provenance(
            records, threshold=.5, human_holdout_k=5, split_mode=mode,
        )]
    if pins != {path: digest(path) for path in DATASETS + SOURCES}:
        raise ValueError("study input/source changed while the experiment was running")
    report = {
        "schema_version": 1, "analysis": "local_cross_generator_split_comparison",
        "detector": "tfidf-logreg", "task": "provenance", "threshold": .5,
        "human_holdout_k": 5, "dataset_records": len(records),
        "parsed_records_sha256": parsed.hexdigest(), "observed_file_sha256": pins,
        "runtime": {"python": platform.python_version(), **{
            package: importlib.metadata.version(package)
            for package in ("scikit-learn", "numpy", "scipy")}},
        "results": results,
        "limitations": [
            "protocols_use_different_training_and_test_records_not_a_paired_model_improvement_test",
            "small_shared_test_cohorts_no_population_confidence_or_equivalence_claim",
            "declared_lineage_only_not_semantic_or_pretraining_leakage_detection",
            "folds_are_not_independent_model_replicates",
            "source_hashes_are_observed_files_not_authenticated_loaded_code_attestation",
            "no_new_generation_provider_calls_or_model_downloads",
        ],
    }
    # Exclusive creation, only after the entire study and consistency checks pass.
    with destination.open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n")
    print(f"Wrote aggregate study report: {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
