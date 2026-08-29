from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from lurebench.cli import main
from lurebench.coverage import (
    OBSERVATION_SCHEMA,
    build_coverage_canaries,
    evaluate_coverage,
    validate_coverage_evaluation,
    write_coverage_artifact,
)

MANIFEST = Path("examples/lurecoverage/manifest.json")


def _write_observations(path: Path, canaries: dict, *, missing=None, duplicate=None) -> None:
    missing = set(missing or [])
    duplicate = set(duplicate or [])
    observations = []
    for probe in canaries["probes"]:
        if probe["probe_id"] in missing:
            continue
        observations.append(
            {
                "probe_id": probe["probe_id"],
                "sensor_id": probe["expected_sensor_id"],
                "observed_sequence": probe["emitted_sequence"],
                "copies": 2 if probe["probe_id"] in duplicate else 1,
                "lineage_contiguous": True,
                "delivery_delay_ms": 25,
            }
        )
    path.write_text(
        json.dumps(
            {
                "schema": OBSERVATION_SCHEMA,
                "schema_version": 1,
                "captured_at": "2026-08-29T12:00:00Z",
                "manifest_sha256": hashlib.sha256(MANIFEST.read_bytes()).hexdigest(),
                "observations": observations,
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def test_coverage_detects_complete_and_missing_routes(tmp_path: Path):
    canaries = build_coverage_canaries(MANIFEST, replicates=2, created_at="2026-08-29T11:00:00Z")
    canary_path = tmp_path / "canaries.json"
    write_coverage_artifact(canary_path, canaries)
    observations = tmp_path / "observations.json"
    _write_observations(observations, canaries)
    report = evaluate_coverage(
        MANIFEST,
        canary_path,
        observations,
        generated_at="2026-08-29T12:01:00Z",
    )
    assert report["summary"]["verdict"] == "pass"
    assert report["summary"]["route_coverage"] == 1.0
    validate_coverage_evaluation(report)

    failed_observations = tmp_path / "failed.json"
    first_route = {probe["probe_id"] for probe in canaries["probes"][:2]}
    _write_observations(failed_observations, canaries, missing=first_route)
    failed = evaluate_coverage(MANIFEST, canary_path, failed_observations)
    assert failed["summary"]["verdict"] == "fail"
    assert failed["summary"]["covered_required_routes"] == 4
    assert failed["summary"]["missing_probes"] == 2


def test_coverage_rejects_unknown_and_rewritten_evidence(tmp_path: Path):
    canaries = build_coverage_canaries(MANIFEST, replicates=2)
    canary_path = tmp_path / "canaries.json"
    write_coverage_artifact(canary_path, canaries)
    observations = tmp_path / "observations.json"
    _write_observations(observations, canaries)
    payload = json.loads(observations.read_text())
    payload["observations"][0]["probe_id"] = "probe-unknown"
    observations.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="unknown probes"):
        evaluate_coverage(MANIFEST, canary_path, observations)

    clean = tmp_path / "clean.json"
    _write_observations(clean, canaries)
    report = evaluate_coverage(MANIFEST, canary_path, clean)
    report["summary"]["route_coverage"] = 0.5
    with pytest.raises(ValueError, match="does not reconcile"):
        validate_coverage_evaluation(report)

    report = evaluate_coverage(MANIFEST, canary_path, clean)
    report["results"][1]["observed_sequence"] = 1
    with pytest.raises(ValueError, match="out_of_order is inconsistent"):
        validate_coverage_evaluation(report)

    report = evaluate_coverage(MANIFEST, canary_path, clean)
    report["results"][0]["allowed_delivery_delay_ms"] = 1
    with pytest.raises(ValueError, match="passed is inconsistent"):
        validate_coverage_evaluation(report)


def test_coverage_cli_creates_private_artifacts(tmp_path: Path):
    canaries = tmp_path / "canaries.json"
    assert main(["coverage-canaries", "--manifest", str(MANIFEST), "--out", str(canaries)]) == 0
    assert os.stat(canaries).st_mode & 0o777 == 0o600
    artifact = json.loads(canaries.read_text())
    observations = tmp_path / "observations.json"
    _write_observations(observations, artifact)
    report = tmp_path / "coverage.json"
    assert (
        main(
            [
                "coverage-eval",
                "--manifest",
                str(MANIFEST),
                "--canaries",
                str(canaries),
                "--observations",
                str(observations),
                "--out",
                str(report),
            ]
        )
        == 0
    )
    assert os.stat(report).st_mode & 0o777 == 0o600
