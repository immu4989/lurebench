from __future__ import annotations

import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from lurebench.coverage import OBSERVATION_SCHEMA, build_coverage_canaries, evaluate_coverage
from lurebench.delegation import default_delegation_suite, run_delegation_evaluation
from lurebench.incident_response import (
    evaluate_ir_responses,
    export_ir_tasks,
    reference_ir_responses,
)

ROOT = Path(__file__).parents[1]
MANIFEST = ROOT / "examples" / "lurecoverage" / "manifest.json"


def _validator(name: str) -> Draft202012Validator:
    schema = json.loads((ROOT / "spec" / name).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def test_published_coverage_schemas_validate_reference_artifacts(tmp_path: Path):
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    canaries = build_coverage_canaries(MANIFEST, created_at="2026-08-29T10:00:00Z")
    observations = {
        "schema": OBSERVATION_SCHEMA,
        "schema_version": 1,
        "captured_at": "2026-08-29T10:01:00Z",
        "manifest_sha256": hashlib.sha256(MANIFEST.read_bytes()).hexdigest(),
        "observations": [
            {
                "probe_id": probe["probe_id"],
                "sensor_id": probe["expected_sensor_id"],
                "observed_sequence": probe["emitted_sequence"],
                "copies": 1,
                "lineage_contiguous": True,
                "delivery_delay_ms": 10,
            }
            for probe in canaries["probes"]
        ],
    }
    canary_path = tmp_path / "canaries.json"
    observation_path = tmp_path / "observations.json"
    canary_path.write_text(json.dumps(canaries), encoding="utf-8")
    observation_path.write_text(json.dumps(observations), encoding="utf-8")
    report = evaluate_coverage(MANIFEST, canary_path, observation_path)
    for name, value in (
        ("agent-coverage-manifest-v1.schema.json", manifest),
        ("agent-coverage-canaries-v1.schema.json", canaries),
        ("agent-coverage-observations-v1.schema.json", observations),
        ("agent-coverage-evaluation-v1.schema.json", report),
    ):
        _validator(name).validate(value)


def test_published_delegation_and_ir_schemas_validate_reference_artifacts(tmp_path: Path):
    responses = reference_ir_responses()
    response_path = tmp_path / "responses.json"
    response_path.write_text(json.dumps(responses), encoding="utf-8")
    artifacts = (
        ("agent-delegation-suite-v1.schema.json", default_delegation_suite()),
        ("agent-delegation-evaluation-v1.schema.json", run_delegation_evaluation()),
        ("lureir-tasks-v1.schema.json", export_ir_tasks()),
        ("lureir-responses-v1.schema.json", responses),
        (
            "lureir-evaluation-v1.schema.json",
            evaluate_ir_responses(
                response_path,
                responder_id="reference-responder",
                responder_version="1.0.0",
            ),
        ),
    )
    for name, value in artifacts:
        _validator(name).validate(value)


def test_container_conformance_schema_is_valid():
    _validator("agent-boundary-container-evaluation-v1.schema.json")
