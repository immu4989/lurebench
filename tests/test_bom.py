from __future__ import annotations

import ast
import copy
import hashlib
import json
import os
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from lurebench.bom import (
    EVALUATION_SCHEMA,
    MANIFEST_SCHEMA,
    load_bom_evaluation,
    project_bom,
    reconcile_boms,
    validate_bom_evaluation,
    validate_bom_manifest,
)
from lurebench.cli import main

ROOT = Path(__file__).parents[1]
VECTOR = ROOT / "conformance" / "lurebom-v1"


def _load(name: str) -> dict:
    return json.loads((VECTOR / name).read_text(encoding="utf-8"))


def _bytes(name: str) -> bytes:
    return (VECTOR / name).read_bytes()


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _registry() -> Registry:
    resources = []
    for path in (ROOT / "spec").glob("*.schema.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        if "$id" in schema:
            resources.append((schema["$id"], Resource.from_contents(schema)))
    return Registry().with_resources(resources)


def test_public_vector_reconciles_exactly_and_schemas_validate():
    artifact_plan = _load("artifact-plan.json")
    manifest = _load("manifest.json")
    expected = _load("evaluation.json")
    actual = reconcile_boms(
        artifact_plan,
        manifest,
        _bytes("cyclonedx-1.7.json"),
        _bytes("spdx-3.0.1.json"),
        evaluated_at="2026-09-05T00:03:00Z",
    )
    assert actual == expected
    assert validate_bom_evaluation(expected) == expected
    assert expected["summary"] == {
        "artifact_subject_count": 3,
        "component_count": 4,
        "component_parity_rate": 1.0,
        "dependency_count": 1,
        "dependency_parity_rate": 1.0,
        "finding_count": 0,
        "ignored_field_count": 35,
        "matched_component_count": 4,
        "matched_dependency_count": 1,
        "verdict": "pass",
    }

    registry = _registry()
    for filename, instance, schema_id in (
        ("lurebom-manifest-v1.schema.json", manifest, MANIFEST_SCHEMA),
        ("lurebom-evaluation-v1.schema.json", expected, EVALUATION_SCHEMA),
    ):
        schema = json.loads((ROOT / "spec" / filename).read_text(encoding="utf-8"))
        assert schema["$id"] == schema_id
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema, registry=registry, format_checker=FormatChecker()).validate(
            instance
        )


def test_manifest_binds_plan_primary_document_and_exact_subjects():
    artifact_plan = _load("artifact-plan.json")
    manifest = _load("manifest.json")
    assert validate_bom_manifest(manifest, artifact_plan) == manifest

    changed = copy.deepcopy(manifest)
    changed["artifact_plan_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="does not bind"):
        validate_bom_manifest(changed, artifact_plan)

    changed = copy.deepcopy(manifest)
    changed["components"][1]["artifact_id"] = None
    with pytest.raises(ValueError, match="cover every"):
        validate_bom_manifest(changed, artifact_plan)

    changed = copy.deepcopy(manifest)
    changed["primary_format"] = "cyclonedx-1.7"
    with pytest.raises(ValueError, match="primary format"):
        validate_bom_manifest(changed, artifact_plan)

    changed = copy.deepcopy(manifest)
    changed["created_at"] = "2026-09-04T23:59:59Z"
    with pytest.raises(ValueError, match="predates"):
        validate_bom_manifest(changed, artifact_plan)


def test_projectors_reject_ambiguous_or_malformed_security_fields():
    duplicate_key = b'{"bomFormat":"CycloneDX","bomFormat":"CycloneDX"}'
    with pytest.raises(ValueError, match="duplicate JSON object key"):
        project_bom(duplicate_key, "cyclonedx-1.7")

    cyclonedx = _load("cyclonedx-1.7.json")
    cyclonedx["specVersion"] = "1.6"
    with pytest.raises(ValueError, match="1.7"):
        project_bom(_json_bytes(cyclonedx), "cyclonedx-1.7")

    cyclonedx = _load("cyclonedx-1.7.json")
    cyclonedx["components"][0]["hashes"].append({"alg": "SHA-256", "content": "0" * 64})
    with pytest.raises(ValueError, match="exactly one SHA-256"):
        project_bom(_json_bytes(cyclonedx), "cyclonedx-1.7")

    spdx = _load("spdx-3.0.1.json")
    spdx["@graph"][-1]["to"] = ["urn:lurebom:spdx:missing"]
    with pytest.raises(ValueError, match="unknown target"):
        project_bom(_json_bytes(spdx), "spdx-3.0.1")


def test_non_sha256_hashes_are_disclosed_as_projection_loss():
    cyclonedx = _load("cyclonedx-1.7.json")
    cyclonedx["components"][0]["hashes"].append({"alg": "SHA-1", "content": "1" * 40})
    projection = project_bom(_json_bytes(cyclonedx), "cyclonedx-1.7")
    assert "$.components[0].hashes[1]" in projection["ignored_field_paths"]

    spdx = _load("spdx-3.0.1.json")
    package_index = next(
        index
        for index, element in enumerate(spdx["@graph"])
        if element.get("type") == "ai_AIPackage"
    )
    spdx["@graph"][package_index]["verifiedUsing"].append(
        {"type": "Hash", "algorithm": "sha1", "hashValue": "1" * 40}
    )
    projection = project_bom(_json_bytes(spdx), "spdx-3.0.1")
    assert f"$.@graph[{package_index}].verifiedUsing[1]" in projection["ignored_field_paths"]


def test_component_and_dependency_drift_become_explicit_failures():
    artifact_plan = _load("artifact-plan.json")

    cyclonedx = _load("cyclonedx-1.7.json")
    cyclonedx["components"][3]["hashes"][0]["content"] = "8" * 64
    cdx_payload = _json_bytes(cyclonedx)
    manifest = _load("manifest.json")
    manifest["cyclonedx_document_sha256"] = hashlib.sha256(cdx_payload).hexdigest()
    evaluation = reconcile_boms(
        artifact_plan,
        manifest,
        cdx_payload,
        _bytes("spdx-3.0.1.json"),
        evaluated_at="2026-09-05T00:03:00Z",
    )
    assert evaluation["summary"]["verdict"] == "fail"
    assert {item["code"] for item in evaluation["findings"]} == {"sha256_mismatch"}

    cyclonedx = _load("cyclonedx-1.7.json")
    cyclonedx["dependencies"][1]["dependsOn"] = []
    cdx_payload = _json_bytes(cyclonedx)
    manifest = _load("manifest.json")
    manifest["cyclonedx_document_sha256"] = hashlib.sha256(cdx_payload).hexdigest()
    evaluation = reconcile_boms(
        artifact_plan,
        manifest,
        cdx_payload,
        _bytes("spdx-3.0.1.json"),
        evaluated_at="2026-09-05T00:03:00Z",
    )
    assert evaluation["summary"]["verdict"] == "fail"
    assert evaluation["findings"] == [
        {
            "code": "dependency_missing_from_cyclonedx",
            "subject": "alpha-model-root->alpha-base-model",
        }
    ]


def test_unmapped_components_are_not_silently_dropped():
    artifact_plan = _load("artifact-plan.json")
    cyclonedx = _load("cyclonedx-1.7.json")
    cyclonedx["components"].append(
        {
            "bom-ref": "urn:lurebom:cyclonedx:undeclared",
            "type": "library",
            "name": "undeclared",
            "version": "1.0.0",
            "purl": "pkg:generic/example/undeclared@1.0.0",
            "hashes": [{"alg": "SHA-256", "content": "7" * 64}],
        }
    )
    cdx_payload = _json_bytes(cyclonedx)
    manifest = _load("manifest.json")
    manifest["cyclonedx_document_sha256"] = hashlib.sha256(cdx_payload).hexdigest()
    evaluation = reconcile_boms(
        artifact_plan,
        manifest,
        cdx_payload,
        _bytes("spdx-3.0.1.json"),
        evaluated_at="2026-09-05T00:03:00Z",
    )
    assert evaluation["summary"]["verdict"] == "fail"
    assert evaluation["findings"] == [
        {
            "code": "cyclonedx_component_unmapped",
            "subject": "urn:lurebom:cyclonedx:undeclared",
        }
    ]


def test_saved_evaluation_recomputes_and_detects_tampering(tmp_path: Path):
    assert load_bom_evaluation(VECTOR / "evaluation.json") == _load("evaluation.json")
    changed = _load("evaluation.json")
    changed["summary"]["finding_count"] = 1
    with pytest.raises(ValueError, match="does not independently reconcile"):
        validate_bom_evaluation(changed)

    path = tmp_path / "changed.json"
    path.write_text(json.dumps(changed), encoding="utf-8")
    assert main(["bom-verify", str(path)]) == 2


def test_cli_writes_private_output_and_refuses_overwrite(tmp_path: Path):
    output = tmp_path / "evaluation.json"
    args = [
        "bom-reconcile",
        "--artifact-plan",
        str(VECTOR / "artifact-plan.json"),
        "--manifest",
        str(VECTOR / "manifest.json"),
        "--cyclonedx",
        str(VECTOR / "cyclonedx-1.7.json"),
        "--spdx",
        str(VECTOR / "spdx-3.0.1.json"),
        "--evaluated-at",
        "2026-09-05T00:03:00Z",
        "--out",
        str(output),
    ]
    assert main(args) == 0
    assert json.loads(output.read_text(encoding="utf-8")) == _load("evaluation.json")
    if os.name == "posix":
        assert output.stat().st_mode & 0o777 == 0o600
    assert main(args) == 2
    assert main(["bom-verify", str(output)]) == 0


def test_reference_adapter_has_no_network_or_model_loading_dependency():
    tree = ast.parse((ROOT / "lurebench" / "bom.py").read_text(encoding="utf-8"))
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported.update(
        node.module.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module and not node.level
    )
    assert imported.isdisjoint({"requests", "socket", "urllib", "transformers", "torch"})
