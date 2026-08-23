from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from lurebench.cli import main
from lurebench.conformance import (
    run_conformance_suite,
    validate_conformance_report,
    validate_suite_manifest,
)
from lurebench.receipts import load_verified_artifact, loads_strict_json

SUITE = Path("conformance/lureeval-v1")
NIST_DRAFT = Path(
    "docs/nist/operational-adversarial-robustness-evaluation.yaml"
)


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_packaged_reference_suite_passes_every_case_and_published_schemas():
    manifest = _load_json(SUITE / "suite.json")
    suite_schema = _load_json(Path("spec/lureeval-conformance-suite-v1.schema.json"))
    report_schema = _load_json(Path("spec/lureeval-conformance-report-v1.schema.json"))

    Draft202012Validator.check_schema(suite_schema)
    Draft202012Validator.check_schema(report_schema)
    Draft202012Validator(
        suite_schema, format_checker=FormatChecker()
    ).validate(manifest)

    report = run_conformance_suite()
    validate_conformance_report(report)
    Draft202012Validator(
        report_schema, format_checker=FormatChecker()
    ).validate(report)

    assert report["summary"] == {
        "total": 12,
        "passed": 12,
        "failed": 0,
        "accept_cases": 3,
        "reject_cases": 9,
        "verdict": "pass",
    }


def test_external_suite_hashes_every_case_before_parsing(tmp_path: Path):
    copied = tmp_path / "suite"
    shutil.copytree(SUITE, copied)
    artifact = copied / "valid/receipt-site-a.json"
    artifact.write_bytes(artifact.read_bytes() + b"\n")

    with pytest.raises(ValueError, match="artifact digest mismatch"):
        run_conformance_suite(copied)


def test_external_suite_refuses_symlinked_artifacts(tmp_path: Path):
    copied = tmp_path / "suite"
    shutil.copytree(SUITE, copied)
    artifact = copied / "valid/receipt-site-a.json"
    external = tmp_path / "external.json"
    artifact.rename(external)
    artifact.symlink_to(external)

    with pytest.raises(ValueError, match="symbolic link"):
        run_conformance_suite(copied)


def test_external_suite_refuses_symlinked_parent_directory(tmp_path: Path):
    copied = tmp_path / "suite"
    shutil.copytree(SUITE, copied)
    external = tmp_path / "external-valid"
    (copied / "valid").rename(external)
    (copied / "valid").symlink_to(external, target_is_directory=True)

    with pytest.raises(ValueError, match="symbolic link"):
        run_conformance_suite(copied)


def test_suite_manifest_refuses_path_traversal_and_duplicate_cases():
    manifest = _load_json(SUITE / "suite.json")
    traversal = json.loads(json.dumps(manifest))
    traversal["cases"][0]["artifact"] = "../receipt.json"
    with pytest.raises(ValueError, match="stay inside"):
        validate_suite_manifest(traversal)

    nonportable = json.loads(json.dumps(manifest))
    nonportable["cases"][0]["artifact"] = "valid/receipt\\site.json"
    with pytest.raises(ValueError, match="portable path profile"):
        validate_suite_manifest(nonportable)

    duplicate = json.loads(json.dumps(manifest))
    duplicate["cases"][1]["case_id"] = duplicate["cases"][0]["case_id"]
    with pytest.raises(ValueError, match="duplicate case_id"):
        validate_suite_manifest(duplicate)


def test_conformance_cli_creates_private_report_and_never_overwrites(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    report = tmp_path / "report.json"
    assert main(["conformance", "--out", str(report)]) == 0
    assert "12/12 cases passed" in capsys.readouterr().out
    assert os.stat(report).st_mode & 0o777 == 0o600

    original = report.read_bytes()
    assert main(["conformance", "--out", str(report)]) == 2
    assert report.read_bytes() == original
    assert "File exists" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("filename", "message"),
    [
        ("invalid/receipt-duplicate-json-key.json", "duplicate JSON object key"),
        ("invalid/receipt-nonfinite-json.json", "non-standard JSON constant"),
    ],
)
def test_direct_artifact_loader_uses_strict_json(filename: str, message: str):
    with pytest.raises(ValueError, match=message):
        load_verified_artifact(SUITE / filename)


def test_nist_draft_uses_v1_shape_and_remains_deliberately_non_submittable():
    draft = loads_strict_json(NIST_DRAFT.read_bytes())
    assert set(draft) == {
        "schema_version",
        "name",
        "applied_definition",
        "submitter_organizations",
        "contact_email",
        "ai_rmf_characteristics",
        "primary_tevv_application",
        "ai_lifecycle_stages",
        "object_of_measurement",
        "model_specificity",
        "domain_specificity",
        "usage_details",
        "known_failure_modes",
        "modality",
        "references",
        "implementation_resources",
        "common_variants",
        "related_metrics",
        "computational_requirements",
        "usage_rights",
    }
    assert draft["schema_version"] == "1.0"
    assert draft["contact_email"] == "replace-before-submission@example.invalid"
    assert "NIST has not evaluated or endorsed" in Path(
        "docs/MEASUREMENT_METHOD.md"
    ).read_text(encoding="utf-8")
