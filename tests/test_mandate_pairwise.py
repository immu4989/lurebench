from __future__ import annotations

import copy
import json
import os
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from lurebench.cli import main
from lurebench.mandate_conformance import (
    compile_mandate_challenge,
    evaluate_mandate_conformance,
    reference_mandate_submission,
)
from lurebench.mandate_pairwise import (
    CASE_COUNT,
    COMBINATIONS,
    FACTOR_IDS,
    evaluate_pairwise_mandate_conformance,
    pairwise_mandate_plan,
    pairwise_mandate_run,
    validate_pairwise_mandate_conformance,
    write_pairwise_mandate_conformance,
)
from lurebench.permit import _canonical

ROOT = Path(__file__).parents[1]
VECTOR = ROOT / "conformance" / "luremandate-pairwise-v1"


def _score() -> dict:
    plan = pairwise_mandate_plan()
    run = pairwise_mandate_run(plan)
    challenge = compile_mandate_challenge(
        plan,
        run,
        challenge_id="luremandate-pairwise-challenge-1",
        generated_at="2026-09-05T15:01:00Z",
    )
    submission = reference_mandate_submission(
        challenge,
        submission_id="luremandate-pairwise-reference-submission-1",
        engine_artifact_sha256="a" * 64,
        submitted_at="2026-09-05T15:02:00Z",
    )
    return evaluate_mandate_conformance(
        challenge,
        submission,
        evaluated_at="2026-09-05T15:03:00Z",
    )


def _registry() -> Registry:
    resources = []
    for path in (ROOT / "spec").glob("*.schema.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        if "$id" in schema:
            resources.append((schema["$id"], Resource.from_contents(schema)))
    return Registry().with_resources(resources)


def test_binary_orthogonal_array_covers_every_pair_and_gateway_answers():
    report = evaluate_pairwise_mandate_conformance(_score())
    summary = report["summary"]
    assert summary == {
        "verdict": "pass",
        "score_verdict": "pass",
        "case_count": 16,
        "factor_count": 15,
        "factor_pair_count": 105,
        "required_interaction_count": 420,
        "covered_interaction_count": 420,
        "interaction_coverage": 1.0,
        "pairwise_coverage_complete": True,
    }
    assert len(report["factor_rows"]) == CASE_COUNT
    assert len(report["pair_coverage"]) == 105
    assert all(
        item["covered_combinations"] == list(COMBINATIONS) for item in report["pair_coverage"]
    )
    assert all(item["missing_combinations"] == [] for item in report["pair_coverage"])
    assert report["score"]["summary"]["exact_match_count"] == CASE_COUNT
    assert report["method"]["factor_ids"] == list(FACTOR_IDS)


def test_pairwise_report_validates_json_schema_and_recomputes():
    report = evaluate_pairwise_mandate_conformance(_score())
    assert validate_pairwise_mandate_conformance(report) == report
    schema = json.loads(
        (ROOT / "spec" / "luremandate-pairwise-assurance-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(
        schema,
        registry=_registry(),
        format_checker=FormatChecker(),
    ).validate(report)


def test_public_pairwise_corpus_is_reproducible_and_self_checks():
    report = json.loads((VECTOR / "pairwise-assurance.json").read_text(encoding="utf-8"))
    assert validate_pairwise_mandate_conformance(report) == report
    assert report == evaluate_pairwise_mandate_conformance(_score())
    assert (VECTOR / "plan.json").read_bytes() == _canonical(pairwise_mandate_plan())
    assert (VECTOR / "run.json").read_bytes() == _canonical(
        pairwise_mandate_run(pairwise_mandate_plan(), engine_artifact_sha256="a" * 64)
    )


def test_pairwise_report_tampering_fails_closed():
    report = evaluate_pairwise_mandate_conformance(_score())
    changed = copy.deepcopy(report)
    changed["summary"]["covered_interaction_count"] = 419
    with pytest.raises(ValueError, match="does not independently recompute"):
        validate_pairwise_mandate_conformance(changed)

    changed = copy.deepcopy(report)
    changed["factor_rows"][0]["values"]["tenant_binding"] = False
    with pytest.raises(ValueError, match="does not independently recompute"):
        validate_pairwise_mandate_conformance(changed)


def test_pairwise_outputs_are_private_non_overwriting_and_cli_verifies(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    report = evaluate_pairwise_mandate_conformance(_score())
    report_path = tmp_path / "pairwise.json"
    write_pairwise_mandate_conformance(report_path, report)
    assert main(["mandate-pairwise-verify", str(report_path)]) == 0
    assert "PAIRWISE VERIFIED: PASS" in capsys.readouterr().out
    if os.name == "posix":
        assert report_path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        write_pairwise_mandate_conformance(report_path, report)

    template = tmp_path / "template"
    assert main(["mandate-pairwise-reference", "--out-dir", str(template)]) == 0
    assert (template / "plan.json").is_file()
    assert (template / "run.json").is_file()
    assert main(["mandate-pairwise-reference", "--out-dir", str(template)]) == 2
