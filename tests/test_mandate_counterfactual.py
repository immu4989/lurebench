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
from lurebench.mandate_counterfactual import (
    COUNTERFACTUALS,
    counterfactual_mandate_plan,
    counterfactual_mandate_run,
    evaluate_counterfactual_mandate_conformance,
    validate_counterfactual_mandate_conformance,
    write_counterfactual_mandate_conformance,
)
from lurebench.permit import _canonical

ROOT = Path(__file__).parents[1]
VECTOR = ROOT / "conformance" / "luremandate-counterfactual-v1"


def _score() -> dict:
    plan = counterfactual_mandate_plan()
    run = counterfactual_mandate_run(plan, engine_artifact_sha256="a" * 64)
    challenge = compile_mandate_challenge(
        plan,
        run,
        challenge_id="luremandate-counterfactual-challenge-1",
        generated_at="2026-09-05T15:04:00Z",
    )
    submission = reference_mandate_submission(
        challenge,
        submission_id="luremandate-counterfactual-reference-submission-1",
        engine_artifact_sha256="a" * 64,
        submitted_at="2026-09-05T15:05:00Z",
    )
    return evaluate_mandate_conformance(
        challenge,
        submission,
        evaluated_at="2026-09-05T15:06:00Z",
    )


def _registry() -> Registry:
    resources = []
    for path in (ROOT / "spec").glob("*.schema.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        if "$id" in schema:
            resources.append((schema["$id"], Resource.from_contents(schema)))
    return Registry().with_resources(resources)


def test_all_twenty_denial_guards_have_adjacent_passing_controls():
    report = evaluate_counterfactual_mandate_conformance(_score())
    assert report["summary"] == {
        "verdict": "pass",
        "score_verdict": "pass",
        "case_count": 40,
        "guard_pair_count": 20,
        "passed_guard_pair_count": 20,
        "single_dimension_pair_count": 18,
        "dependency_coupled_pair_count": 2,
        "guard_reason_coverage_complete": True,
    }
    assert [item["guard_reason"] for item in report["pairs"]] == [
        reason for reason, _ in COUNTERFACTUALS
    ]
    assert all(item["status"] == "pass" for item in report["pairs"])
    assert all(item["baseline_expected_decision"] == "allow" for item in report["pairs"])
    assert all(item["mutant_expected_decision"] == "block" for item in report["pairs"])


def test_public_counterfactual_corpus_reproduces_and_validates_schema():
    report = json.loads((VECTOR / "counterfactual-assurance.json").read_text(encoding="utf-8"))
    assert validate_counterfactual_mandate_conformance(report) == report
    assert report == evaluate_counterfactual_mandate_conformance(_score())
    assert (VECTOR / "plan.json").read_bytes() == _canonical(counterfactual_mandate_plan())
    assert (VECTOR / "run.json").read_bytes() == _canonical(
        counterfactual_mandate_run(counterfactual_mandate_plan(), engine_artifact_sha256="a" * 64)
    )
    schema = json.loads(
        (ROOT / "spec" / "luremandate-counterfactual-assurance-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(
        schema,
        registry=_registry(),
        format_checker=FormatChecker(),
    ).validate(report)


def test_counterfactual_tampering_fails_closed():
    report = evaluate_counterfactual_mandate_conformance(_score())
    changed = copy.deepcopy(report)
    changed["pairs"][0]["changed_dimensions"] = ["tenant_binding"]
    with pytest.raises(ValueError, match="does not independently recompute"):
        validate_counterfactual_mandate_conformance(changed)

    changed = copy.deepcopy(report)
    changed["summary"]["single_dimension_pair_count"] = 17
    with pytest.raises(ValueError, match="does not independently recompute"):
        validate_counterfactual_mandate_conformance(changed)


def test_counterfactual_output_is_private_non_overwriting_and_cli_verifies(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    report = evaluate_counterfactual_mandate_conformance(_score())
    output = tmp_path / "counterfactual.json"
    write_counterfactual_mandate_conformance(output, report)
    assert main(["mandate-counterfactual-verify", str(output)]) == 0
    assert "COUNTERFACTUAL VERIFIED: PASS" in capsys.readouterr().out
    if os.name == "posix":
        assert output.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        write_counterfactual_mandate_conformance(output, report)

    template = tmp_path / "template"
    assert main(["mandate-counterfactual-reference", "--out-dir", str(template)]) == 0
    assert (template / "plan.json").is_file()
    assert (template / "run.json").is_file()
    assert main(["mandate-counterfactual-reference", "--out-dir", str(template)]) == 2
