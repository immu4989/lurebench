from __future__ import annotations

import ast
import json
import os
from pathlib import Path

import jsonschema
import pytest
from referencing import Registry, Resource

from lurebench.cli import main
from lurebench.mandate_conformance import (
    compile_mandate_challenge,
    evaluate_mandate_conformance,
    exhaustive_mandate_conformance_plan,
    exhaustive_mandate_conformance_run,
    load_mandate_conformance_score,
    reference_mandate_submission,
    validate_mandate_challenge,
    validate_mandate_conformance_score,
    validate_mandate_submission,
)

ROOT = Path(__file__).parents[1]
VECTOR = ROOT / "conformance/luremandate-v1"


def _load(name: str) -> dict:
    return json.loads((VECTOR / name).read_text(encoding="utf-8"))


def _registry() -> Registry:
    resources = []
    for path in (ROOT / "spec").glob("*.schema.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        if "$id" in schema:
            resources.append((schema["$id"], Resource.from_contents(schema)))
    return Registry().with_resources(resources)


def _keys(value) -> set[str]:
    if isinstance(value, dict):
        return set(value).union(*(_keys(item) for item in value.values()))
    if isinstance(value, list):
        return set().union(*(_keys(item) for item in value))
    return set()


def test_public_answer_free_challenge_and_reference_score_recompute():
    challenge = _load("challenge.json")
    submission = _load("submission.json")
    score = _load("conformance-score.json")

    assert validate_mandate_challenge(challenge) == challenge
    assert validate_mandate_submission(submission, challenge) == submission
    assert validate_mandate_conformance_score(score) == score
    assert score["summary"] == {
        "verdict": "pass",
        "case_count": 25,
        "exact_match_count": 25,
        "decision_match_count": 25,
        "reason_match_count": 25,
        "invalid_allow_count": 0,
        "collateral_denial_count": 0,
        "covered_reason_count": 21,
        "reason_universe_count": 21,
        "reason_coverage_complete": True,
    }
    assert len(score["guard_coverage"]) == 21
    assert all(item["case_count"] >= 1 for item in score["guard_coverage"])
    for case in challenge["cases"]:
        assert set(case["transaction"]) == {
            "transaction_id",
            "intent",
            "intent_sha256",
            "approvals",
            "decided_at",
        }
        assert "decision" not in case["transaction"]
        assert "outcome" not in case["transaction"]
    keys = _keys(challenge)
    assert "expected_decision" not in keys
    assert "expected_reason_code" not in keys
    assert "reason_code" not in keys


def test_public_conformance_artifacts_validate_against_published_schemas():
    registry = _registry()
    for schema_name, artifact_name in (
        ("luremandate-conformance-challenge-v1.schema.json", "challenge.json"),
        ("luremandate-conformance-submission-v1.schema.json", "submission.json"),
        ("luremandate-conformance-score-v1.schema.json", "conformance-score.json"),
    ):
        schema = json.loads((ROOT / "spec" / schema_name).read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator(
            schema,
            registry=registry,
            format_checker=jsonschema.FormatChecker(),
        ).validate(_load(artifact_name))


def test_compilation_and_reference_submission_are_deterministic():
    challenge = compile_mandate_challenge(
        _load("conformance-plan.json"),
        _load("conformance-run.json"),
        challenge_id="luremandate-exhaustive-challenge-1",
        generated_at="2026-09-05T15:26:00Z",
    )
    assert challenge == _load("challenge.json")
    submission = reference_mandate_submission(
        challenge,
        submission_id="luremandate-exhaustive-reference-submission-1",
        engine_id="luremandate-reference",
        engine_version="1.0.0",
        engine_artifact_sha256="a" * 64,
        submitted_at="2026-09-05T15:27:00Z",
    )
    assert submission == _load("submission.json")
    score = evaluate_mandate_conformance(challenge, submission, evaluated_at="2026-09-05T15:28:00Z")
    assert score == _load("conformance-score.json")


def test_invalid_allow_and_wrong_reason_are_measured_not_trusted():
    challenge = _load("challenge.json")
    submission = _load("submission.json")
    submission["results"][2] = {
        "case_id": "case-0003",
        "decision": "allow",
        "reason_code": "authority_satisfied",
    }
    score = evaluate_mandate_conformance(challenge, submission, evaluated_at="2026-09-05T15:28:00Z")
    assert score["summary"]["verdict"] == "fail"
    assert score["summary"]["exact_match_count"] == 24
    assert score["summary"]["invalid_allow_count"] == 1
    assert score["summary"]["collateral_denial_count"] == 0
    assert score["results"][2]["expected_reason_code"] == "self_approval"
    assert score["results"][2]["status"] == "fail"


def test_exhaustive_reference_reaches_every_reason_without_changing_base_vector():
    plan = exhaustive_mandate_conformance_plan()
    run = exhaustive_mandate_conformance_run(plan, engine_artifact_sha256="a" * 64)
    assert plan == _load("conformance-plan.json")
    assert run == _load("conformance-run.json")
    score = _load("conformance-score.json")
    assert {item["expected_reason_code"] for item in score["results"]} == {
        item["expected_reason_code"] for item in score["guard_coverage"]
    }
    assert len(run["transactions"]) == 25
    assert len(_load("run.json")["transactions"]) == 16


def test_challenge_submission_and_score_tampering_fail_closed():
    challenge = _load("challenge.json")
    challenge["cases"][0]["transaction"]["intent"]["impact_units"] += 1
    with pytest.raises(ValueError, match="intent digest"):
        validate_mandate_challenge(challenge)

    challenge = _load("challenge.json")
    reordered = _load("submission.json")
    reordered["results"][0], reordered["results"][1] = (
        reordered["results"][1],
        reordered["results"][0],
    )
    with pytest.raises(ValueError, match="case order"):
        validate_mandate_submission(reordered, challenge)

    score = _load("conformance-score.json")
    score["summary"]["exact_match_count"] -= 1
    with pytest.raises(ValueError, match="does not independently recompute"):
        validate_mandate_conformance_score(score)


def test_cli_files_are_private_non_overwriting_and_recomputable(tmp_path: Path):
    template = tmp_path / "exhaustive-template"
    template_args = [
        "mandate-conformance-reference",
        "--engine-artifact-sha256",
        "a" * 64,
        "--out-dir",
        str(template),
    ]
    assert main(template_args) == 0
    assert len(json.loads((template / "run.json").read_text())["transactions"]) == 25
    assert main(template_args) == 2
    challenge_path = tmp_path / "challenge.json"
    submission_path = tmp_path / "submission.json"
    score_path = tmp_path / "score.json"
    assert (
        main(
            [
                "mandate-challenge",
                "--plan",
                str(VECTOR / "plan.json"),
                "--run",
                str(VECTOR / "run.json"),
                "--challenge-id",
                "cli-challenge",
                "--generated-at",
                "2026-09-05T15:17:00Z",
                "--out",
                str(challenge_path),
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "mandate-reference-submit",
                str(challenge_path),
                "--submission-id",
                "cli-submission",
                "--submitted-at",
                "2026-09-05T15:18:00Z",
                "--out",
                str(submission_path),
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "mandate-score",
                "--challenge",
                str(challenge_path),
                "--submission",
                str(submission_path),
                "--evaluated-at",
                "2026-09-05T15:19:00Z",
                "--out",
                str(score_path),
            ]
        )
        == 0
    )
    assert main(["mandate-score-verify", str(score_path)]) == 0
    assert load_mandate_conformance_score(score_path)["summary"]["verdict"] == "pass"
    assert main(["mandate-score-verify", str(score_path)]) == 0
    assert (
        main(
            [
                "mandate-challenge",
                "--plan",
                str(VECTOR / "plan.json"),
                "--run",
                str(VECTOR / "run.json"),
                "--out",
                str(challenge_path),
            ]
        )
        == 2
    )
    if os.name == "posix":
        assert template.stat().st_mode & 0o777 == 0o700
        for path in (challenge_path, submission_path, score_path):
            assert path.stat().st_mode & 0o777 == 0o600


def test_conformance_module_has_no_network_model_or_process_runtime():
    tree = ast.parse((ROOT / "lurebench/mandate_conformance.py").read_text(encoding="utf-8"))
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imports.update(
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module and not node.level
    )
    assert not any(
        name.split(".")[0]
        in {"requests", "socket", "subprocess", "torch", "transformers", "openai"}
        for name in imports
    )
