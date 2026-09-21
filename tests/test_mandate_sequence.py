from __future__ import annotations

import copy
import json
import os
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from lurebench.cli import main
from lurebench.mandate import _sha256
from lurebench.mandate_conformance import (
    compile_mandate_challenge,
    evaluate_mandate_conformance,
    reference_mandate_submission,
)
from lurebench.mandate_sequence import (
    OPERATIONS,
    _de_bruijn_order_two,
    evaluate_sequence_mandate_conformance,
    sequence_mandate_plan,
    sequence_mandate_run,
    validate_sequence_mandate_conformance,
    write_sequence_mandate_conformance,
)
from lurebench.permit import _canonical

ROOT = Path(__file__).parents[1]
VECTOR = ROOT / "conformance" / "luremandate-sequence-v1"


def _score() -> dict:
    plan = sequence_mandate_plan()
    run = sequence_mandate_run(plan, engine_artifact_sha256="a" * 64)
    challenge = compile_mandate_challenge(
        plan,
        run,
        challenge_id="luremandate-sequence-challenge-1",
        generated_at="2026-09-05T16:10:00Z",
    )
    submission = reference_mandate_submission(
        challenge,
        submission_id="luremandate-sequence-reference-submission-1",
        engine_artifact_sha256="a" * 64,
        submitted_at="2026-09-05T16:11:00Z",
    )
    return evaluate_mandate_conformance(
        challenge,
        submission,
        evaluated_at="2026-09-05T16:12:00Z",
    )


def _registry() -> Registry:
    resources = []
    for path in (ROOT / "spec").glob("*.schema.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        if "$id" in schema:
            resources.append((schema["$id"], Resource.from_contents(schema)))
    return Registry().with_resources(resources)


def test_de_bruijn_sequence_covers_all_twenty_five_ordered_pairs_once():
    sequence = _de_bruijn_order_two()
    observed = list(zip(sequence, sequence[1:], strict=False))
    required = [(left, right) for left in OPERATIONS for right in OPERATIONS]
    assert len(sequence) == 26
    assert len(observed) == 25
    assert len(set(observed)) == 25
    assert set(observed) == set(required)


def test_sequence_campaign_passes_and_declares_state_boundaries():
    report = evaluate_sequence_mandate_conformance(_score())
    assert report["summary"] == {
        "verdict": "pass",
        "score_verdict": "pass",
        "preamble_case_count": 20,
        "measured_case_count": 26,
        "passed_measured_case_count": 26,
        "operation_count": 5,
        "required_ordered_pair_count": 25,
        "covered_ordered_pair_count": 25,
        "ordered_pair_coverage_complete": True,
    }
    assert len(report["score"]["results"]) == 46
    assert [item["operation"] for item in report["operation_results"]] == (_de_bruijn_order_two())
    assert all(item["status"] == "pass" for item in report["operation_results"])
    assert report["ordered_pair_coverage"]["missing_pairs"] == []
    assert any("isolated_requester" in item for item in report["limitations"])


def test_public_sequence_corpus_reproduces_and_validates_schema():
    report = json.loads((VECTOR / "sequence-assurance.json").read_text(encoding="utf-8"))
    assert validate_sequence_mandate_conformance(report) == report
    assert report == evaluate_sequence_mandate_conformance(_score())
    plan = sequence_mandate_plan()
    assert (VECTOR / "plan.json").read_bytes() == _canonical(plan)
    assert (VECTOR / "run.json").read_bytes() == _canonical(
        sequence_mandate_run(plan, engine_artifact_sha256="a" * 64)
    )
    schema = json.loads(
        (ROOT / "spec" / "luremandate-sequence-assurance-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(
        schema,
        registry=_registry(),
        format_checker=FormatChecker(),
    ).validate(report)


def test_sequence_tampering_fails_closed():
    report = evaluate_sequence_mandate_conformance(_score())
    changed = copy.deepcopy(report)
    changed["operation_results"][0]["operation"] = "replay-block"
    with pytest.raises(ValueError, match="does not independently recompute"):
        validate_sequence_mandate_conformance(changed)

    changed = copy.deepcopy(report)
    changed["ordered_pair_coverage"]["covered_pairs"].pop()
    with pytest.raises(ValueError, match="does not independently recompute"):
        validate_sequence_mandate_conformance(changed)


@pytest.mark.parametrize(
    "action,impact,message",
    [
        ("sequence-budget-boundary-allow", 49, "exactly exhaust"),
        ("sequence-expired-window-allow", 40, "expired budget reservation"),
    ],
)
def test_correct_gateway_answers_cannot_launder_false_operation_labels(action, impact, message):
    plan = sequence_mandate_plan()
    run = sequence_mandate_run(plan, engine_artifact_sha256="a" * 64)
    transaction = next(t for t in run["transactions"] if t["intent"]["action"] == action)
    transaction["intent"]["impact_units"] = impact
    transaction["intent_sha256"] = _sha256(_canonical(transaction["intent"]))
    for approval in transaction["approvals"]:
        approval["intent_sha256"] = transaction["intent_sha256"]
    challenge = compile_mandate_challenge(
        plan, run, challenge_id="false-label", generated_at="2026-09-05T16:10:00Z"
    )
    submission = reference_mandate_submission(
        challenge, submission_id="false-label-answer", submitted_at="2026-09-05T16:11:00Z"
    )
    score = evaluate_mandate_conformance(challenge, submission, evaluated_at="2026-09-05T16:12:00Z")
    assert score["summary"]["verdict"] == "pass"
    with pytest.raises(ValueError, match=message):
        evaluate_sequence_mandate_conformance(score)


def test_sequence_output_is_private_non_overwriting_and_cli_verifies(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    report = evaluate_sequence_mandate_conformance(_score())
    output = tmp_path / "sequence.json"
    write_sequence_mandate_conformance(output, report)
    assert main(["mandate-sequence-verify", str(output)]) == 0
    assert "SEQUENCE VERIFIED: PASS" in capsys.readouterr().out
    if os.name == "posix":
        assert output.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        write_sequence_mandate_conformance(output, report)

    template = tmp_path / "template"
    assert main(["mandate-sequence-reference", "--out-dir", str(template)]) == 0
    assert (template / "plan.json").is_file()
    assert (template / "run.json").is_file()
    assert main(["mandate-sequence-reference", "--out-dir", str(template)]) == 2
