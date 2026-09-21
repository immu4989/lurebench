from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

import lurebench.mandate as mandate
from lurebench.cli import main
from lurebench.mandate_conformance import (
    evaluate_mandate_conformance,
    reference_mandate_submission,
    validate_mandate_challenge,
)
from lurebench.mandate_transitions import SCENARIOS, transition_mandate_plan, transition_mandate_run
from lurebench.permit import _canonical

VECTOR = Path(__file__).parents[1] / "conformance/luremandate-transitions-v1"
A = "authority_satisfied"
B = "cumulative_limit_exceeded"
R = "approval_replay"
D = "approval_denied"
EXPECTED = (
    (A, B, A, B),
    (D, A, A, B),
    (D, R, A),
    (A, A, A, B, A),
    (A, A, A, A, B, B),
    (A, B, A, B),
    (A, A, A, B, A),
    (A, R, A),
    (A, B, A, B),
    (A, R, A),
)


def load(name):
    return json.loads((VECTOR / name).read_text())


def test_transition_corpus_matches_explicit_state_oracle():
    assert len(SCENARIOS) == len(EXPECTED) == 10
    assert (VECTOR / "plan.json").read_bytes() == _canonical(transition_mandate_plan())
    assert (VECTOR / "run.json").read_bytes() == _canonical(
        transition_mandate_run(engine_artifact_sha256="a" * 64)
    )
    challenge = validate_mandate_challenge(load("challenge.json"))
    score = evaluate_mandate_conformance(
        challenge, load("submission.json"), evaluated_at="2026-09-06T04:02:00Z"
    )
    assert score == load("score.json")
    assert score["summary"]["exact_match_count"] == 41
    assert [item["expected_reason_code"] for item in score["results"]] == [
        reason for scenario in EXPECTED for reason in scenario
    ]


@pytest.mark.parametrize(
    "defect",
    [
        "forget-replay",
        "forget-budget",
        "keep-only-last-reservation",
        "expire-one-ms-early",
        "expire-one-ms-late",
        "budget-off-by-one",
        "wrong-budget-scope",
    ],
)
def test_transition_campaign_detects_state_machine_defects(monkeypatch, defect):
    """Generate real faulty-engine answers, then score with the unmodified oracle."""
    original = mandate._authority_decision

    def faulty(transaction, plan, run_id, ids, nonces, reservations):
        plan = copy.deepcopy(plan)
        if defect == "forget-replay":
            ids, nonces = set(), set()
        elif defect == "forget-budget":
            reservations = {}
        elif defect == "keep-only-last-reservation":
            reservations = {key: values[-1:] for key, values in reservations.items()}
        else:
            for policy in plan["policies"]:
                if defect == "expire-one-ms-early":
                    policy["cumulative_window_ms"] -= 1
                elif defect == "expire-one-ms-late":
                    policy["cumulative_window_ms"] += 1
                elif defect == "budget-off-by-one":
                    policy["cumulative_limit_units"] += 1
                elif defect == "wrong-budget-scope":
                    policy["cumulative_scope"] = "requester_policy"
        return original(transaction, plan, run_id, ids, nonces, reservations)

    challenge = load("challenge.json")
    with monkeypatch.context() as context:
        context.setattr(mandate, "_authority_decision", faulty)
        submission = reference_mandate_submission(
            challenge, submission_id=f"mutant-{defect}", submitted_at="2026-09-06T04:01:00Z"
        )
    score = evaluate_mandate_conformance(challenge, submission, evaluated_at="2026-09-06T04:02:00Z")
    assert score["summary"]["verdict"] == "fail", defect
    assert score["summary"]["exact_match_count"] < 41, defect


def test_transition_cli_and_no_overwrite(tmp_path):
    directory = tmp_path / "campaign"
    assert main(["mandate-transitions-reference", "--out-dir", str(directory)]) == 0
    before = (directory / "run.json").read_bytes()
    assert main(["mandate-transitions-reference", "--out-dir", str(directory)]) == 2
    assert (directory / "run.json").read_bytes() == before
