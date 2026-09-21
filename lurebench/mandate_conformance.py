"""Answer-free, stateful black-box conformance challenges for LureMandate gateways."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from .mandate import (
    DECISIONS,
    LIMITATIONS,
    PRIVACY,
    REASON_CODES,
    RUN_SCHEMA,
    _bounded,
    _digest,
    _instant,
    _load,
    _now,
    _reference_time,
    _sha256,
    _write,
    default_mandate_plan,
    evaluate_mandate,
    reference_mandate_run,
    validate_mandate_plan,
    validate_mandate_run,
)
from .permit import _canonical, _exact, _identifier

CHALLENGE_SCHEMA = "https://github.com/immu4989/lurebench/spec/luremandate-conformance-challenge/v1"
SUBMISSION_SCHEMA = (
    "https://github.com/immu4989/lurebench/spec/luremandate-conformance-submission/v1"
)
SCORE_SCHEMA = "https://github.com/immu4989/lurebench/spec/luremandate-conformance-score/v1"
VERSION = "1.0.0"
STATE_MODEL = "single_session_ordered_no_reset"
CONFORMANCE_LIMITATIONS = (
    "challenge_omits_expected_decisions_and_reasons_but_does_not_prevent_input_inference",
    "cases_measure_only_declared_metadata_and_stateful_order_not_unrepresented_actions",
    "reference_submission_tests_the_reference_semantics_not_an_external_gateway",
    "engine_identity_and_submitted_results_are_claims_unless_authenticated_externally",
    "passing_is_not_complete_mediation_safety_compliance_or_deployment_authorization",
)


def exhaustive_mandate_conformance_plan() -> Dict[str, Any]:
    """Return a separate reference plan that makes every v1 guard reachable."""
    plan = copy.deepcopy(default_mandate_plan())
    plan["agents"].append(
        {
            "agent_id": "agent-limited",
            "workload_spiffe_id": "spiffe://example.gov/workload/agent-limited",
            "allowed_policy_ids": ["standard-change"],
        }
    )
    plan["agents"].sort(key=lambda item: item["agent_id"])
    return validate_mandate_plan(plan)


def exhaustive_mandate_conformance_run(
    plan_value: Optional[Mapping[str, Any]] = None,
    *,
    run_id: str = "mandate-conformance-run-1",
    engine_id: str = "luremandate-reference",
    engine_version: str = VERSION,
    engine_artifact_sha256: Optional[str] = None,
) -> Dict[str, Any]:
    """Return a 25-case template that reaches every LureMandate v1 reason."""
    plan = validate_mandate_plan(plan_value or exhaustive_mandate_conformance_plan())
    run = copy.deepcopy(
        reference_mandate_run(
            plan,
            run_id=run_id,
            engine_id=engine_id,
            engine_version=engine_version,
            engine_artifact_sha256=engine_artifact_sha256,
        )
    )
    definitions = [
        ("policy_unknown", {"policy_id": "unknown-policy"}, {}),
        ("run_binding_mismatch", {"run_id": "substituted-run"}, {}),
        (
            "agent_policy_denied",
            {
                "agent_id": "agent-limited",
                "workload_spiffe_id": "spiffe://example.gov/workload/agent-limited",
                "policy_id": "high-impact",
            },
            {},
        ),
        ("requester_unknown", {"requester_id": "unknown-requester"}, {}),
        ("approval_denied", {}, {"decision": "deny"}),
        ("approver_unknown", {}, {"approver_id": "unknown-approver"}),
        (
            "approver_role_unauthorized",
            {},
            {"approver_role": "mission-owner"},
        ),
        ("approval_predates_intent", {}, {"issued_offset": -1}),
        ("approval_window_invalid", {}, {"expires_offset": 400}),
    ]
    for sequence, (reason, intent_changes, approval_changes) in enumerate(definitions, start=17):
        minute = sequence - 1
        policy_id = intent_changes.get("policy_id", "standard-change")
        intent = {
            "intent_id": f"conformance-intent-{sequence:02d}",
            "proposed_at": _reference_time(minute, 0),
            "tenant_id": plan["environment"]["tenant_id"],
            "run_id": run_id,
            "agent_id": "agent-a",
            "workload_spiffe_id": "spiffe://example.gov/workload/agent-a",
            "requester_id": "requester-a",
            "policy_id": policy_id,
            "action": "apply-change",
            "resource_id": f"conformance-resource-{sequence:02d}",
            "impact_units": 5,
            "intent_nonce": f"conformance-intent-nonce-{sequence:02d}",
        }
        intent.update(intent_changes)
        intent_sha256 = _sha256(_canonical(intent))
        approval_id = f"conformance-approval-{sequence:02d}"
        approval = {
            "approval_id": approval_id,
            "approver_id": "approver-operator",
            "approver_role": "operator",
            "decision": "approve",
            "intent_sha256": intent_sha256,
            "issued_at": _reference_time(minute, approval_changes.get("issued_offset", 10)),
            "expires_at": _reference_time(minute, approval_changes.get("expires_offset", 250)),
            "nonce": f"{approval_id}-nonce",
        }
        approval.update(
            {
                key: value
                for key, value in approval_changes.items()
                if key not in {"issued_offset", "expires_offset"}
            }
        )
        run["transactions"].append(
            {
                "transaction_id": f"tx-{sequence:02d}",
                "sequence": sequence,
                "intent": intent,
                "intent_sha256": intent_sha256,
                "approvals": [approval],
                "decision": {
                    "decision_id": f"decision-{sequence:02d}",
                    "decided_at": _reference_time(minute, 20),
                    "decision": "block",
                    "reason_code": reason,
                },
                "outcome": {
                    "state": "not_attempted",
                    "observed_at": None,
                    "sensor_id": None,
                },
            }
        )
    run["completed_at"] = "2026-09-05T15:25:00Z"
    return validate_mandate_run(run, plan)


def _engine(value: Any, field: str) -> Dict[str, Any]:
    engine = _exact(value, field, ("engine_id", "engine_version", "engine_artifact_sha256"))
    _identifier(engine["engine_id"], f"{field}.engine_id")
    _identifier(engine["engine_version"], f"{field}.engine_version")
    if engine["engine_artifact_sha256"] is not None:
        _digest(engine["engine_artifact_sha256"], f"{field}.engine_artifact_sha256")
    return dict(engine)


def _run_from_challenge(
    challenge: Mapping[str, Any],
    engine: Mapping[str, Any],
    answers: Optional[Mapping[str, Mapping[str, str]]] = None,
) -> Dict[str, Any]:
    transactions = []
    for case in challenge["cases"]:
        answer = (
            answers[case["case_id"]]
            if answers is not None
            else {"decision": "block", "reason_code": "policy_unknown"}
        )
        transaction = case["transaction"]
        transactions.append(
            {
                "transaction_id": transaction["transaction_id"],
                "sequence": case["sequence"],
                "intent": transaction["intent"],
                "intent_sha256": transaction["intent_sha256"],
                "approvals": transaction["approvals"],
                "decision": {
                    "decision_id": f"{case['case_id']}-decision",
                    "decided_at": transaction["decided_at"],
                    "decision": answer["decision"],
                    "reason_code": answer["reason_code"],
                },
                "outcome": {
                    "state": "not_attempted",
                    "observed_at": None,
                    "sensor_id": None,
                },
            }
        )
    execution = challenge["execution"]
    return {
        "schema": RUN_SCHEMA,
        "schema_version": 1,
        "run_id": execution["run_id"],
        "campaign_id": challenge["campaign_id"],
        "plan_sha256": challenge["plan_sha256"],
        "started_at": execution["started_at"],
        "completed_at": execution["completed_at"],
        "engine": dict(engine),
        "transactions": transactions,
        "privacy": dict(PRIVACY),
        "limitations": list(LIMITATIONS),
    }


def validate_mandate_challenge(value: Any) -> Dict[str, Any]:
    challenge = _exact(
        value,
        "LureMandate conformance challenge",
        (
            "schema",
            "schema_version",
            "challenge_id",
            "generated_at",
            "campaign_id",
            "plan_sha256",
            "plan",
            "execution",
            "cases",
            "privacy",
            "limitations",
        ),
    )
    if challenge["schema"] != CHALLENGE_SCHEMA or (
        type(challenge["schema_version"]) is not int or challenge["schema_version"] != 1
    ):
        raise ValueError("unsupported LureMandate conformance challenge schema")
    _identifier(challenge["challenge_id"], "challenge_id")
    generated = _instant(challenge["generated_at"], "generated_at")
    _identifier(challenge["campaign_id"], "campaign_id")
    _digest(challenge["plan_sha256"], "plan_sha256")
    plan = validate_mandate_plan(challenge["plan"])
    if challenge["campaign_id"] != plan["campaign_id"] or challenge["plan_sha256"] != _sha256(
        _canonical(plan)
    ):
        raise ValueError("conformance challenge does not bind its embedded plan")
    execution = _exact(
        challenge["execution"],
        "challenge execution",
        ("run_id", "started_at", "completed_at", "state_model"),
    )
    _identifier(execution["run_id"], "execution.run_id")
    started = _instant(execution["started_at"], "execution.started_at")
    completed = _instant(execution["completed_at"], "execution.completed_at")
    if completed < started or generated < completed:
        raise ValueError("conformance challenge has an invalid execution chronology")
    if execution["state_model"] != STATE_MODEL:
        raise ValueError("conformance challenge requires one ordered stateful session")

    case_ids: list[str] = []
    sequences: list[int] = []
    for index, item in enumerate(_bounded(challenge["cases"], "cases", 4096)):
        case = _exact(item, f"cases[{index}]", ("case_id", "sequence", "transaction"))
        case_id = _identifier(case["case_id"], f"cases[{index}].case_id")
        expected_case_id = f"case-{index + 1:04d}"
        if case_id != expected_case_id:
            raise ValueError("conformance case IDs must be opaque contiguous identifiers")
        if type(case["sequence"]) is not int or case["sequence"] != index + 1:
            raise ValueError("conformance cases must use contiguous execution order")
        transaction = _exact(
            case["transaction"],
            f"cases[{index}].transaction",
            (
                "transaction_id",
                "intent",
                "intent_sha256",
                "approvals",
                "decided_at",
            ),
        )
        _identifier(transaction["transaction_id"], "transaction_id")
        _digest(transaction["intent_sha256"], "intent_sha256")
        _instant(transaction["decided_at"], "decided_at")
        case_ids.append(case_id)
        sequences.append(case["sequence"])
    if len(case_ids) != len(set(case_ids)) or sequences != list(range(1, len(sequences) + 1)):
        raise ValueError("conformance cases must be unique and ordered")
    if challenge["privacy"] != PRIVACY:
        raise ValueError("conformance challenge must preserve the metadata-only privacy profile")
    if challenge["limitations"] != list(CONFORMANCE_LIMITATIONS):
        raise ValueError("conformance challenge must preserve its complete claims boundary")
    placeholder = _run_from_challenge(
        challenge,
        {"engine_id": "unscored-gateway", "engine_version": "0", "engine_artifact_sha256": None},
    )
    validate_mandate_run(placeholder, plan)
    return dict(challenge)


def compile_mandate_challenge(
    plan_value: Mapping[str, Any],
    template_run_value: Mapping[str, Any],
    *,
    challenge_id: str,
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    plan = validate_mandate_plan(plan_value)
    run = validate_mandate_run(template_run_value, plan)
    created = generated_at or _now()
    if _instant(created, "generated_at") < _instant(run["completed_at"], "completed_at"):
        raise ValueError("conformance challenge cannot predate its template execution")
    challenge = {
        "schema": CHALLENGE_SCHEMA,
        "schema_version": 1,
        "challenge_id": challenge_id,
        "generated_at": created,
        "campaign_id": plan["campaign_id"],
        "plan_sha256": _sha256(_canonical(plan)),
        "plan": plan,
        "execution": {
            "run_id": run["run_id"],
            "started_at": run["started_at"],
            "completed_at": run["completed_at"],
            "state_model": STATE_MODEL,
        },
        "cases": [
            {
                "case_id": f"case-{index:04d}",
                "sequence": index,
                "transaction": {
                    "transaction_id": transaction["transaction_id"],
                    "intent": transaction["intent"],
                    "intent_sha256": transaction["intent_sha256"],
                    "approvals": transaction["approvals"],
                    "decided_at": transaction["decision"]["decided_at"],
                },
            }
            for index, transaction in enumerate(run["transactions"], start=1)
        ],
        "privacy": dict(PRIVACY),
        "limitations": list(CONFORMANCE_LIMITATIONS),
    }
    return validate_mandate_challenge(challenge)


def validate_mandate_submission(value: Any, challenge_value: Mapping[str, Any]) -> Dict[str, Any]:
    challenge = validate_mandate_challenge(challenge_value)
    submission = _exact(
        value,
        "LureMandate conformance submission",
        (
            "schema",
            "schema_version",
            "submission_id",
            "submitted_at",
            "challenge_id",
            "challenge_sha256",
            "engine",
            "results",
            "limitations",
        ),
    )
    if submission["schema"] != SUBMISSION_SCHEMA or (
        type(submission["schema_version"]) is not int or submission["schema_version"] != 1
    ):
        raise ValueError("unsupported LureMandate conformance submission schema")
    _identifier(submission["submission_id"], "submission_id")
    if _instant(submission["submitted_at"], "submitted_at") < _instant(
        challenge["generated_at"], "challenge generated_at"
    ):
        raise ValueError("conformance submission predates its challenge")
    _identifier(submission["challenge_id"], "challenge_id")
    _digest(submission["challenge_sha256"], "challenge_sha256")
    if submission["challenge_id"] != challenge["challenge_id"] or submission[
        "challenge_sha256"
    ] != _sha256(_canonical(challenge)):
        raise ValueError("conformance submission does not bind the supplied challenge")
    _engine(submission["engine"], "submission engine")
    results = _bounded(submission["results"], "submission results", 4096)
    if len(results) != len(challenge["cases"]):
        raise ValueError("conformance submission must cover every challenge case exactly once")
    for index, (item, case) in enumerate(zip(results, challenge["cases"], strict=True)):
        result = _exact(
            item,
            f"results[{index}]",
            ("case_id", "decision", "reason_code"),
        )
        if result["case_id"] != case["case_id"]:
            raise ValueError("submission results must preserve challenge case order")
        if result["decision"] not in DECISIONS or result["reason_code"] not in REASON_CODES:
            raise ValueError("submission contains an unsupported decision or reason code")
    if submission["limitations"] != list(CONFORMANCE_LIMITATIONS):
        raise ValueError("conformance submission must preserve its complete claims boundary")
    return dict(submission)


def reference_mandate_submission(
    challenge_value: Mapping[str, Any],
    *,
    submission_id: str,
    engine_id: str = "luremandate-reference",
    engine_version: str = VERSION,
    engine_artifact_sha256: Optional[str] = None,
    submitted_at: Optional[str] = None,
) -> Dict[str, Any]:
    challenge = validate_mandate_challenge(challenge_value)
    engine = _engine(
        {
            "engine_id": engine_id,
            "engine_version": engine_version,
            "engine_artifact_sha256": engine_artifact_sha256,
        },
        "reference engine",
    )
    placeholder = _run_from_challenge(challenge, engine)
    oracle = evaluate_mandate(
        challenge["plan"], placeholder, evaluated_at=challenge["generated_at"]
    )
    submission = {
        "schema": SUBMISSION_SCHEMA,
        "schema_version": 1,
        "submission_id": submission_id,
        "submitted_at": submitted_at or _now(),
        "challenge_id": challenge["challenge_id"],
        "challenge_sha256": _sha256(_canonical(challenge)),
        "engine": engine,
        "results": [
            {
                "case_id": case["case_id"],
                "decision": result["expected_decision"],
                "reason_code": result["expected_reason_code"],
            }
            for case, result in zip(challenge["cases"], oracle["results"], strict=True)
        ],
        "limitations": list(CONFORMANCE_LIMITATIONS),
    }
    return validate_mandate_submission(submission, challenge)


def _score_value(
    challenge_value: Mapping[str, Any],
    submission_value: Mapping[str, Any],
    *,
    evaluated_at: str,
) -> Dict[str, Any]:
    challenge = validate_mandate_challenge(challenge_value)
    submission = validate_mandate_submission(submission_value, challenge)
    evaluated = _instant(evaluated_at, "evaluated_at")
    if evaluated < max(
        _instant(challenge["generated_at"], "challenge generated_at"),
        _instant(submission["submitted_at"], "submission submitted_at"),
    ):
        raise ValueError("conformance score predates its challenge or submission")
    answers = {item["case_id"]: item for item in submission["results"]}
    scored_run = _run_from_challenge(challenge, submission["engine"], answers)
    evaluation = evaluate_mandate(challenge["plan"], scored_run, evaluated_at=evaluated_at)
    results = []
    decision_match_count = reason_match_count = exact_match_count = 0
    invalid_allow_count = collateral_denial_count = 0
    reason_counts: Dict[str, int] = {}
    for case, item in zip(challenge["cases"], evaluation["results"], strict=True):
        decision_match = item["submitted_decision"] == item["expected_decision"]
        reason_match = item["submitted_reason_code"] == item["expected_reason_code"]
        exact_match = decision_match and reason_match
        decision_match_count += int(decision_match)
        reason_match_count += int(reason_match)
        exact_match_count += int(exact_match)
        invalid_allow_count += int(
            item["expected_decision"] == "block" and item["submitted_decision"] == "allow"
        )
        collateral_denial_count += int(
            item["expected_decision"] == "allow" and item["submitted_decision"] == "block"
        )
        reason_counts[item["expected_reason_code"]] = (
            reason_counts.get(item["expected_reason_code"], 0) + 1
        )
        results.append(
            {
                "case_id": case["case_id"],
                "sequence": case["sequence"],
                "expected_decision": item["expected_decision"],
                "expected_reason_code": item["expected_reason_code"],
                "submitted_decision": item["submitted_decision"],
                "submitted_reason_code": item["submitted_reason_code"],
                "decision_match": decision_match,
                "reason_match": reason_match,
                "status": "pass" if exact_match else "fail",
            }
        )
    case_count = len(results)
    summary = {
        "verdict": "pass" if exact_match_count == case_count else "fail",
        "case_count": case_count,
        "exact_match_count": exact_match_count,
        "decision_match_count": decision_match_count,
        "reason_match_count": reason_match_count,
        "invalid_allow_count": invalid_allow_count,
        "collateral_denial_count": collateral_denial_count,
        "covered_reason_count": len(reason_counts),
        "reason_universe_count": len(REASON_CODES),
        "reason_coverage_complete": set(reason_counts) == REASON_CODES,
    }
    return {
        "schema": SCORE_SCHEMA,
        "schema_version": 1,
        "score_id": f"{submission['submission_id']}-score",
        "evaluated_at": evaluated_at,
        "evaluator": {"name": "lurebench-luremandate-conformance", "version": VERSION},
        "challenge_sha256": _sha256(_canonical(challenge)),
        "submission_sha256": _sha256(_canonical(submission)),
        "challenge": challenge,
        "submission": submission,
        "results": results,
        "guard_coverage": [
            {"expected_reason_code": reason, "case_count": reason_counts.get(reason, 0)}
            for reason in sorted(REASON_CODES)
        ],
        "summary": summary,
        "limitations": list(CONFORMANCE_LIMITATIONS),
    }


def evaluate_mandate_conformance(
    challenge_value: Mapping[str, Any],
    submission_value: Mapping[str, Any],
    *,
    evaluated_at: Optional[str] = None,
) -> Dict[str, Any]:
    return _score_value(
        challenge_value,
        submission_value,
        evaluated_at=evaluated_at or _now(),
    )


def validate_mandate_conformance_score(value: Any) -> Dict[str, Any]:
    score = _exact(
        value,
        "LureMandate conformance score",
        (
            "schema",
            "schema_version",
            "score_id",
            "evaluated_at",
            "evaluator",
            "challenge_sha256",
            "submission_sha256",
            "challenge",
            "submission",
            "results",
            "guard_coverage",
            "summary",
            "limitations",
        ),
    )
    if score["schema"] != SCORE_SCHEMA or (
        type(score["schema_version"]) is not int or score["schema_version"] != 1
    ):
        raise ValueError("unsupported LureMandate conformance score schema")
    expected = _score_value(
        score["challenge"], score["submission"], evaluated_at=score["evaluated_at"]
    )
    if _canonical(score) != _canonical(expected):
        raise ValueError("LureMandate conformance score does not independently recompute")
    return dict(score)


def write_mandate_challenge(path: Path, value: Mapping[str, Any]) -> None:
    _write(Path(path), validate_mandate_challenge(value))


def write_exhaustive_mandate_conformance_template(
    directory: Path,
    *,
    run_id: str = "mandate-conformance-run-1",
    engine_id: str = "luremandate-reference",
    engine_version: str = VERSION,
    engine_artifact_sha256: Optional[str] = None,
) -> tuple[Path, Path]:
    """Create a private no-overwrite directory with the exhaustive plan and run."""
    destination = Path(directory)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(destination)
    if not destination.parent.is_dir() or destination.parent.is_symlink():
        raise ValueError("conformance template parent must be a regular directory")
    plan = exhaustive_mandate_conformance_plan()
    run = exhaustive_mandate_conformance_run(
        plan,
        run_id=run_id,
        engine_id=engine_id,
        engine_version=engine_version,
        engine_artifact_sha256=engine_artifact_sha256,
    )
    plan_path = destination / "plan.json"
    run_path = destination / "run.json"
    destination.mkdir(mode=0o700)
    try:
        _write(plan_path, plan)
        _write(run_path, run)
    except Exception:
        plan_path.unlink(missing_ok=True)
        run_path.unlink(missing_ok=True)
        destination.rmdir()
        raise
    return plan_path, run_path


def write_mandate_submission(
    path: Path, value: Mapping[str, Any], challenge: Mapping[str, Any]
) -> None:
    _write(Path(path), validate_mandate_submission(value, challenge))


def write_mandate_conformance_score(path: Path, value: Mapping[str, Any]) -> None:
    _write(Path(path), validate_mandate_conformance_score(value))


def load_mandate_challenge(path: Path) -> Dict[str, Any]:
    return validate_mandate_challenge(_load(Path(path), "LureMandate conformance challenge"))


def load_mandate_submission(path: Path, challenge: Mapping[str, Any]) -> Dict[str, Any]:
    return validate_mandate_submission(
        _load(Path(path), "LureMandate conformance submission"), challenge
    )


def load_mandate_conformance_score(path: Path) -> Dict[str, Any]:
    return validate_mandate_conformance_score(_load(Path(path), "LureMandate conformance score"))
