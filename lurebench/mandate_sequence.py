"""Ordered 2-way state-operation coverage for LureMandate gateways."""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from .mandate import (
    LIMITATIONS,
    PRIVACY,
    RUN_SCHEMA,
    _sha256,
    _write,
    default_mandate_plan,
    validate_mandate_plan,
    validate_mandate_run,
)
from .mandate_conformance import validate_mandate_conformance_score
from .permit import _canonical, _exact, _identifier

SCHEMA = "https://github.com/immu4989/lurebench/spec/luremandate-sequence-assurance/v1"
VERSION = "1.0.0"
OPERATIONS = (
    "fresh-allow",
    "replay-block",
    "budget-boundary-allow",
    "budget-exceed-block",
    "expired-window-allow",
)
EXPECTED_REASONS = {
    "fresh-allow": "authority_satisfied",
    "replay-block": "approval_replay",
    "budget-boundary-allow": "authority_satisfied",
    "budget-exceed-block": "cumulative_limit_exceeded",
    "expired-window-allow": "authority_satisfied",
}
EXPECTED_DECISIONS = {
    operation: "block" if operation.endswith("block") else "allow" for operation in OPERATIONS
}
LIMITATIONS_SEQUENCE = (
    "ordered_strength_two_operation_coverage_does_not_establish_longer_sequence_coverage",
    "each_measured_operation_uses_an_isolated_requester_scope_to_keep_state_preconditions_stable",
    "reference_submission_tests_the_reference_semantics_not_an_external_gateway",
    "passing_does_not_establish_cross_subject_interference_unrepresented_operations_or_complete_mediation",
    "passing_is_not_compliance_certification_safety_legal_authority_or_deployment_authorization",
)


def _time(second: int, milliseconds: int = 0) -> str:
    instant = datetime(2026, 9, 5, 15, 0, tzinfo=timezone.utc) + timedelta(
        seconds=second, milliseconds=milliseconds
    )
    return instant.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _de_bruijn_order_two() -> list[str]:
    """Return a deterministic cyclic B(5, 2), linearized to expose its wrap pair."""
    alphabet_size = len(OPERATIONS)
    work = [0] * (alphabet_size * 2)
    output: list[int] = []

    def visit(position: int, period: int) -> None:
        if position > 2:
            if 2 % period == 0:
                output.extend(work[1 : period + 1])
            return
        work[position] = work[position - period]
        visit(position + 1, period)
        for value in range(work[position - period] + 1, alphabet_size):
            work[position] = value
            visit(position + 1, position)

    visit(1, 1)
    sequence = [OPERATIONS[index] for index in output]
    return sequence + sequence[:1]


def sequence_mandate_plan() -> Dict[str, Any]:
    plan = copy.deepcopy(default_mandate_plan())
    plan["campaign_id"] = "luremandate-sequence-v1"
    plan["people"].extend(
        {
            "person_id": f"sequence-subject-{index:02d}",
            "roles": ["requester"],
        }
        for index in range(1, len(_de_bruijn_order_two()) + 1)
    )
    plan["people"].sort(key=lambda item: item["person_id"])
    return validate_mandate_plan(plan)


def _intent(
    operation_index: int,
    variant: str,
    run_id: str,
    second: int,
    impact_units: int,
    action: str,
) -> Dict[str, Any]:
    return {
        "intent_id": f"sequence-{operation_index:02d}-{variant}-intent",
        "proposed_at": _time(second, 100),
        "tenant_id": "agency-tenant",
        "run_id": run_id,
        "agent_id": "agent-a",
        "workload_spiffe_id": "spiffe://example.gov/workload/agent-a",
        "requester_id": f"sequence-subject-{operation_index:02d}",
        "policy_id": "high-impact",
        "action": action,
        "resource_id": f"sequence-resource-{operation_index:02d}",
        "impact_units": impact_units,
        "intent_nonce": f"sequence-{operation_index:02d}-{variant}-intent-nonce",
    }


def _approvals(
    operation_index: int,
    variant: str,
    intent_sha256: str,
    second: int,
) -> list[Dict[str, Any]]:
    return [
        {
            "approval_id": f"sequence-{operation_index:02d}-{variant}-mission",
            "approver_id": "approver-mission",
            "approver_role": "mission-owner",
            "decision": "approve",
            "intent_sha256": intent_sha256,
            "issued_at": _time(second, 200),
            "expires_at": _time(second, 900),
            "nonce": f"sequence-{operation_index:02d}-{variant}-mission-nonce",
        },
        {
            "approval_id": f"sequence-{operation_index:02d}-{variant}-security",
            "approver_id": "approver-security",
            "approver_role": "security-reviewer",
            "decision": "approve",
            "intent_sha256": intent_sha256,
            "issued_at": _time(second, 200),
            "expires_at": _time(second, 900),
            "nonce": f"sequence-{operation_index:02d}-{variant}-security-nonce",
        },
    ]


def _transaction(
    transaction_id: str,
    sequence: int,
    intent: Mapping[str, Any],
    approvals: list[Mapping[str, Any]],
    second: int,
) -> Dict[str, Any]:
    return {
        "transaction_id": transaction_id,
        "sequence": sequence,
        "intent": dict(intent),
        "intent_sha256": _sha256(_canonical(intent)),
        "approvals": [dict(item) for item in approvals],
        "decision": {
            "decision_id": f"{transaction_id}-decision",
            "decided_at": _time(second, 400),
            "decision": "block",
            "reason_code": "policy_unknown",
        },
        "outcome": {"state": "not_attempted", "observed_at": None, "sensor_id": None},
    }


def sequence_mandate_run(
    plan_value: Optional[Mapping[str, Any]] = None,
    *,
    run_id: str = "mandate-sequence-run-1",
    engine_id: str = "luremandate-reference",
    engine_version: str = VERSION,
    engine_artifact_sha256: Optional[str] = None,
) -> Dict[str, Any]:
    plan = validate_mandate_plan(plan_value or sequence_mandate_plan())
    operations = _de_bruijn_order_two()
    old_window = [
        index
        for index, operation in enumerate(operations, start=1)
        if operation == "expired-window-allow"
    ]
    recent = [
        index
        for index, operation in enumerate(operations, start=1)
        if operation in {"replay-block", "budget-boundary-allow", "budget-exceed-block"}
    ]
    primed: Dict[int, tuple[Dict[str, Any], list[Dict[str, Any]]]] = {}
    transactions = []
    preamble_order = old_window + recent
    for preamble_index, operation_index in enumerate(preamble_order, start=1):
        operation = operations[operation_index - 1]
        second = preamble_index if operation == "expired-window-allow" else 3_600 + preamble_index
        impact = 10 if operation == "replay-block" else 100
        intent = _intent(
            operation_index,
            "prime",
            run_id,
            second,
            impact,
            "state-prime",
        )
        digest = _sha256(_canonical(intent))
        approvals = _approvals(operation_index, "prime", digest, second)
        primed[operation_index] = (intent, approvals)
        transactions.append(
            _transaction(
                f"preamble-{preamble_index:02d}",
                preamble_index,
                intent,
                approvals,
                second,
            )
        )
    preamble_count = len(transactions)
    for sequence_index, operation in enumerate(operations, start=1):
        sequence = preamble_count + sequence_index
        second = 3_800 + sequence_index
        impact = {
            "fresh-allow": 10,
            "replay-block": 10,
            "budget-boundary-allow": 50,
            "budget-exceed-block": 51,
            "expired-window-allow": 100,
        }[operation]
        intent = _intent(
            sequence_index,
            "measure",
            run_id,
            second,
            impact,
            f"sequence-{operation}",
        )
        digest = _sha256(_canonical(intent))
        approvals = _approvals(sequence_index, "measure", digest, second)
        if operation == "replay-block":
            approvals[0] = copy.deepcopy(primed[sequence_index][1][0])
            approvals.sort(key=lambda item: item["approval_id"])
        transactions.append(
            _transaction(
                f"sequence-{sequence_index:02d}",
                sequence,
                intent,
                approvals,
                second,
            )
        )
    run = {
        "schema": RUN_SCHEMA,
        "schema_version": 1,
        "run_id": run_id,
        "campaign_id": plan["campaign_id"],
        "plan_sha256": _sha256(_canonical(plan)),
        "started_at": _time(0),
        "completed_at": _time(3_900),
        "engine": {
            "engine_id": engine_id,
            "engine_version": engine_version,
            "engine_artifact_sha256": engine_artifact_sha256,
        },
        "transactions": transactions,
        "privacy": dict(PRIVACY),
        "limitations": list(LIMITATIONS),
    }
    return validate_mandate_run(run, plan)


def _value(score_value: Mapping[str, Any]) -> Dict[str, Any]:
    score = validate_mandate_conformance_score(score_value)
    cases = score["challenge"]["cases"]
    results = score["results"]
    if len(cases) != 46:
        raise ValueError("sequence campaign must contain exactly 20 preamble and 26 measured cases")
    if any(
        case["transaction"]["intent"]["action"] != "state-prime" for case in cases[:20]
    ):
        raise ValueError("sequence campaign must begin with exactly 20 state-prime cases")
    measured = []
    for case, result in zip(cases[20:], results[20:], strict=True):
        action = case["transaction"]["intent"]["action"]
        if not action.startswith("sequence-"):
            raise ValueError("sequence campaign measured cases require sequence actions")
        operation = action.removeprefix("sequence-")
        if operation not in OPERATIONS:
            raise ValueError("sequence campaign contains an unsupported operation")
        measured.append((case, result, operation))
    expected_sequence = _de_bruijn_order_two()
    if [item[2] for item in measured] != expected_sequence:
        raise ValueError("sequence campaign does not match the fixed ordered covering sequence")
    requesters = [item[0]["transaction"]["intent"]["requester_id"] for item in measured]
    if len(set(requesters)) != len(expected_sequence):
        raise ValueError("sequence campaign measured cases require isolated requester scopes")
    operation_results = []
    passed_operations = 0
    for case, result, operation in measured:
        passed = (
            result["expected_decision"] == EXPECTED_DECISIONS[operation]
            and result["expected_reason_code"] == EXPECTED_REASONS[operation]
            and result["status"] == "pass"
        )
        passed_operations += int(passed)
        operation_results.append(
            {
                "case_id": case["case_id"],
                "operation": operation,
                "expected_decision": result["expected_decision"],
                "expected_reason_code": result["expected_reason_code"],
                "submitted_decision": result["submitted_decision"],
                "submitted_reason_code": result["submitted_reason_code"],
                "status": "pass" if passed else "fail",
            }
        )
    covered_pairs = sorted(
        {
            f"{left}>{right}"
            for left, right in zip(expected_sequence, expected_sequence[1:], strict=False)
        }
    )
    required_pairs = sorted(f"{left}>{right}" for left in OPERATIONS for right in OPERATIONS)
    missing_pairs = [item for item in required_pairs if item not in covered_pairs]
    sequence_count = len(measured)
    preamble_count = len(cases) - sequence_count
    sequence_complete = not missing_pairs and len(covered_pairs) == len(required_pairs)
    score_passed = score["summary"]["verdict"] == "pass"
    return {
        "schema": SCHEMA,
        "schema_version": 1,
        "report_id": f"{score['score_id']}-sequence",
        "evaluated_at": score["evaluated_at"],
        "method": {
            "name": "cyclic-de-bruijn-ordered-operation-coverage",
            "strength": 2,
            "operation_alphabet": list(OPERATIONS),
        },
        "score_sha256": _sha256(_canonical(score)),
        "score": score,
        "operation_results": operation_results,
        "ordered_pair_coverage": {
            "required_pairs": required_pairs,
            "covered_pairs": covered_pairs,
            "missing_pairs": missing_pairs,
        },
        "summary": {
            "verdict": "pass"
            if score_passed and passed_operations == sequence_count and sequence_complete
            else "fail",
            "score_verdict": score["summary"]["verdict"],
            "preamble_case_count": preamble_count,
            "measured_case_count": sequence_count,
            "passed_measured_case_count": passed_operations,
            "operation_count": len(OPERATIONS),
            "required_ordered_pair_count": len(required_pairs),
            "covered_ordered_pair_count": len(covered_pairs),
            "ordered_pair_coverage_complete": sequence_complete,
        },
        "limitations": list(LIMITATIONS_SEQUENCE),
    }


def evaluate_sequence_mandate_conformance(score_value: Mapping[str, Any]) -> Dict[str, Any]:
    return validate_sequence_mandate_conformance(_value(score_value))


def validate_sequence_mandate_conformance(value: Any) -> Dict[str, Any]:
    report = _exact(
        value,
        "LureMandate sequence assurance",
        (
            "schema",
            "schema_version",
            "report_id",
            "evaluated_at",
            "method",
            "score_sha256",
            "score",
            "operation_results",
            "ordered_pair_coverage",
            "summary",
            "limitations",
        ),
    )
    if report["schema"] != SCHEMA or report["schema_version"] != 1:
        raise ValueError("unsupported LureMandate sequence assurance schema")
    _identifier(report["report_id"], "sequence report_id")
    if report != _value(report["score"]):
        raise ValueError("LureMandate sequence assurance does not independently recompute")
    return dict(report)


def write_sequence_mandate_template(
    directory: Path,
    *,
    run_id: str = "mandate-sequence-run-1",
    engine_id: str = "luremandate-reference",
    engine_version: str = VERSION,
    engine_artifact_sha256: Optional[str] = None,
) -> tuple[Path, Path]:
    destination = Path(directory)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(destination)
    if not destination.parent.is_dir() or destination.parent.is_symlink():
        raise ValueError("sequence template parent must be a regular directory")
    plan = sequence_mandate_plan()
    run = sequence_mandate_run(
        plan,
        run_id=run_id,
        engine_id=engine_id,
        engine_version=engine_version,
        engine_artifact_sha256=engine_artifact_sha256,
    )
    destination.mkdir(mode=0o700)
    plan_path = destination / "plan.json"
    run_path = destination / "run.json"
    try:
        _write(plan_path, plan)
        _write(run_path, run)
    except Exception:
        plan_path.unlink(missing_ok=True)
        run_path.unlink(missing_ok=True)
        destination.rmdir()
        raise
    return plan_path, run_path


def write_sequence_mandate_conformance(path: Path, value: Mapping[str, Any]) -> None:
    _write(Path(path), validate_sequence_mandate_conformance(value))


def load_sequence_mandate_conformance(path: Path) -> Dict[str, Any]:
    from .mandate import _load

    return validate_sequence_mandate_conformance(
        _load(Path(path), "LureMandate sequence assurance")
    )
