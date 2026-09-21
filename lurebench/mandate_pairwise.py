"""Deterministic 2-way input-interaction assurance for LureMandate gateways.

The reference campaign uses a binary orthogonal array: 16 answer-free cases
cover all four value combinations for every pair of 15 authority input factors.
This complements, but does not replace, reason/branch and stateful-sequence
coverage in the exhaustive LureMandate conformance campaign.
"""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from itertools import combinations
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from .mandate import (
    LIMITATIONS,
    PRIVACY,
    RUN_SCHEMA,
    _instant,
    _sha256,
    _write,
    default_mandate_plan,
    validate_mandate_plan,
    validate_mandate_run,
)
from .mandate_conformance import validate_mandate_conformance_score
from .permit import _canonical, _exact, _identifier

SCHEMA = "https://github.com/immu4989/lurebench/spec/luremandate-pairwise-assurance/v1"
VERSION = "1.0.0"
STRENGTH = 2
CASE_COUNT = 16
FACTOR_IDS = (
    "tenant_binding",
    "run_binding",
    "agent_workload_binding",
    "agent_policy_assignment",
    "requester_registry_membership",
    "impact_within_limit",
    "approval_intent_binding",
    "approval_decision",
    "requester_separation",
    "security_approver_registry_membership",
    "mission_role_assignment",
    "mission_issue_before_decision",
    "mission_unexpired_at_decision",
    "security_ttl_within_policy",
    "required_security_role",
)
COMBINATIONS = ("00", "01", "10", "11")
LIMITATIONS_PAIRWISE = (
    "binary_two_way_input_coverage_does_not_establish_three_way_or_higher_interaction_coverage",
    "factor_abstraction_and_feasible_value_domains_are_specific_to_the_reference_campaign",
    "reference_submission_tests_the_reference_semantics_not_an_external_gateway",
    "passing_does_not_prove_implementation_structure_unrepresented_behavior_or_complete_mediation",
    "passing_is_not_compliance_certification_safety_legal_authority_or_deployment_authorization",
)


def _time(second: int, milliseconds: int = 0) -> str:
    instant = datetime(2026, 9, 5, 15, 0, tzinfo=timezone.utc) + timedelta(
        seconds=second, milliseconds=milliseconds
    )
    return instant.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _row(index: int) -> Dict[str, bool]:
    """Return one OA(16, 15, 2, 2) row over nonzero GF(2)^4 columns."""
    return {
        factor: (index & mask).bit_count() % 2 == 0
        for factor, mask in zip(FACTOR_IDS, range(1, len(FACTOR_IDS) + 1), strict=True)
    }


def pairwise_mandate_plan() -> Dict[str, Any]:
    plan = copy.deepcopy(default_mandate_plan())
    plan["campaign_id"] = "luremandate-pairwise-v1"
    plan["agents"].append(
        {
            "agent_id": "agent-limited",
            "workload_spiffe_id": "spiffe://example.gov/workload/agent-limited",
            "allowed_policy_ids": ["standard-change"],
        }
    )
    plan["agents"].sort(key=lambda item: item["agent_id"])
    for person in plan["people"]:
        if person["person_id"] == "requester-a":
            person["roles"] = ["mission-owner", "requester"]
        elif person["person_id"] == "approver-security":
            person["roles"] = ["operator", "security-reviewer"]
    for policy in plan["policies"]:
        if policy["policy_id"] == "high-impact":
            policy["cumulative_limit_units"] = 1_000_000_000
            policy["cumulative_window_ms"] = 1
            policy["approval_ttl_ms"] = 1_000
    return validate_mandate_plan(plan)


def pairwise_mandate_run(
    plan_value: Optional[Mapping[str, Any]] = None,
    *,
    run_id: str = "mandate-pairwise-run-1",
    engine_id: str = "luremandate-reference",
    engine_version: str = VERSION,
    engine_artifact_sha256: Optional[str] = None,
) -> Dict[str, Any]:
    plan = validate_mandate_plan(plan_value or pairwise_mandate_plan())
    transactions = []
    for offset in range(CASE_COUNT):
        sequence = offset + 1
        values = _row(offset)
        proposed = _time(sequence, 100)
        decision_time = _time(sequence, 400)
        agent_id = "agent-a" if values["agent_policy_assignment"] else "agent-limited"
        expected_workload = f"spiffe://example.gov/workload/{agent_id}"
        intent = {
            "intent_id": f"pairwise-intent-{sequence:02d}",
            "proposed_at": proposed,
            "tenant_id": "agency-tenant" if values["tenant_binding"] else "other-tenant",
            "run_id": run_id if values["run_binding"] else "other-run",
            "agent_id": agent_id,
            "workload_spiffe_id": (
                expected_workload
                if values["agent_workload_binding"]
                else "spiffe://example.gov/workload/substituted"
            ),
            "requester_id": (
                "requester-a" if values["requester_registry_membership"] else "unknown-requester"
            ),
            "policy_id": "high-impact",
            "action": "apply-change",
            "resource_id": f"pairwise-resource-{sequence:02d}",
            "impact_units": 10 if values["impact_within_limit"] else 101,
            "intent_nonce": f"pairwise-intent-nonce-{sequence:02d}",
        }
        intent_sha256 = _sha256(_canonical(intent))
        requester_id = intent["requester_id"]
        mission_id = "approver-mission" if values["requester_separation"] else requester_id
        mission_issued = _time(
            sequence,
            200 if values["mission_issue_before_decision"] else 500,
        )
        mission_expires = _time(
            sequence,
            900 if values["mission_unexpired_at_decision"] else 300,
        )
        security_expires = _time(
            sequence,
            900 if values["security_ttl_within_policy"] else 1_500,
        )
        approvals = [
            {
                "approval_id": f"pairwise-mission-{sequence:02d}",
                "approver_id": mission_id,
                "approver_role": (
                    "mission-owner" if values["mission_role_assignment"] else "operator"
                ),
                "decision": "approve" if values["approval_decision"] else "deny",
                "intent_sha256": (intent_sha256 if values["approval_intent_binding"] else "f" * 64),
                "issued_at": mission_issued,
                "expires_at": mission_expires,
                "nonce": f"pairwise-mission-nonce-{sequence:02d}",
            },
            {
                "approval_id": f"pairwise-security-{sequence:02d}",
                "approver_id": (
                    "approver-security"
                    if values["security_approver_registry_membership"]
                    else "unknown-security"
                ),
                "approver_role": (
                    "security-reviewer" if values["required_security_role"] else "operator"
                ),
                "decision": "approve",
                "intent_sha256": intent_sha256,
                "issued_at": _time(sequence, 200),
                "expires_at": security_expires,
                "nonce": f"pairwise-security-nonce-{sequence:02d}",
            },
        ]
        transactions.append(
            {
                "transaction_id": f"pairwise-tx-{sequence:02d}",
                "sequence": sequence,
                "intent": intent,
                "intent_sha256": intent_sha256,
                "approvals": approvals,
                "decision": {
                    "decision_id": f"pairwise-decision-{sequence:02d}",
                    "decided_at": decision_time,
                    "decision": "block",
                    "reason_code": "policy_unknown",
                },
                "outcome": {
                    "state": "not_attempted",
                    "observed_at": None,
                    "sensor_id": None,
                },
            }
        )
    run = {
        "schema": RUN_SCHEMA,
        "schema_version": 1,
        "run_id": run_id,
        "campaign_id": plan["campaign_id"],
        "plan_sha256": _sha256(_canonical(plan)),
        "started_at": _time(0),
        "completed_at": _time(CASE_COUNT + 1),
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


def _factor_values(challenge: Mapping[str, Any]) -> list[Dict[str, bool]]:
    plan = challenge["plan"]
    environment = plan["environment"]
    people = {item["person_id"]: item for item in plan["people"]}
    agents = {item["agent_id"]: item for item in plan["agents"]}
    policies = {item["policy_id"]: item for item in plan["policies"]}
    rows = []
    for case in challenge["cases"]:
        transaction = case["transaction"]
        intent = transaction["intent"]
        approvals = transaction["approvals"]
        if len(approvals) != 2 or intent["policy_id"] not in policies:
            raise ValueError("pairwise campaign requires two approvals and one known policy")
        mission, security = approvals
        agent = agents.get(intent["agent_id"])
        policy = policies[intent["policy_id"]]
        mission_person = people.get(mission["approver_id"])
        rows.append(
            {
                "tenant_binding": intent["tenant_id"] == environment["tenant_id"],
                "run_binding": intent["run_id"] == challenge["execution"]["run_id"],
                "agent_workload_binding": agent is not None
                and agent["workload_spiffe_id"] == intent["workload_spiffe_id"],
                "agent_policy_assignment": agent is not None
                and intent["policy_id"] in agent["allowed_policy_ids"],
                "requester_registry_membership": intent["requester_id"] in people,
                "impact_within_limit": intent["impact_units"] <= policy["maximum_impact_units"],
                "approval_intent_binding": mission["intent_sha256"] == transaction["intent_sha256"],
                "approval_decision": mission["decision"] == "approve",
                "requester_separation": mission["approver_id"] != intent["requester_id"],
                "security_approver_registry_membership": security["approver_id"] in people,
                "mission_role_assignment": mission_person is not None
                and mission["approver_role"] in mission_person["roles"],
                "mission_issue_before_decision": _instant(mission["issued_at"], "mission issued_at")
                <= _instant(transaction["decided_at"], "decided_at"),
                "mission_unexpired_at_decision": _instant(
                    mission["expires_at"], "mission expires_at"
                )
                >= _instant(transaction["decided_at"], "decided_at"),
                "security_ttl_within_policy": timedelta(0)
                < _instant(security["expires_at"], "security expires_at")
                - _instant(security["issued_at"], "security issued_at")
                <= timedelta(milliseconds=policy["approval_ttl_ms"]),
                "required_security_role": security["approver_role"] == "security-reviewer",
            }
        )
    return rows


def _value(score_value: Mapping[str, Any]) -> Dict[str, Any]:
    score = validate_mandate_conformance_score(score_value)
    challenge = score["challenge"]
    rows = _factor_values(challenge)
    pair_coverage = []
    covered_total = 0
    for factor_a, factor_b in combinations(FACTOR_IDS, 2):
        covered = sorted({f"{int(row[factor_a])}{int(row[factor_b])}" for row in rows})
        covered_total += len(covered)
        pair_coverage.append(
            {
                "factor_a": factor_a,
                "factor_b": factor_b,
                "covered_combinations": covered,
                "missing_combinations": [item for item in COMBINATIONS if item not in covered],
            }
        )
    required_total = len(pair_coverage) * len(COMBINATIONS)
    coverage_complete = covered_total == required_total
    score_passed = score["summary"]["verdict"] == "pass"
    return {
        "schema": SCHEMA,
        "schema_version": 1,
        "report_id": f"{score['score_id']}-pairwise",
        "evaluated_at": score["evaluated_at"],
        "method": {
            "name": "binary-pairwise-input-coverage",
            "strength": STRENGTH,
            "factor_ids": list(FACTOR_IDS),
            "required_value_combinations": list(COMBINATIONS),
        },
        "score_sha256": _sha256(_canonical(score)),
        "score": score,
        "factor_rows": [
            {"case_id": case["case_id"], "values": row}
            for case, row in zip(challenge["cases"], rows, strict=True)
        ],
        "pair_coverage": pair_coverage,
        "summary": {
            "verdict": "pass" if score_passed and coverage_complete else "fail",
            "score_verdict": score["summary"]["verdict"],
            "case_count": len(rows),
            "factor_count": len(FACTOR_IDS),
            "factor_pair_count": len(pair_coverage),
            "required_interaction_count": required_total,
            "covered_interaction_count": covered_total,
            "interaction_coverage": covered_total / required_total,
            "pairwise_coverage_complete": coverage_complete,
        },
        "limitations": list(LIMITATIONS_PAIRWISE),
    }


def evaluate_pairwise_mandate_conformance(score_value: Mapping[str, Any]) -> Dict[str, Any]:
    return validate_pairwise_mandate_conformance(_value(score_value))


def validate_pairwise_mandate_conformance(value: Any) -> Dict[str, Any]:
    report = _exact(
        value,
        "LureMandate pairwise assurance",
        (
            "schema",
            "schema_version",
            "report_id",
            "evaluated_at",
            "method",
            "score_sha256",
            "score",
            "factor_rows",
            "pair_coverage",
            "summary",
            "limitations",
        ),
    )
    if report["schema"] != SCHEMA or (
        type(report["schema_version"]) is not int or report["schema_version"] != 1
    ):
        raise ValueError("unsupported LureMandate pairwise assurance schema")
    _identifier(report["report_id"], "pairwise report_id")
    expected = _value(report["score"])
    if _canonical(report) != _canonical(expected):
        raise ValueError("LureMandate pairwise assurance does not independently recompute")
    return dict(report)


def write_pairwise_mandate_template(
    directory: Path,
    *,
    run_id: str = "mandate-pairwise-run-1",
    engine_id: str = "luremandate-reference",
    engine_version: str = VERSION,
    engine_artifact_sha256: Optional[str] = None,
) -> tuple[Path, Path]:
    destination = Path(directory)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(destination)
    if not destination.parent.is_dir() or destination.parent.is_symlink():
        raise ValueError("pairwise template parent must be a regular directory")
    plan = pairwise_mandate_plan()
    run = pairwise_mandate_run(
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


def write_pairwise_mandate_conformance(path: Path, value: Mapping[str, Any]) -> None:
    _write(Path(path), validate_pairwise_mandate_conformance(value))


def load_pairwise_mandate_conformance(path: Path) -> Dict[str, Any]:
    from .mandate import _load

    return validate_pairwise_mandate_conformance(
        _load(Path(path), "LureMandate pairwise assurance")
    )
