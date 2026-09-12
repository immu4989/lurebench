"""Counterfactual guard-pair assurance for LureMandate gateways."""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
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

SCHEMA = "https://github.com/immu4989/lurebench/spec/luremandate-counterfactual-assurance/v1"
VERSION = "1.0.0"
COUNTERFACTUALS = (
    ("policy_unknown", ("policy_binding",)),
    ("tenant_mismatch", ("tenant_binding",)),
    ("run_binding_mismatch", ("run_binding",)),
    ("agent_identity_mismatch", ("agent_identity_binding",)),
    ("agent_policy_denied", ("agent_policy_assignment",)),
    ("requester_unknown", ("requester_registry_membership",)),
    ("impact_limit_exceeded", ("impact_within_limit",)),
    (
        "approval_count_insufficient",
        ("approval_count_sufficient", "required_security_role"),
    ),
    ("approval_binding_mismatch", ("mission_intent_binding",)),
    ("approval_denied", ("mission_decision_approve",)),
    ("self_approval", ("requester_separation",)),
    ("approver_unknown", ("mission_approver_registry_membership",)),
    ("approver_role_unauthorized", ("mission_role_assignment",)),
    ("approval_predates_intent", ("mission_not_before_intent",)),
    ("approval_after_decision", ("mission_not_after_decision",)),
    ("approval_expired", ("mission_unexpired_at_decision",)),
    ("approval_window_invalid", ("mission_ttl_within_policy",)),
    ("required_role_missing", ("required_security_role",)),
    (
        "approval_replay",
        (
            "mission_approval_fresh",
            "mission_intent_binding",
            "mission_not_before_intent",
            "mission_unexpired_at_decision",
        ),
    ),
    ("cumulative_limit_exceeded", ("cumulative_budget_available",)),
)
DIMENSION_IDS = (
    "policy_binding",
    "tenant_binding",
    "run_binding",
    "agent_identity_binding",
    "agent_policy_assignment",
    "requester_registry_membership",
    "impact_within_limit",
    "approval_count_sufficient",
    "mission_approval_fresh",
    "mission_intent_binding",
    "mission_decision_approve",
    "requester_separation",
    "mission_approver_registry_membership",
    "mission_role_assignment",
    "mission_not_before_intent",
    "mission_not_after_decision",
    "mission_unexpired_at_decision",
    "mission_ttl_within_policy",
    "required_security_role",
    "cumulative_budget_available",
)
LIMITATIONS_COUNTERFACTUAL = (
    "pairs_measure_declared_semantic_dimensions_not_source_code_conditions_or_formal_mcdc",
    "approval_count_and_replay_pairs_require_multiple_changed_dimensions_due_to_contract_dependencies",
    "reference_submission_tests_the_reference_semantics_not_an_external_gateway",
    "passing_does_not_establish_unrepresented_values_interactions_sequences_or_complete_mediation",
    "passing_is_not_compliance_certification_safety_legal_authority_or_deployment_authorization",
)


def _time(second: int, milliseconds: int = 0) -> str:
    instant = datetime(2026, 9, 5, 15, 0, tzinfo=timezone.utc) + timedelta(
        seconds=second, milliseconds=milliseconds
    )
    return instant.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def counterfactual_mandate_plan() -> Dict[str, Any]:
    plan = copy.deepcopy(default_mandate_plan())
    plan["campaign_id"] = "luremandate-counterfactual-v1"
    plan["agents"].append(
        {
            "agent_id": "agent-limited",
            "workload_spiffe_id": "spiffe://example.gov/workload/agent-limited",
            "allowed_policy_ids": ["standard-change"],
        }
    )
    plan["agents"].sort(key=lambda item: item["agent_id"])
    for person in plan["people"]:
        if person["person_id"] == "approver-security":
            person["roles"] = ["operator", "security-reviewer"]
    plan["people"].extend(
        {
            "person_id": f"requester-{index:02d}",
            "roles": ["mission-owner", "requester"],
        }
        for index in range(1, len(COUNTERFACTUALS) + 1)
    )
    plan["people"].sort(key=lambda item: item["person_id"])
    return validate_mandate_plan(plan)


def _intent(
    pair: int,
    variant: str,
    run_id: str,
    proposed_at: str,
    *,
    impact_units: int,
) -> Dict[str, Any]:
    return {
        "intent_id": f"cf-{pair:02d}-{variant}-intent",
        "proposed_at": proposed_at,
        "tenant_id": "agency-tenant",
        "run_id": run_id,
        "agent_id": "agent-a",
        "workload_spiffe_id": "spiffe://example.gov/workload/agent-a",
        "requester_id": f"requester-{pair:02d}",
        "policy_id": "high-impact",
        "action": "apply-change",
        "resource_id": f"cf-resource-{pair:02d}",
        "impact_units": impact_units,
        "intent_nonce": f"cf-{pair:02d}-{variant}-intent-nonce",
    }


def _approvals(
    pair: int,
    variant: str,
    intent_sha256: str,
    proposed_second: int,
) -> list[Dict[str, Any]]:
    return [
        {
            "approval_id": f"cf-{pair:02d}-{variant}-mission",
            "approver_id": "approver-mission",
            "approver_role": "mission-owner",
            "decision": "approve",
            "intent_sha256": intent_sha256,
            "issued_at": _time(proposed_second, 200),
            "expires_at": _time(proposed_second, 900),
            "nonce": f"cf-{pair:02d}-{variant}-mission-nonce",
        },
        {
            "approval_id": f"cf-{pair:02d}-{variant}-security",
            "approver_id": "approver-security",
            "approver_role": "security-reviewer",
            "decision": "approve",
            "intent_sha256": intent_sha256,
            "issued_at": _time(proposed_second, 200),
            "expires_at": _time(proposed_second, 900),
            "nonce": f"cf-{pair:02d}-{variant}-security-nonce",
        },
    ]


def _transaction(
    pair: int,
    variant: str,
    sequence: int,
    intent: Mapping[str, Any],
    approvals: list[Mapping[str, Any]],
) -> Dict[str, Any]:
    return {
        "transaction_id": f"cf-{pair:02d}-{variant}",
        "sequence": sequence,
        "intent": dict(intent),
        "intent_sha256": _sha256(_canonical(intent)),
        "approvals": [dict(item) for item in approvals],
        "decision": {
            "decision_id": f"cf-{pair:02d}-{variant}-decision",
            "decided_at": _time(sequence, 400),
            "decision": "block",
            "reason_code": "policy_unknown",
        },
        "outcome": {"state": "not_attempted", "observed_at": None, "sensor_id": None},
    }


def counterfactual_mandate_run(
    plan_value: Optional[Mapping[str, Any]] = None,
    *,
    run_id: str = "mandate-counterfactual-run-1",
    engine_id: str = "luremandate-reference",
    engine_version: str = VERSION,
    engine_artifact_sha256: Optional[str] = None,
) -> Dict[str, Any]:
    plan = validate_mandate_plan(plan_value or counterfactual_mandate_plan())
    transactions = []
    for pair, (reason, _) in enumerate(COUNTERFACTUALS, start=1):
        baseline_sequence = pair * 2 - 1
        mutant_sequence = pair * 2
        baseline_impact = 75 if reason == "cumulative_limit_exceeded" else 10
        mutant_impact = 76 if reason == "cumulative_limit_exceeded" else baseline_impact
        baseline_intent = _intent(
            pair,
            "baseline",
            run_id,
            _time(baseline_sequence, 100),
            impact_units=baseline_impact,
        )
        baseline_digest = _sha256(_canonical(baseline_intent))
        baseline_approvals = _approvals(pair, "baseline", baseline_digest, baseline_sequence)
        transactions.append(
            _transaction(
                pair,
                "baseline",
                baseline_sequence,
                baseline_intent,
                baseline_approvals,
            )
        )

        mutant_intent = _intent(
            pair,
            "mutant",
            run_id,
            _time(mutant_sequence, 100),
            impact_units=mutant_impact,
        )
        if reason == "policy_unknown":
            mutant_intent["policy_id"] = "unknown-policy"
        elif reason == "tenant_mismatch":
            mutant_intent["tenant_id"] = "other-tenant"
        elif reason == "run_binding_mismatch":
            mutant_intent["run_id"] = "other-run"
        elif reason == "agent_identity_mismatch":
            mutant_intent["workload_spiffe_id"] = "spiffe://example.gov/workload/substituted"
        elif reason == "agent_policy_denied":
            mutant_intent["agent_id"] = "agent-limited"
            mutant_intent["workload_spiffe_id"] = "spiffe://example.gov/workload/agent-limited"
        elif reason == "requester_unknown":
            mutant_intent["requester_id"] = f"unknown-requester-{pair:02d}"
        elif reason == "impact_limit_exceeded":
            mutant_intent["impact_units"] = 101
        mutant_digest = _sha256(_canonical(mutant_intent))
        mutant_approvals = _approvals(pair, "mutant", mutant_digest, mutant_sequence)
        mission = mutant_approvals[0]
        if reason == "approval_count_insufficient":
            mutant_approvals = [mission]
        elif reason == "approval_binding_mismatch":
            mission["intent_sha256"] = "f" * 64
        elif reason == "approval_denied":
            mission["decision"] = "deny"
        elif reason == "self_approval":
            mission["approver_id"] = mutant_intent["requester_id"]
        elif reason == "approver_unknown":
            mission["approver_id"] = "unknown-approver"
        elif reason == "approver_role_unauthorized":
            mission["approver_role"] = "operator"
        elif reason == "approval_predates_intent":
            mission["issued_at"] = _time(mutant_sequence, 0)
        elif reason == "approval_after_decision":
            mission["issued_at"] = _time(mutant_sequence, 500)
        elif reason == "approval_expired":
            mission["expires_at"] = _time(mutant_sequence, 300)
        elif reason == "approval_window_invalid":
            mission["expires_at"] = _time(mutant_sequence + 121)
        elif reason == "required_role_missing":
            mutant_approvals[1]["approver_role"] = "operator"
        elif reason == "approval_replay":
            mutant_approvals[0] = copy.deepcopy(baseline_approvals[0])
        transactions.append(
            _transaction(
                pair,
                "mutant",
                mutant_sequence,
                mutant_intent,
                mutant_approvals,
            )
        )
    run = {
        "schema": RUN_SCHEMA,
        "schema_version": 1,
        "run_id": run_id,
        "campaign_id": plan["campaign_id"],
        "plan_sha256": _sha256(_canonical(plan)),
        "started_at": _time(0),
        "completed_at": _time(180),
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


def _dimensions(
    transaction: Mapping[str, Any],
    plan: Mapping[str, Any],
    run_id: str,
    used_ids: set[str],
    used_nonces: set[str],
    reserved_by_requester: Mapping[str, int],
) -> Dict[str, bool]:
    intent = transaction["intent"]
    approvals = transaction["approvals"]
    mission = approvals[0]
    agents = {item["agent_id"]: item for item in plan["agents"]}
    people = {item["person_id"]: item for item in plan["people"]}
    policy = next(item for item in plan["policies"] if item["policy_id"] == "high-impact")
    agent = agents.get(intent["agent_id"])
    decision = _instant(transaction["decided_at"], "decided_at")
    proposed = _instant(intent["proposed_at"], "proposed_at")
    issued = _instant(mission["issued_at"], "mission issued_at")
    expires = _instant(mission["expires_at"], "mission expires_at")
    distinct_approvers = len({item["approver_id"] for item in approvals})
    return {
        "policy_binding": intent["policy_id"] == "high-impact",
        "tenant_binding": intent["tenant_id"] == plan["environment"]["tenant_id"],
        "run_binding": intent["run_id"] == run_id,
        "agent_identity_binding": agent is not None
        and agent["workload_spiffe_id"] == intent["workload_spiffe_id"],
        "agent_policy_assignment": agent is not None
        and "high-impact" in agent["allowed_policy_ids"],
        "requester_registry_membership": intent["requester_id"] in people,
        "impact_within_limit": intent["impact_units"] <= policy["maximum_impact_units"],
        "approval_count_sufficient": distinct_approvers >= policy["minimum_distinct_approvers"],
        "mission_approval_fresh": mission["approval_id"] not in used_ids
        and mission["nonce"] not in used_nonces,
        "mission_intent_binding": mission["intent_sha256"] == transaction["intent_sha256"],
        "mission_decision_approve": mission["decision"] == "approve",
        "requester_separation": mission["approver_id"] != intent["requester_id"],
        "mission_approver_registry_membership": mission["approver_id"] in people,
        "mission_role_assignment": mission["approver_role"] == "mission-owner",
        "mission_not_before_intent": issued >= proposed,
        "mission_not_after_decision": issued <= decision,
        "mission_unexpired_at_decision": expires >= decision and expires > issued,
        "mission_ttl_within_policy": timedelta(0)
        < expires - issued
        <= timedelta(milliseconds=policy["approval_ttl_ms"]),
        "required_security_role": any(
            item["approver_role"] == "security-reviewer" for item in approvals
        ),
        "cumulative_budget_available": reserved_by_requester.get(intent["requester_id"], 0)
        + intent["impact_units"]
        <= policy["cumulative_limit_units"],
    }


def _value(score_value: Mapping[str, Any]) -> Dict[str, Any]:
    score = validate_mandate_conformance_score(score_value)
    challenge = score["challenge"]
    if len(challenge["cases"]) != len(COUNTERFACTUALS) * 2:
        raise ValueError("counterfactual campaign must contain exactly 40 ordered cases")
    plan = challenge["plan"]
    used_ids: set[str] = set()
    used_nonces: set[str] = set()
    reserved: Dict[str, int] = {}
    dimensions = []
    for case, result in zip(challenge["cases"], score["results"], strict=True):
        transaction = case["transaction"]
        dimensions.append(
            _dimensions(
                transaction,
                plan,
                challenge["execution"]["run_id"],
                used_ids,
                used_nonces,
                reserved,
            )
        )
        for approval in transaction["approvals"]:
            used_ids.add(approval["approval_id"])
            used_nonces.add(approval["nonce"])
        if result["expected_decision"] == "allow":
            requester = transaction["intent"]["requester_id"]
            reserved[requester] = reserved.get(requester, 0) + transaction["intent"]["impact_units"]

    pairs = []
    passed_pairs = single_dimension_pairs = 0
    for index, (reason, expected_changes) in enumerate(COUNTERFACTUALS):
        baseline_index = index * 2
        mutant_index = baseline_index + 1
        baseline_result = score["results"][baseline_index]
        mutant_result = score["results"][mutant_index]
        baseline_dimensions = dimensions[baseline_index]
        mutant_dimensions = dimensions[mutant_index]
        changed = [
            name for name in DIMENSION_IDS if baseline_dimensions[name] != mutant_dimensions[name]
        ]
        baseline_valid = all(baseline_dimensions.values())
        pair_passed = (
            baseline_valid
            and baseline_result["expected_decision"] == "allow"
            and baseline_result["expected_reason_code"] == "authority_satisfied"
            and mutant_result["expected_decision"] == "block"
            and mutant_result["expected_reason_code"] == reason
            and changed == list(expected_changes)
            and baseline_result["status"] == "pass"
            and mutant_result["status"] == "pass"
        )
        passed_pairs += int(pair_passed)
        single_dimension_pairs += int(len(changed) == 1)
        pairs.append(
            {
                "pair_id": f"guard-pair-{index + 1:02d}",
                "guard_reason": reason,
                "baseline_case_id": baseline_result["case_id"],
                "mutant_case_id": mutant_result["case_id"],
                "changed_dimensions": changed,
                "expected_changed_dimensions": list(expected_changes),
                "baseline_expected_decision": baseline_result["expected_decision"],
                "mutant_expected_decision": mutant_result["expected_decision"],
                "baseline_submitted_decision": baseline_result["submitted_decision"],
                "mutant_submitted_decision": mutant_result["submitted_decision"],
                "status": "pass" if pair_passed else "fail",
            }
        )
    pair_count = len(pairs)
    score_passed = score["summary"]["verdict"] == "pass"
    return {
        "schema": SCHEMA,
        "schema_version": 1,
        "report_id": f"{score['score_id']}-counterfactual",
        "evaluated_at": score["evaluated_at"],
        "method": {
            "name": "adjacent-valid-control-guard-pairs",
            "dimension_ids": list(DIMENSION_IDS),
            "guard_reasons": [reason for reason, _ in COUNTERFACTUALS],
        },
        "score_sha256": _sha256(_canonical(score)),
        "score": score,
        "pairs": pairs,
        "summary": {
            "verdict": "pass" if score_passed and passed_pairs == pair_count else "fail",
            "score_verdict": score["summary"]["verdict"],
            "case_count": len(score["results"]),
            "guard_pair_count": pair_count,
            "passed_guard_pair_count": passed_pairs,
            "single_dimension_pair_count": single_dimension_pairs,
            "dependency_coupled_pair_count": pair_count - single_dimension_pairs,
            "guard_reason_coverage_complete": passed_pairs == pair_count,
        },
        "limitations": list(LIMITATIONS_COUNTERFACTUAL),
    }


def evaluate_counterfactual_mandate_conformance(
    score_value: Mapping[str, Any],
) -> Dict[str, Any]:
    return validate_counterfactual_mandate_conformance(_value(score_value))


def validate_counterfactual_mandate_conformance(value: Any) -> Dict[str, Any]:
    report = _exact(
        value,
        "LureMandate counterfactual assurance",
        (
            "schema",
            "schema_version",
            "report_id",
            "evaluated_at",
            "method",
            "score_sha256",
            "score",
            "pairs",
            "summary",
            "limitations",
        ),
    )
    if report["schema"] != SCHEMA or report["schema_version"] != 1:
        raise ValueError("unsupported LureMandate counterfactual assurance schema")
    _identifier(report["report_id"], "counterfactual report_id")
    if report != _value(report["score"]):
        raise ValueError("LureMandate counterfactual assurance does not independently recompute")
    return dict(report)


def write_counterfactual_mandate_template(
    directory: Path,
    *,
    run_id: str = "mandate-counterfactual-run-1",
    engine_id: str = "luremandate-reference",
    engine_version: str = VERSION,
    engine_artifact_sha256: Optional[str] = None,
) -> tuple[Path, Path]:
    destination = Path(directory)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(destination)
    if not destination.parent.is_dir() or destination.parent.is_symlink():
        raise ValueError("counterfactual template parent must be a regular directory")
    plan = counterfactual_mandate_plan()
    run = counterfactual_mandate_run(
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


def write_counterfactual_mandate_conformance(path: Path, value: Mapping[str, Any]) -> None:
    _write(Path(path), validate_counterfactual_mandate_conformance(value))


def load_counterfactual_mandate_conformance(path: Path) -> Dict[str, Any]:
    from .mandate import _load

    return validate_counterfactual_mandate_conformance(
        _load(Path(path), "LureMandate counterfactual assurance")
    )
