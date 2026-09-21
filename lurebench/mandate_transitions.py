"""Deterministic shared-state transition challenges using the v1 conformance format.

Each scenario has its own requester pair, but transactions inside a scenario
share state. Expected answers belong in tests and are not exported in challenges.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional

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
from .permit import _canonical


@dataclass(frozen=True)
class Step:
    milliseconds: int
    impact: int
    subject: str = "a"
    policy: str = "high-impact"
    deny: bool = False
    replay: Optional[int] = None


SCENARIOS = (
    (
        "budget-denial-does-not-reserve",
        (
            Step(0, 100),
            Step(1000, 51),
            Step(2000, 50),
            Step(3000, 1),
        ),
    ),
    (
        "approval-denial-does-not-reserve",
        (
            Step(0, 100, deny=True),
            Step(1000, 100),
            Step(2000, 50),
            Step(3000, 1),
        ),
    ),
    (
        "denied-approval-is-consumed",
        (
            Step(0, 10, deny=True),
            Step(1000, 10, replay=0),
            Step(2000, 100),
        ),
    ),
    (
        "requester-budget-isolation",
        (
            Step(0, 100),
            Step(1000, 100, subject="b"),
            Step(2000, 50),
            Step(3000, 1),
            Step(4000, 50, subject="b"),
        ),
    ),
    (
        "policy-budget-isolation",
        (
            Step(0, 100),
            Step(1000, 50),
            Step(2000, 25, policy="standard-change"),
            Step(3000, 25, policy="standard-change"),
            Step(4000, 1),
            Step(5000, 1, policy="standard-change"),
        ),
    ),
    (
        "inclusive-window-edge",
        (
            Step(0, 100),
            Step(3_600_000, 51),
            Step(3_600_001, 100),
            Step(3_600_002, 51),
        ),
    ),
    (
        "partial-window-retirement",
        (
            Step(0, 100),
            Step(1000, 50),
            Step(3_600_001, 100),
            Step(3_600_002, 1),
            Step(3_601_001, 50),
        ),
    ),
    (
        "replay-survives-budget-expiry",
        (
            Step(0, 10),
            Step(3_600_001, 10, replay=0),
            Step(3_600_002, 100),
        ),
    ),
    (
        "tenant-budget-shared-across-requesters",
        (
            Step(0, 100, policy="tenant-impact"),
            Step(1000, 51, subject="b", policy="tenant-impact"),
            Step(2000, 50, subject="b", policy="tenant-impact"),
            Step(3000, 1, policy="tenant-impact"),
        ),
    ),
    (
        "replay-crosses-policy-scope",
        (
            Step(0, 10),
            Step(1000, 10, policy="standard-change", replay=0),
            Step(2000, 100),
        ),
    ),
)


def _time(milliseconds: int) -> str:
    instant = datetime(2026, 9, 5, 15, tzinfo=timezone.utc) + timedelta(milliseconds=milliseconds)
    return instant.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def transition_mandate_plan() -> Dict[str, Any]:
    plan = copy.deepcopy(default_mandate_plan())
    plan["campaign_id"] = "luremandate-transitions-v1"
    policy = copy.deepcopy(plan["policies"][0])
    policy["policy_id"] = "tenant-impact"
    policy["transaction_class"] = "tenant-impact-change"
    policy["cumulative_scope"] = "tenant_policy"
    plan["policies"].append(policy)
    plan["agents"][0]["allowed_policy_ids"].append("tenant-impact")
    plan["people"].extend(
        {"person_id": f"transition-{index:02d}-{subject}", "roles": ["requester"]}
        for index in range(1, len(SCENARIOS) + 1)
        for subject in ("a", "b")
    )
    plan["people"].sort(key=lambda item: item["person_id"])
    return validate_mandate_plan(plan)


def transition_mandate_run(
    *,
    run_id: str = "mandate-transitions-run-1",
    engine_id: str = "luremandate-reference",
    engine_version: str = "1.0.0",
    engine_artifact_sha256: Optional[str] = None,
) -> Dict[str, Any]:
    plan = transition_mandate_plan()
    transactions = []
    for scenario_index, (_, steps) in enumerate(SCENARIOS, start=1):
        previous = []
        for step in steps:
            sequence = len(transactions) + 1
            identifier = f"transition-{sequence:04d}"
            moment = (scenario_index - 1) * 4_000_000 + step.milliseconds + 1000
            intent = {
                "intent_id": f"{identifier}-intent",
                "proposed_at": _time(moment),
                "tenant_id": "agency-tenant",
                "run_id": run_id,
                "agent_id": "agent-a",
                "workload_spiffe_id": "spiffe://example.gov/workload/agent-a",
                "requester_id": f"transition-{scenario_index:02d}-{step.subject}",
                "policy_id": step.policy,
                "action": "apply-change",
                "resource_id": f"resource-{scenario_index:02d}",
                "impact_units": step.impact,
                "intent_nonce": f"{identifier}-intent-nonce",
            }
            digest = _sha256(_canonical(intent))
            approvals = [
                {
                    "approval_id": f"{identifier}-{role}",
                    "approver_id": f"approver-{role}",
                    "approver_role": {
                        "mission": "mission-owner",
                        "security": "security-reviewer",
                        "operator": "operator",
                    }[role],
                    "decision": "deny" if step.deny and role == "mission" else "approve",
                    "intent_sha256": digest,
                    "issued_at": _time(moment),
                    "expires_at": _time(moment + 60_000),
                    "nonce": f"{identifier}-{role}-nonce",
                }
                for role in (
                    ("operator",) if step.policy == "standard-change" else ("mission", "security")
                )
            ]
            if step.replay is not None:
                approvals[0] = copy.deepcopy(previous[step.replay]["approvals"][0])
                approvals.sort(key=lambda item: item["approval_id"])
            transaction = {
                "transaction_id": identifier,
                "sequence": sequence,
                "intent": intent,
                "intent_sha256": digest,
                "approvals": approvals,
                "decision": {
                    "decision_id": f"{identifier}-decision",
                    "decided_at": _time(moment),
                    "decision": "block",
                    "reason_code": "policy_unknown",
                },
                "outcome": {"state": "not_attempted", "observed_at": None, "sensor_id": None},
            }
            previous.append(transaction)
            transactions.append(transaction)
    return validate_mandate_run(
        {
            "schema": RUN_SCHEMA,
            "schema_version": 1,
            "run_id": run_id,
            "campaign_id": plan["campaign_id"],
            "plan_sha256": _sha256(_canonical(plan)),
            "started_at": _time(0),
            "completed_at": _time(len(SCENARIOS) * 4_000_000),
            "engine": {
                "engine_id": engine_id,
                "engine_version": engine_version,
                "engine_artifact_sha256": engine_artifact_sha256,
            },
            "transactions": transactions,
            "privacy": dict(PRIVACY),
            "limitations": list(LIMITATIONS),
        },
        plan,
    )


def write_transition_mandate_template(directory: Path, **kwargs: Any) -> tuple[Path, Path]:
    destination = Path(directory)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(destination)
    if not destination.parent.is_dir() or destination.parent.is_symlink():
        raise ValueError("transition template parent must be a regular directory")
    plan = transition_mandate_plan()
    run = transition_mandate_run(**kwargs)
    destination.mkdir(mode=0o700)
    plan_path, run_path = destination / "plan.json", destination / "run.json"
    try:
        _write(plan_path, plan)
        _write(run_path, run)
    except Exception:
        plan_path.unlink(missing_ok=True)
        run_path.unlink(missing_ok=True)
        destination.rmdir()
        raise
    return plan_path, run_path
