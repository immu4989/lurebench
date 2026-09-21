"""Seeded traces checked against a small integer-time budget/replay model.

The oracle deliberately uses neither production decision functions nor datetime
window arithmetic. This bounded property test is not exhaustive verification.
"""

import copy
import hashlib
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from lurebench.mandate import evaluate_mandate
from lurebench.permit import _canonical

ROOT = Path(__file__).parents[1] / "conformance/luremandate-v1"


def digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def trace(seed, tenant_scope, scale):
    rng = random.Random(seed)
    plan = json.loads((ROOT / "plan.json").read_bytes())
    run = json.loads((ROOT / "run.json").read_bytes())
    template = run["transactions"][0]
    base = datetime(2026, 9, 5, 15, tzinfo=timezone.utc) + timedelta(days=seed)

    def stamp(microseconds):
        return (base + timedelta(microseconds=microseconds)).isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z")

    maximum = rng.randint(10, 100)
    limit = maximum * rng.randint(1, 3)
    window_us = rng.randint(1, 2000) * 1000
    for policy in plan["policies"]:
        policy.update(
            maximum_impact_units=maximum * scale,
            cumulative_limit_units=limit * scale,
            cumulative_window_ms=window_us // 1000,
            cumulative_scope="tenant_policy" if tenant_scope else "requester_policy",
            minimum_distinct_approvers=1,
            required_approver_roles=["operator"],
        )
    for person in ("model-requester-a", "model-requester-b"):
        plan["people"].append({"person_id": person, "roles": ["requester"]})
    plan["people"].sort(key=lambda item: item["person_id"])
    plan["created_at"] = stamp(-1_000_000)
    run["plan_sha256"] = digest(plan)
    run["started_at"] = stamp(0)
    reservations = []
    used_ids, used_nonces = set(), set()
    approvals_seen, transactions, expected = [], [], []
    now = 0
    for index in range(64):
        now += rng.choice([1, window_us - 1, window_us, window_us + 1, 1000])
        requester = rng.choice(["model-requester-a", "model-requester-b"])
        policy_id = rng.choice(["high-impact", "standard-change"])
        subject = "tenant" if tenant_scope else requester
        key = (subject, policy_id)
        # Keep the full history and recompute an inclusive integer-time interval.
        used = sum(
            amount for time, scope, amount in reservations
            if scope == key and now - window_us <= time <= now
        )
        remaining = limit - used
        impact = rng.choice([1, maximum, maximum + 1, max(1, remaining), remaining + 1])
        identifier = f"model-{index + 1:04d}"
        transaction = copy.deepcopy(template)
        transaction["transaction_id"] = identifier
        transaction["sequence"] = index + 1
        transaction["intent"].update(
            intent_id=f"{identifier}-intent",
            intent_nonce=f"{identifier}-nonce",
            proposed_at=stamp(now),
            requester_id=requester,
            policy_id=policy_id,
            impact_units=impact * scale,
        )
        transaction["intent_sha256"] = digest(transaction["intent"])
        approval = copy.deepcopy(template["approvals"][0])
        approval.update(
            approval_id=f"{identifier}-approval",
            nonce=f"{identifier}-approval-nonce",
            intent_sha256=transaction["intent_sha256"],
            issued_at=stamp(now),
            expires_at=stamp(now + 1000),
            decision="approve",
        )
        variation = rng.randrange(8)
        if approvals_seen and variation == 0:
            approval = copy.deepcopy(rng.choice(approvals_seen))
        elif approvals_seen and variation == 1:
            approval["nonce"] = rng.choice(approvals_seen)["nonce"]
        elif variation == 2:
            approval["decision"] = "deny"
        if impact > maximum:
            reason = "impact_limit_exceeded"
        elif approval["approval_id"] in used_ids or approval["nonce"] in used_nonces:
            reason = "approval_replay"
        elif approval["decision"] == "deny":
            reason = "approval_denied"
        elif used + impact > limit:
            reason = "cumulative_limit_exceeded"
        else:
            reason = "authority_satisfied"
            reservations.append((now, key, impact))
        used_ids.add(approval["approval_id"])
        used_nonces.add(approval["nonce"])
        approvals_seen.append(copy.deepcopy(approval))
        transaction["approvals"] = [approval]
        transaction["decision"].update(
            decision_id=f"{identifier}-decision",
            decided_at=stamp(now),
            decision="allow" if reason == "authority_satisfied" else "block",
            reason_code=reason,
        )
        transaction["outcome"] = {
            "state": "not_attempted", "observed_at": None, "sensor_id": None
        }
        transactions.append(transaction)
        expected.append(reason)
    run["transactions"] = transactions
    run["completed_at"] = stamp(now + 1_000_000)
    return plan, run, expected


@pytest.mark.parametrize("seed", range(20))
@pytest.mark.parametrize("tenant_scope", [False, True])
@pytest.mark.parametrize("scale", [1, 7])
def test_seeded_state_traces_match_integer_time_model(seed, tenant_scope, scale):
    plan, run, expected = trace(seed, tenant_scope, scale)
    result = evaluate_mandate(plan, run, evaluated_at=run["completed_at"])
    assert [item["expected_reason_code"] for item in result["results"]] == expected
    assert result["summary"]["verdict"] == "pass"


def test_integer_scaling_preserves_reference_decisions():
    for seed in range(20):
        for tenant_scope in (False, True):
            assert trace(seed, tenant_scope, 1)[2] == trace(seed, tenant_scope, 7)[2]
