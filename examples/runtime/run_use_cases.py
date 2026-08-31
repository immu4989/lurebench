#!/usr/bin/env python3
"""Run three deterministic metadata-only LurePermit demonstrations."""

from __future__ import annotations

import argparse
import json

from lurebench.permit import build_permit_request
from lurebench.runtime import RuntimePDP, build_runtime_request, default_runtime_profile


def _decide(name: str, request: dict, **runtime_fields) -> dict:
    profile = default_runtime_profile()
    envelope = build_runtime_request(
        request,
        profile=profile,
        correlation_id=f"{name}-correlation",
        nonce=f"{name}-nonce",
        requested_at="2026-08-30T10:00:00Z",
        **runtime_fields,
    )
    decision, receipt = RuntimePDP(profile).decide(envelope, decided_at="2026-08-30T10:00:01Z")
    return {
        "case": name,
        "decision": decision["decision"],
        "reason_code": decision["reason_code"],
        "mediation_point_id": envelope["mediation_point_id"],
        "runtime_request_sha256": receipt["runtime_request_sha256"],
        "executes_actions": False,
    }


def workforce() -> list[dict]:
    allowed = build_permit_request(request_id="workforce-local")
    denied = build_permit_request(request_id="workforce-cross-tenant", tenant_id="tenant-b")
    return [
        _decide("workforce-allowed", allowed),
        _decide("workforce-cross-tenant", denied),
    ]


def security() -> list[dict]:
    escalation = build_permit_request(
        request_id="security-escalation",
        action_type="incident_escalation",
        resource_id="incident_channel",
        resource_class="control",
        capability="escalate",
    )
    mcp = build_permit_request(request_id="security-mcp")
    return [
        _decide("security-escalation", escalation),
        _decide(
            "security-token-passthrough",
            mcp,
            protocol_kind="mcp",
            server_id="mock-mcp",
            method="tools/call",
            oauth_resource="mock-mcp",
            oauth_audience="mock-mcp",
            oauth_issuer_id="issuer-a",
            oauth_subject_id="operator-a",
            oauth_actor_id="agent-a",
            human_subject_id="operator-a",
            token_mode="exchanged",
            token_passthrough=True,
        ),
    ]


def deployment() -> list[dict]:
    change = build_permit_request(
        request_id="deployment-change",
        action_type="high_impact_change",
        resource_id="boundary_controller",
        resource_class="control",
        capability="modify",
        approval_state="present",
    )
    return [
        _decide(
            "deployment-approved",
            change,
            human_subject_id="operator-a",
            approval_id="change-approval",
            approval_request_sha256="auto",
        ),
        _decide(
            "deployment-rebound-approval",
            change,
            human_subject_id="operator-a",
            approval_id="change-approval",
            approval_request_sha256="0" * 64,
        ),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--use-case",
        choices=("all", "workforce", "security", "deployment"),
        default="all",
    )
    args = parser.parse_args()
    runners = {"workforce": workforce, "security": security, "deployment": deployment}
    selected = runners if args.use_case == "all" else {args.use_case: runners[args.use_case]}
    result = {
        "schema": "https://github.com/immu4989/lurebench/examples/runtime-use-cases-v1",
        "metadata_only": True,
        "executes_actions": False,
        "use_cases": {name: runner() for name, runner in selected.items()},
        "limitations": [
            "synthetic_decisions_do_not_prove_deployment_enforcement",
            "declared_identity_metadata_requires_external_cryptographic_authentication",
            "no_tool_network_credential_process_or_remediation_action_is_executed",
        ],
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
