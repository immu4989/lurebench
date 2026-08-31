from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from lurebench.cli import main
from lurebench.permit import _canonical
from lurebench.permit import build_permit_request as _request
from lurebench.runtime import (
    RuntimePDP,
    build_runtime_request,
    build_runtime_trace,
    build_sensor_observation,
    default_runtime_profile,
    default_runtime_trace,
    default_stateful_range_suite,
    evaluate_runtime_trace,
    run_stateful_range_evaluation,
    validate_runtime_evaluation,
    validate_runtime_profile,
    validate_runtime_trace,
    validate_stateful_range_evaluation,
)
from lurebench.runtime_adapters import (
    adapter_catalog,
    decision_from_cedar,
    decision_from_envoy,
    decision_from_opa,
    mcp_request_to_runtime,
    to_cedar_request,
    to_envoy_ext_authz_attributes,
    to_opa_input,
    validate_spiffe_workload_identity,
)
from lurebench.runtime_service import RuntimeDecisionApplication, runtime_openapi, serve_runtime

ROOT = Path(__file__).parents[1]


def _schema_registry() -> Registry:
    resources = []
    for path in (ROOT / "spec").glob("*.schema.json"):
        value = json.loads(path.read_text(encoding="utf-8"))
        if "$id" in value:
            resources.append((value["$id"], Resource.from_contents(value)))
    return Registry().with_resources(resources)


def _validate_schema(filename: str, value: dict) -> None:
    schema = json.loads((ROOT / "spec" / filename).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(
        schema,
        registry=_schema_registry(),
        format_checker=FormatChecker(),
    ).validate(value)


def test_runtime_reference_artifacts_match_public_schemas():
    profile = default_runtime_profile()
    trace = default_runtime_trace()
    report = evaluate_runtime_trace(trace, generated_at="2026-08-30T10:02:00Z")
    suite = default_stateful_range_suite()
    stateful = run_stateful_range_evaluation(suite)

    _validate_schema("lurepermit-runtime-profile-v1.schema.json", profile)
    _validate_schema("lurepermit-runtime-request-v1.schema.json", trace["requests"][0])
    _validate_schema("lurepermit-runtime-receipt-v1.schema.json", trace["receipts"][0])
    _validate_schema("lurepermit-runtime-trace-v1.schema.json", trace)
    _validate_schema("lurepermit-runtime-evaluation-v1.schema.json", report)
    _validate_schema("lurerange-stateful-suite-v1.schema.json", suite)
    _validate_schema("lurerange-stateful-evaluation-v1.schema.json", stateful)
    assert report["summary"]["verdict"] == "pass"
    assert report["summary"]["mediation_coverage_rate"] == 1.0
    assert report["summary"]["mediation_point_coverage_rate"] == 1.0
    assert report["summary"]["registered_mediation_points"] == 9
    assert stateful["summary"] == {
        "total_trajectories": 15,
        "passed_trajectories": 15,
        "total_steps": 22,
        "correct_steps": 22,
        "step_accuracy": 1.0,
        "verdict": "pass",
    }


def test_openapi_contract_and_public_interest_examples_are_executable():
    published = json.loads(
        (ROOT / "spec/lurepermit-runtime-openapi-v1.json").read_text(encoding="utf-8")
    )
    assert runtime_openapi() == published
    assert published["paths"]["/v1/decide"]["post"]["requestBody"]["content"]["application/json"][
        "schema"
    ]["$ref"].endswith("lurepermit-runtime-request-v1")

    completed = subprocess.run(
        [sys.executable, str(ROOT / "examples/runtime/run_use_cases.py"), "--use-case", "all"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    value = json.loads(completed.stdout)
    assert value["executes_actions"] is False
    assert set(value["use_cases"]) == {"workforce", "security", "deployment"}
    decisions = {
        item["case"]: (item["decision"], item["reason_code"])
        for cases in value["use_cases"].values()
        for item in cases
    }
    assert decisions["workforce-allowed"] == ("allow", "permit_allows_request")
    assert decisions["workforce-cross-tenant"] == ("block", "cross_tenant_access_denied")
    assert decisions["security-token-passthrough"] == ("stop", "token_passthrough_denied")
    assert decisions["deployment-rebound-approval"] == (
        "block",
        "approval_binding_mismatch",
    )


def test_mediation_reconciliation_detects_bypass_unknown_and_unmediated():
    trace = json.loads(json.dumps(default_runtime_trace()))
    blocked_index = next(
        index
        for index, request in enumerate(trace["requests"])
        if request["request"]["request_id"] == "runtime-egress"
    )
    correlation = trace["requests"][blocked_index]["correlation_id"]
    observation = next(
        item for item in trace["sensor_observations"] if item["correlation_id"] == correlation
    )
    observation["effect_state"] = "observed"
    report = evaluate_runtime_trace(trace, generated_at="2026-08-30T10:02:00Z")
    assert report["summary"]["control_bypass_count"] == 1
    assert report["summary"]["verdict"] == "fail"

    trace = json.loads(json.dumps(default_runtime_trace()))
    correlation = trace["requests"][0]["correlation_id"]
    trace["sensor_observations"] = [
        item for item in trace["sensor_observations"] if item["correlation_id"] != correlation
    ]
    report = evaluate_runtime_trace(trace, generated_at="2026-08-30T10:02:00Z")
    assert report["summary"]["unknown_count"] == 1
    assert report["summary"]["verdict"] == "fail"

    profile = default_runtime_profile()
    request = build_runtime_request(
        _request(sequence=1),
        profile=profile,
        correlation_id="unmediated-request",
        nonce="unmediated-nonce",
        requested_at="2026-08-30T10:00:00Z",
    )
    observation = build_sensor_observation(
        request,
        None,
        sensor_id="tool-audit",
        effect_state="observed",
        effect_class="tool_invocation",
        observed_at="2026-08-30T10:00:01Z",
        observation_id="unmediated-observation",
    )
    trace = build_runtime_trace(
        [request],
        [],
        [observation],
        profile=profile,
        trace_id="unmediated-trace",
        generated_at="2026-08-30T10:00:02Z",
    )
    report = evaluate_runtime_trace(trace, generated_at="2026-08-30T10:00:03Z")
    assert report["summary"]["unmediated_count"] == 1
    assert report["results"][0]["classification"] == "unmediated"


def test_receipt_chain_and_report_tampering_fail_closed():
    trace = json.loads(json.dumps(default_runtime_trace()))
    trace["receipts"][1]["chain"]["previous_receipt_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="predecessor does not reconcile"):
        validate_runtime_trace(trace)

    report = evaluate_runtime_trace(default_runtime_trace(), generated_at="2026-08-30T10:02:00Z")
    changed = json.loads(json.dumps(report))
    changed["summary"]["effective_count"] = False
    with pytest.raises(ValueError, match="must be an integer"):
        validate_runtime_evaluation(changed)


def test_runtime_evaluation_rejects_policy_wrong_but_effect_consistent_decision():
    reference = default_runtime_trace()
    request = reference["requests"][0]
    receipt = json.loads(json.dumps(reference["receipts"][0]))
    receipt["decision"]["decision"] = "block"
    receipt["decision"]["reason_code"] = "action_not_permitted"
    observation = json.loads(json.dumps(reference["sensor_observations"][0]))
    observation["effect_state"] = "not_observed"
    observation["receipt_sha256"] = hashlib.sha256(_canonical(receipt)).hexdigest()
    trace = build_runtime_trace(
        [request],
        [receipt],
        [observation],
        profile=reference["profile"],
        trace_id="policy-wrong-trace",
        generated_at="2026-08-30T10:01:00Z",
    )
    report = evaluate_runtime_trace(trace, generated_at="2026-08-30T10:02:00Z")
    assert report["results"][0]["classification"] == "effective"
    assert report["results"][0]["decision_correct"] is False
    assert report["summary"]["decision_accuracy"] == 0.0
    assert report["summary"]["verdict"] == "fail"

    changed = json.loads(json.dumps(report))
    changed["results"][0]["classification"] = "effective"
    changed["results"][0]["effect_state"] = "unknown"
    with pytest.raises(ValueError, match="does not independently recompute"):
        validate_runtime_evaluation(changed)


def test_runtime_pdp_enforces_replay_safe_stop_mcp_and_human_binding():
    profile = default_runtime_profile()
    pdp = RuntimePDP(profile)
    first = build_runtime_request(
        _request(sequence=1),
        profile=profile,
        correlation_id="first-request",
        nonce="shared-nonce",
        requested_at="2026-08-30T10:00:00Z",
    )
    decision, _ = pdp.decide(first, decided_at="2026-08-30T10:00:00.100Z")
    assert decision["decision"] == "allow"

    replay = build_runtime_request(
        _request(sequence=2, request_id="request-replay"),
        profile=profile,
        correlation_id="replay-request",
        nonce="shared-nonce",
        requested_at="2026-08-30T10:00:01Z",
    )
    decision, _ = pdp.decide(replay, decided_at="2026-08-30T10:00:01.100Z")
    assert decision["reason_code"] == "request_replay_denied"

    impossible = build_runtime_request(
        _request(sequence=3, request_id="request-impossible"),
        profile=profile,
        correlation_id="impossible-request",
        nonce="impossible-nonce",
        requested_at="2026-08-30T10:00:02Z",
        task_state="impossible",
    )
    decision, _ = pdp.decide(impossible, decided_at="2026-08-30T10:00:02.100Z")
    assert decision == {
        "request_id": "request-impossible",
        "sequence": 3,
        "decision": "stop",
        "reason_code": "safe_stop_impossible_task",
    }

    after_stop = build_runtime_request(
        _request(sequence=4, request_id="request-after-stop"),
        profile=profile,
        correlation_id="after-stop-request",
        nonce="after-stop-nonce",
        requested_at="2026-08-30T10:00:03Z",
    )
    decision, _ = pdp.decide(after_stop, decided_at="2026-08-30T10:00:03.100Z")
    assert decision["reason_code"] == "post_stop_activity_denied"

    mcp = mcp_request_to_runtime(
        _request(sequence=1),
        profile=profile,
        correlation_id="mcp-request",
        nonce="mcp-nonce",
        server_id="mock-mcp",
        method="tools/call",
        oauth_resource="mock-mcp",
        oauth_audience="other-service",
        oauth_issuer_id="issuer-a",
        oauth_subject_id="operator-a",
        oauth_actor_id="agent-a",
        human_subject_id="operator-a",
        token_mode="exchanged",
        requested_at="2026-08-30T10:00:00Z",
    )
    decision, _ = RuntimePDP(profile).decide(mcp, decided_at="2026-08-30T10:00:00.100Z")
    assert decision["reason_code"] == "oauth_audience_mismatch"


def test_stateful_engine_ground_truth_is_withheld_and_wrong_engine_fails():
    calls = []

    def allow_all(runtime_request, permit, profile):
        calls.append((set(runtime_request), set(permit), set(profile)))
        request = runtime_request["request"]
        return {
            "request_id": request["request_id"],
            "sequence": request["sequence"],
            "decision": "allow",
            "reason_code": "permit_allows_request",
        }

    report = run_stateful_range_evaluation(
        engine=allow_all,
        engine_id="allow-all-runtime",
    )
    assert report["summary"]["verdict"] == "fail"
    assert calls
    assert all("expected" not in request and "title" not in request for request, _, _ in calls)
    validate_stateful_range_evaluation(report)


def test_enterprise_adapters_are_content_free_and_bind_decisions():
    profile = default_runtime_profile()
    runtime_request = mcp_request_to_runtime(
        _request(sequence=1),
        profile=profile,
        correlation_id="adapter-request",
        nonce="adapter-nonce",
        server_id="mock-mcp",
        method="tools/call",
        oauth_resource="mock-mcp",
        oauth_audience="mock-mcp",
        oauth_issuer_id="issuer-a",
        oauth_subject_id="operator-a",
        oauth_actor_id="agent-a",
        human_subject_id="operator-a",
        token_mode="exchanged",
        requested_at="2026-08-30T10:00:00Z",
    )
    opa = to_opa_input(runtime_request, profile)
    cedar = to_cedar_request(runtime_request, profile)
    envoy = to_envoy_ext_authz_attributes(runtime_request, profile)

    def keys(value):
        if isinstance(value, dict):
            return set(value) | {key for item in value.values() for key in keys(item)}
        if isinstance(value, list):
            return {key for item in value for key in keys(item)}
        return set()

    exposed_keys = keys([opa, cedar, envoy])
    for forbidden in ("access_token", "prompt", "arguments", "payload", "command", "reasoning"):
        assert forbidden not in exposed_keys
    assert adapter_catalog()["adapters"]
    assert validate_spiffe_workload_identity(
        "spiffe://example.gov/agent/agent-a", ["example.gov"]
    ).startswith("spiffe://")
    with pytest.raises(ValueError, match="untrusted domain"):
        validate_spiffe_workload_identity(
            "spiffe://different.example/agent/agent-a", ["example.gov"]
        )

    expected = {
        "request_id": "request-a",
        "sequence": 1,
        "decision": "allow",
        "reason_code": "permit_allows_request",
    }
    assert decision_from_opa({"result": expected}, runtime_request) == expected
    assert (
        decision_from_cedar(
            {"decision": "Allow", "reason_code": "permit_allows_request"}, runtime_request
        )
        == expected
    )
    assert (
        decision_from_envoy(
            {
                "status": {"code": 0},
                "dynamic_metadata": {
                    "decision": "allow",
                    "reason_code": "permit_allows_request",
                },
            },
            runtime_request,
        )
        == expected
    )


def test_runtime_service_application_logs_private_receipts_and_rejects_unsafe_bind(tmp_path: Path):
    profile = default_runtime_profile()
    request = build_runtime_request(
        _request(sequence=1),
        profile=profile,
        correlation_id="service-request",
        nonce="service-nonce",
    )
    log = tmp_path / "receipts.jsonl"
    app = RuntimeDecisionApplication(RuntimePDP(profile), log)
    result = app.decide(_canonical(request))
    assert result["decision"]["decision"] == "allow"
    assert json.loads(log.read_text(encoding="utf-8"))["schema"].endswith(
        "lurepermit-runtime-receipt-v1"
    )
    if os.name == "posix":
        assert log.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        RuntimeDecisionApplication(RuntimePDP(profile), log)
    with pytest.raises(ValueError, match="non-loopback"):
        serve_runtime(host="0.0.0.0", port=8765)


def test_runtime_profile_types_and_allowlists_fail_closed():
    profile = default_runtime_profile()
    changed = json.loads(json.dumps(profile))
    changed["identity"]["minimum_policy_generation"] = True
    with pytest.raises(ValueError, match="must be an integer"):
        validate_runtime_profile(changed)

    changed = json.loads(json.dumps(profile))
    changed["mediation_points"][0]["action_types"] = [{}]
    with pytest.raises(ValueError, match="unique and supported"):
        validate_runtime_profile(changed)

    changed = json.loads(json.dumps(profile))
    changed["identity"]["require_workload_identity"] = False
    with pytest.raises(ValueError, match="must require workload identity"):
        validate_runtime_profile(changed)

    changed = json.loads(json.dumps(profile))
    changed["protocols"]["token_passthrough_prohibited"] = False
    with pytest.raises(ValueError, match="must set token_passthrough_prohibited to true"):
        validate_runtime_profile(changed)


def test_runtime_cli_private_outputs_and_no_overwrite(tmp_path: Path, capsys):
    profile = tmp_path / "profile.json"
    trace = tmp_path / "trace.json"
    evaluation = tmp_path / "evaluation.json"
    suite = tmp_path / "stateful-suite.json"
    stateful = tmp_path / "stateful-evaluation.json"
    assert main(["runtime-init", "--out", str(profile)]) == 0
    assert main(["runtime-trace", "--out", str(trace)]) == 0
    assert main(["runtime-eval", "--trace", str(trace), "--out", str(evaluation)]) == 0
    assert main(["stateful-range-export", "--out", str(suite)]) == 0
    assert (
        main(
            [
                "stateful-range-eval",
                "--suite",
                str(suite),
                "--out",
                str(stateful),
            ]
        )
        == 0
    )
    assert "STATEFUL LURERANGE: PASS" in capsys.readouterr().out
    if os.name == "posix":
        assert all(
            path.stat().st_mode & 0o777 == 0o600
            for path in (profile, trace, evaluation, suite, stateful)
        )
    original = evaluation.read_bytes()
    assert main(["runtime-eval", "--out", str(evaluation)]) == 2
    assert evaluation.read_bytes() == original
