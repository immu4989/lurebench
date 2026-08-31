"""Content-free enterprise protocol adapters for LurePermit runtime requests.

Adapters translate identity and authorization metadata.  They deliberately do
not accept MCP arguments, HTTP bodies, prompts, access tokens, credentials, or
tool output, and they never invoke the downstream protocol or policy engine.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional

from .permit import _canonical, _exact, _identifier, _integer, _sha256
from .runtime import (
    _RUNTIME_REASONS,
    _spiffe_id,
    build_runtime_request,
    default_runtime_profile,
    validate_runtime_profile,
    validate_runtime_request,
)


def validate_spiffe_workload_identity(value: str, allowed_trust_domains: list[str]) -> str:
    """Validate a canonical SPIFFE ID without contacting a Workload API."""

    spiffe_id, trust_domain = _spiffe_id(value, "SPIFFE workload identity")
    if trust_domain not in allowed_trust_domains:
        raise ValueError("SPIFFE workload identity uses an untrusted domain")
    return spiffe_id


def mcp_request_to_runtime(
    request: Mapping[str, Any],
    *,
    correlation_id: str,
    nonce: str,
    server_id: str,
    method: str,
    requested_at: Optional[str] = None,
    profile: Optional[Mapping[str, Any]] = None,
    workload_spiffe_id: str = "spiffe://example.gov/agent/agent-a",
    human_subject_id: Optional[str] = None,
    oauth_issuer_id: Optional[str] = None,
    oauth_subject_id: Optional[str] = None,
    oauth_actor_id: Optional[str] = None,
    oauth_resource: Optional[str] = None,
    oauth_audience: Optional[str] = None,
    token_mode: str = "none",
    token_passthrough: bool = False,
) -> Dict[str, Any]:
    """Map an MCP method declaration to a runtime request without arguments."""

    runtime_profile = validate_runtime_profile(profile or default_runtime_profile())
    return build_runtime_request(
        request,
        profile=runtime_profile,
        correlation_id=correlation_id,
        nonce=nonce,
        requested_at=requested_at,
        workload_spiffe_id=workload_spiffe_id,
        human_subject_id=human_subject_id,
        protocol_kind="mcp",
        server_id=server_id,
        method=method,
        oauth_resource=oauth_resource,
        oauth_audience=oauth_audience,
        oauth_issuer_id=oauth_issuer_id,
        oauth_subject_id=oauth_subject_id,
        oauth_actor_id=oauth_actor_id,
        token_mode=token_mode,
        token_passthrough=token_passthrough,
    )


def to_opa_input(runtime_request: Mapping[str, Any], profile: Mapping[str, Any]) -> Dict[str, Any]:
    """Return a bounded OPA input document; this function does not call OPA."""

    runtime_profile = validate_runtime_profile(profile)
    request = validate_runtime_request(runtime_request, runtime_profile)
    return {
        "input": {
            "schema": "https://github.com/immu4989/lurebench/adapters/opa-input-v1",
            "runtime_request": request,
            "profile_sha256": _sha256(_canonical(runtime_profile)),
            "permit": runtime_profile["permit"],
        }
    }


def decision_from_opa(value: Any, request: Mapping[str, Any]) -> Dict[str, Any]:
    response = _exact(value, "OPA response", ("result",))
    result = _exact(
        response["result"],
        "OPA response.result",
        ("request_id", "sequence", "decision", "reason_code"),
    )
    return _adapter_decision(result, request, "OPA response.result")


def to_cedar_request(
    runtime_request: Mapping[str, Any], profile: Mapping[str, Any]
) -> Dict[str, Any]:
    """Map metadata to a Cedar authorization request without evaluating it."""

    runtime_profile = validate_runtime_profile(profile)
    envelope = validate_runtime_request(runtime_request, runtime_profile)
    request = envelope["request"]
    return {
        "principal": {"type": "LureAgent", "id": envelope["identity"]["agent_id"]},
        "action": {"type": "LureAction", "id": request["action_type"]},
        "resource": {"type": "LureResource", "id": request["resource_id"]},
        "context": {
            "correlation_id": envelope["correlation_id"],
            "permit_sha256": envelope["permit_sha256"],
            "tenant_id": request["tenant_id"],
            "run_id": request["run_id"],
            "capability": request["capability"],
            "mediation_point_id": envelope["mediation_point_id"],
            "human_subject_id": envelope["identity"]["human_subject_id"],
        },
    }


def decision_from_cedar(value: Any, request: Mapping[str, Any]) -> Dict[str, Any]:
    response = _exact(value, "Cedar response", ("decision", "reason_code"))
    if not isinstance(response["decision"], str) or response["decision"] not in {
        "Allow",
        "Deny",
    }:
        raise ValueError("Cedar response decision is unsupported")
    return _adapter_decision(
        {
            "request_id": request["request"]["request_id"],
            "sequence": request["request"]["sequence"],
            "decision": "allow" if response["decision"] == "Allow" else "block",
            "reason_code": response["reason_code"],
        },
        request,
        "Cedar response",
    )


def to_envoy_ext_authz_attributes(
    runtime_request: Mapping[str, Any], profile: Mapping[str, Any]
) -> Dict[str, Any]:
    """Return content-free Envoy ext_authz-style attributes."""

    runtime_profile = validate_runtime_profile(profile)
    envelope = validate_runtime_request(runtime_request, runtime_profile)
    action = envelope["request"]
    return {
        "attributes": {
            "source": {"principal": envelope["identity"]["workload_spiffe_id"]},
            "destination": {"service": envelope["mediation_point_id"]},
            "request": {"id": envelope["correlation_id"]},
            "metadata_context": {
                "filter_metadata": {
                    "lurepermit": {
                        "runtime_request_sha256": _sha256(_canonical(envelope)),
                        "permit_sha256": envelope["permit_sha256"],
                        "agent_id": action["actor_id"],
                        "tenant_id": action["tenant_id"],
                        "run_id": action["run_id"],
                        "action_type": action["action_type"],
                        "resource_id": action["resource_id"],
                        "capability": action["capability"],
                    }
                }
            },
        }
    }


def decision_from_envoy(value: Any, request: Mapping[str, Any]) -> Dict[str, Any]:
    response = _exact(value, "Envoy response", ("status", "dynamic_metadata"))
    status = _exact(response["status"], "Envoy response.status", ("code",))
    _integer(status["code"], "Envoy response.status.code", 0, 16)
    metadata = _exact(
        response["dynamic_metadata"],
        "Envoy response.dynamic_metadata",
        ("decision", "reason_code"),
    )
    if status["code"] not in {0, 7}:
        raise ValueError("Envoy response status must be OK or PERMISSION_DENIED")
    expected_decision = "allow" if status["code"] == 0 else "block"
    if not isinstance(metadata["decision"], str) or metadata["decision"] != expected_decision:
        raise ValueError("Envoy response status and decision disagree")
    return _adapter_decision(
        {
            "request_id": request["request"]["request_id"],
            "sequence": request["request"]["sequence"],
            "decision": metadata["decision"],
            "reason_code": metadata["reason_code"],
        },
        request,
        "Envoy response",
    )


def _adapter_decision(
    value: Mapping[str, Any], request: Mapping[str, Any], field_name: str
) -> Dict[str, Any]:
    decision = _exact(value, field_name, ("request_id", "sequence", "decision", "reason_code"))
    action = request["request"]
    _identifier(decision["request_id"], f"{field_name}.request_id")
    _integer(decision["sequence"], f"{field_name}.sequence", 1, 128)
    if decision["request_id"] != action["request_id"] or decision["sequence"] != action["sequence"]:
        raise ValueError(f"{field_name} does not bind the runtime request")
    if not isinstance(decision["decision"], str) or decision["decision"] not in {
        "allow",
        "block",
        "stop",
    }:
        raise ValueError(f"{field_name} decision is unsupported")
    if (
        not isinstance(decision["reason_code"], str)
        or decision["reason_code"] not in _RUNTIME_REASONS
    ):
        raise ValueError(f"{field_name} reason code is unsupported")
    return dict(decision)


def adapter_catalog() -> Dict[str, Any]:
    """Describe implemented adapters and their intentionally narrow boundary."""

    return {
        "schema": "https://github.com/immu4989/lurebench/adapters/catalog-v1",
        "adapters": [
            {"adapter": "mcp", "direction": "request", "network_calls": False},
            {"adapter": "oauth-oidc", "direction": "metadata", "token_values": False},
            {"adapter": "spiffe", "direction": "identity", "authentication": False},
            {"adapter": "opa", "direction": "request-response", "network_calls": False},
            {"adapter": "cedar", "direction": "request-response", "network_calls": False},
            {
                "adapter": "envoy-ext-authz",
                "direction": "request-response",
                "network_calls": False,
            },
        ],
        "limitations": [
            "adapters_translate_typed_metadata_and_do_not_invoke_external_services",
            "spiffe_and_oauth_identity_declarations_require_external_cryptographic_validation",
            "no_adapter_accepts_access_tokens_prompts_arguments_payloads_commands_or_reasoning",
        ],
    }
