package lurepermit.runtime

import rego.v1

default decision := {
  "request_id": input.runtime_request.request.request_id,
  "sequence": input.runtime_request.request.sequence,
  "decision": "block",
  "reason_code": "action_not_permitted",
}

decision := {
  "request_id": input.runtime_request.request.request_id,
  "sequence": input.runtime_request.request.sequence,
  "decision": "stop",
  "reason_code": "token_passthrough_denied",
} if {
  input.runtime_request.protocol.token_passthrough == true
}

decision := {
  "request_id": input.runtime_request.request.request_id,
  "sequence": input.runtime_request.request.sequence,
  "decision": "allow",
  "reason_code": "permit_allows_request",
} if {
  input.runtime_request.protocol.token_passthrough == false
  input.runtime_request.state.permit_state == "active"
  input.runtime_request.state.task_state == "healthy"
  input.runtime_request.request.actor_id == input.permit.subject.agent_id
  input.runtime_request.request.tenant_id == input.permit.subject.tenant_id
  input.runtime_request.request.run_id == input.permit.run_id
  input.runtime_request.request.action_type in input.permit.authorization.allowed_action_types
  input.runtime_request.request.resource_id in input.permit.authorization.allowed_resource_ids
  input.runtime_request.request.capability in input.permit.authorization.allowed_capabilities
}
