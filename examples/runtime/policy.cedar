// Illustrative Cedar policy for the output of to_cedar_request(). The adapter
// carries identifiers and authorization metadata only; it never sends content.
permit (
    principal is LureAgent,
    action in [LureAction::"local_tool_call", LureAction::"registry_read"],
    resource
)
when {
    principal == LureAgent::"agent-a" &&
    context.tenant_id == "tenant-a" &&
    context.run_id == "range-run-a" &&
    context.mediation_point_id == "tool-gateway"
};

forbid (
    principal,
    action,
    resource
)
unless {
    context.tenant_id == "tenant-a" &&
    context.run_id == "range-run-a"
};
