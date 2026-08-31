# LurePermit runtime deployment patterns

These examples show where a metadata-only LurePermit policy decision point can
sit in an agent system. They are safe templates: none of them invokes a tool,
contacts an MCP server, forwards a token, executes a command, or applies a
remediation.

Start with the three synthetic public-interest use cases:

```bash
python examples/runtime/run_use_cases.py --use-case all
```

The output demonstrates six decisions across three patterns drawn from the NIST
AI Agent Identity and Authorization concept paper:

| Use case | Allowed path | Denied path |
|---|---|---|
| Workforce assistant | Same-run workspace operation | Cross-tenant operation |
| Security operations agent | Incident escalation | OAuth token passthrough |
| Software deployment agent | Human-bound approved change | Rebound approval digest |

Run the local decision service in a container:

```bash
docker compose -f examples/runtime/docker-compose.yml up --build
```

The Compose service has no network and listens on a shared Unix socket;
`permit-serve` also supports explicit loopback IPs for same-host integrations.
`kubernetes-sidecar.yaml` demonstrates a shared-network sidecar with a read-only
root filesystem and a mode-0600 receipt log. Replace image placeholders with a
digest-pinned image built and signed by your organization.

`policy.rego` and `policy.cedar` are translation examples for OPA and Cedar.
`envoy-ext-authz.yaml` is deliberately marked as a bridge pattern: Envoy's native
ext_authz wire contract is not the LurePermit `/v1/decide` contract. A reviewed
bridge must translate only allowlisted metadata with
`to_envoy_ext_authz_attributes`; do not point Envoy directly at `permit-serve`.

Production responsibilities remain outside LureBench: authenticate SPIFFE
identities, validate OAuth/OIDC signatures and issuer metadata, exchange tokens
for the exact resource, authorize access to the local socket, assess sensor
coverage, protect and retain receipt logs, and independently test enforcement.

To project an already authenticated OpenID CAEP event into a privacy-minimized
LureRevoke event, run:

```bash
python examples/runtime/project_verified_caep.py
```

The example is offline and synthetic. The adapter accepts decoded claims only
after external signature, issuer, audience, time, replay, and delivery checks;
it never accepts or verifies a compact SET/JWT. See
[`docs/LUREREVOKE.md`](../../docs/LUREREVOKE.md#projecting-externally-verified-caep-claims-safely).

The checked-in output is embedded in `revocation-campaign.json`. Compose its
two-node preregistered plan with:

```bash
lurebench revocation-compose \
  --campaign examples/runtime/revocation-campaign.json \
  --out revocation-plan.json
```
