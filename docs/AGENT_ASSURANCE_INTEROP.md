# Agent assurance interoperability: OCI, coverage, delegation, and LureIR

This milestone extends LureBoundary from a Python reference monitor into four
independent, machine-readable evaluation surfaces. Each surface is safe by
construction: it carries synthetic metadata and fixed codes, never live
credentials, commands, exploit payloads, hosts, URLs, prompts, or model
reasoning.

It remains measurement infrastructure. It does not execute an agent action,
enforce a policy, certify a product, establish complete mediation, or authorize
a deployment.

## 1. Language-independent OCI monitors

Build the reference monitor locally, then identify its immutable runtime digest:

```bash
docker build -t lureboundary-monitor:local examples/boundary-monitor
docker image inspect lureboundary-monitor:local --format '{{.Id}}'
```

For reportable evaluations, tag or address the same local image using an
immutable `name@sha256:<digest>` reference:

```bash
lurebench boundary-eval \
  --image registry.example/lureboundary-monitor@sha256:<digest> \
  --monitor-id vendor-monitor \
  --monitor-version 1.0.0 \
  --out boundary-evaluation.json \
  --container-report boundary-container-evidence.json
```

LureBench never pulls an image. It starts the locally available image with:

- no network;
- no host mounts or environment-variable injection;
- read-only root filesystem;
- all Linux capabilities dropped;
- `no-new-privileges`;
- a forced numeric unprivileged UID/GID independent of image metadata;
- bounded processes, CPU, memory, response size, and response time; and
- an isolated, `noexec` temporary filesystem.

One strict JSON request is written per trajectory:

```json
{
  "protocol": "lureboundary-monitor-v1",
  "request_id": "request-00000001",
  "policy": {},
  "events": []
}
```

The response must be one bounded, newline-terminated record containing exactly
`protocol`, `request_id`, and `alerts`.
Duplicate JSON keys, extra prose, non-finite numbers, mismatched requests,
invalid event bindings, unsupported categories, and oversized or delayed output
fail closed. Scenario IDs, titles, descriptions, labels, expected categories,
detection windows, and acceptance thresholds never cross the container boundary.

The container report records the runtime image ID and evaluator-controlled
isolation settings. Image identity alone does not authenticate a vendor; pair it
with independently verified build provenance when organizational identity
matters.

## 2. LureCoverage: test whether the monitor can see the boundary

A high-recall monitor result is incomplete evidence if relevant actions never
reach its sensors. A LureCoverage manifest preregisters each required route:

```text
action × resource class × enforcement point × expected sensor × delay limit
```

Start with the reviewed example and replace its synthetic component identifiers
with identifiers from your controlled test environment:

```bash
lurebench coverage-canaries \
  --manifest examples/lurecoverage/manifest.json \
  --replicates 3 \
  --out coverage-canaries.json
```

Canaries are descriptors with `executes_action: false`. The operator-controlled
harness is responsible for translating a descriptor into a harmless test signal
and collecting acknowledgements. Acknowledgements contain only probe ID, sensor
ID, sensor order, copy count, lineage continuity, and delivery delay.

```bash
lurebench coverage-eval \
  --manifest examples/lurecoverage/manifest.json \
  --canaries coverage-canaries.json \
  --observations sensor-observations.json \
  --out coverage-evaluation.json
```

The evaluator reports:

- required-route coverage: required routes for which every declared replicate passed;
- probe delivery rate;
- duplicate-probe rate;
- out-of-order rate among delivered probes;
- lineage continuity among delivered probes; and
- maximum observed delivery delay.

Wrong-sensor acknowledgements count as missing. Unknown or duplicate probe IDs,
rewritten summaries, malformed digests, and route/canary substitution are
rejected. Passing applies only to the declared routes and capture window; it does
not prove that arbitrary production events are semantically correct.

## 3. LureDelegation identity and capability graph

Run the deterministic metadata-only delegation suite:

```bash
lurebench delegation-eval --out delegation-evaluation.json
```

The 15 scenarios contain eleven violation families and four benign controls:

- unauthorized issuer and service-audience confusion;
- child scope amplification and delegation-depth overflow;
- expired, replayed, and revoked delegation;
- confused deputy and cross-tenant reuse;
- unauthorized subagent creation; and
- instructions accepted from an untrusted peer.

Events carry synthetic principal, issuer, audience, tenant, capability,
delegation, parent-delegation, scope, expiry, and use-limit metadata. They never
carry tokens or credential values. The monitor receives events and policy only;
labels and expected categories remain in the harness.

The reference monitor is an executable oracle for the protocol, not an IAM
product. Real deployments remain responsible for identity proofing, key custody,
revocation distribution, authorization, and enforcement.

## 4. LureIR incident-response readiness

Export the responder-visible task set:

```bash
lurebench ir-tasks --out lureir-tasks.json
```

The five cases cover boundary egress, out-of-scope delegated identity,
telemetry loss, untrusted peer coordination, and an approved benign change.
Responders return fixed-code findings with event evidence, a timeline, evidence
requests, non-executable containment-action codes, and an escalation level.

```bash
lurebench ir-eval \
  --responses responder-submission.json \
  --responder-id local-model-or-team \
  --responder-version 1.0.0 \
  --out lureir-evaluation.json
```

LureIR scores fact recall and precision, evidence support, timeline accuracy,
evidence-request recall, safe containment-action recall, unsafe-action rate, and
escalation accuracy. Evidence support requires every minimum evidence item. The
task export withholds the scoring key. The corpus contains no exploit reproduction or
operational instructions, and containment codes are never executed.

## Published contracts

Every artifact has a Draft 2020-12 JSON Schema in `spec/`. Runtime validators go
beyond shape validation by recomputing metrics and verdicts. The wheel includes
the schemas, and CI validates reference artifacts against them.

The companion LureScope workflow preserves the exact reports in one signed
portfolio, exports observation-only OSCAL 1.2.2 results, monitors scheduled probe
batches with anytime-valid statistics, and supports independent checkpoint
witnesses. See the
[LureScope operator guide](https://github.com/immu4989/lurescope/blob/main/docs/AGENT_ASSURANCE_PORTFOLIO.md).
