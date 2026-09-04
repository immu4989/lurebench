# LureIdentity OpenTelemetry bridge

LureIdentity can reconstruct one complete benchmark run from a deliberately
small, body-free projection of the stable OpenTelemetry Logs Data Model. This
connects production-like lifecycle and access telemetry to the benchmark
without admitting directory records, user identifiers, workload identities,
tokens, prompts, payloads, targets, or free-form log messages.

This is a strict JSON interchange contract. It is not an OTLP decoder and the
custom LureIdentity event names and attributes are not an OpenTelemetry semantic
conventions conformance claim.

## Why this shape

OpenTelemetry models an event as a `LogRecord` with a non-empty `EventName`.
`Timestamp` represents when the event occurred; `ObservedTimestamp` represents
when it was observed by the collection system. The OpenTelemetry event guidance
also recommends low-cardinality event names and placing changing values in
attributes. LureIdentity follows those boundaries with two fixed names:

- `org.lurebench.lureidentity.lifecycle_event_observed`
- `org.lurebench.lureidentity.access_decided`

The contract rejects `Body` entirely. This is stronger than the upstream model,
where a body is optional, because an unrestricted display message is an easy
place to leak names, email addresses, raw SCIM content, tokens, prompts, or
access targets. The contract also avoids `enduser.id`, which OpenTelemetry marks
as sensitive personally identifiable information.

Authoritative references:

- [OpenTelemetry Logs Data Model](https://opentelemetry.io/docs/specs/otel/logs/data-model/)
- [OpenTelemetry semantic conventions for events](https://opentelemetry.io/docs/specs/semconv/general/events/)
- [OpenTelemetry attribute naming](https://opentelemetry.io/docs/specs/semconv/general/naming/)
- [OpenTelemetry `enduser` attributes](https://opentelemetry.io/docs/specs/semconv/registry/attributes/enduser/)

## Exact accepted record

Every record contains exactly these fields:

| Field | LureIdentity use |
|---|---|
| `Timestamp` | event time in Unix nanoseconds; benchmark timing source |
| `ObservedTimestamp` | collector time, byte-bound but never scored |
| `TraceId`, `SpanId` | unique nonzero lowercase correlation identifiers |
| `EventName` | one of the two fixed names above |
| `Resource` | exact receiver name, node instance ID, and receiver version |
| `Attributes` | one exact bounded attribute set selected by `EventName` |

Lifecycle attributes are `observation_id`, `event_id`, `node_id`,
`event_sha256`, and `disposition`. Access attributes are `probe_id`, `decision`,
and `reason_code`. Unknown fields fail closed.

`Timestamp` is converted to relative milliseconds from
`time_origin_unix_nano`. Access timestamps must equal the preregistered
`attempted_at_ms` for their probes exactly. Output access observations follow
the immutable plan's probe order; lifecycle observations follow plan event and
node order with deterministic timestamp/identifier tie-breaking. Export record
order therefore cannot silently change the projected run.

## Project and verify

Produce the exact plan first, then obtain a JSON export from reviewed
instrumentation:

```bash
lurebench identity-export --out identity-plan.json

lurebench identity-otel-project \
  --plan identity-plan.json \
  --logs identity-otel-export.json \
  --run-id identity-production-run-1 \
  --out identity-otel-projection.json \
  --run-out identity-run.json

lurebench identity-otel-verify identity-otel-projection.json
lurebench identity-eval \
  --plan identity-plan.json \
  --run identity-run.json \
  --out identity-evaluation.json
```

The projection embeds and hashes the exact plan and source export, reconstructs
and hashes the exact run, and is written as private canonical JSON without
overwriting an existing path. `identity-otel-verify` recomputes all fields from
the embedded sources.

For release decisions, pass this projection to LureScope. Its verifier is an
independent implementation and its LureIdentity deployment gate requires the
topology audit, telemetry projection, and authenticated evidence bundle to bind
the same exact plan and run.

## Collection guidance

1. Preregister a reviewed plan and runtime profile before collection.
2. Authenticate the SCIM or directory source outside this format and retain the
   authentic source evidence separately.
3. Emit only opaque identifiers already present in the plan and SHA-256
   commitments; do not transform personal data into new identifiers here.
4. Derive `service.instance.id` from the actual enforcement node, not an
   agent-supplied value.
5. Establish clock synchronization and collector trust externally. The bridge
   binds timestamps but cannot prove their truth.
6. Restrict and attest the receiver artifact separately. A matching digest is a
   caller-supplied identity claim until independently verified.
7. Preserve the source export and projection as sensitive evidence even though
   the schema excludes common content-bearing fields.

## Claims boundary

A valid projection proves only that the accepted body-free records
deterministically reconstruct the embedded run under this contract. It does not
prove OTLP transport, OpenTelemetry semantic-convention conformance, telemetry
completeness, event authenticity, clock synchronization, causal linkage,
independent observation, directory authorization, SVID possession, or actual
enforcement. Those exclusions are embedded in the public schemas.
