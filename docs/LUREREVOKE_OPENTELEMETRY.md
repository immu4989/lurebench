# OpenTelemetry to LureRevoke

LureBench can turn a deliberately narrow, body-free projection of the stable
[OpenTelemetry Logs Data Model](https://opentelemetry.io/docs/specs/otel/logs/data-model/)
into a digest-bound LureRevoke run. This closes the gap between a synthetic
revocation campaign and production-like receiver/access observations without
accepting log bodies, tokens, raw subjects, prompts, payloads, or targets.

This adapter is not a general OTLP decoder and the custom LureBench attributes
are not OpenTelemetry semantic conventions. Normalize records at a trusted
collector boundary, review the resulting JSON, and retain the source export.

## Instrument two events

Emit only these `EventName` values:

| Event | Required `Attributes` |
|---|---|
| `org.lurebench.lurerevoke.signal_observed` | `observation_id`, `event_id`, `node_id`, `signal_sha256`, `disposition` |
| `org.lurebench.lurerevoke.access_decided` | `probe_id`, `decision`, `reason_code` |

Each record must also contain:

- `Timestamp`: origin-clock Unix nanoseconds, exactly millisecond-aligned
  relative to the export's `time_origin_unix_nano`;
- `ObservedTimestamp`: collector observation time, retained but never used for
  convergence scoring;
- nonzero lowercase 16-byte `TraceId` and 8-byte `SpanId` values, with each pair
  unique in the export; and
- `Resource.service.name`, `Resource.service.instance.id`, and
  `Resource.service.version`.

The service name/version must equal the declared receiver. The opaque service
instance ID must equal the plan's node ID for the signal or referenced probe.
OpenTelemetry notes that service-instance identity can be sensitive and
recommends opaque identifiers; do not copy a pod name, hostname, email address,
or account identifier into this field. See the official
[`service.instance.id` guidance](https://opentelemetry.io/docs/specs/semconv/registry/attributes/service/).

The public input contract is
[`lurerevoke-otel-log-export-v1.schema.json`](../spec/lurerevoke-otel-log-export-v1.schema.json).
Its exact-object policy rejects `Body`, unknown resource fields, and arbitrary
attributes.

## Project and evaluate

```bash
lurebench revocation-otel-project \
  --plan revocation-plan.json \
  --logs receiver-otel.json \
  --run-id production-shadow-2026-08-30 \
  --out receiver-otel.projection.json \
  --run-out receiver-run.json

lurebench revocation-otel-verify receiver-otel.projection.json

lurebench revocation-eval \
  --plan revocation-plan.json \
  --run receiver-run.json \
  --out receiver-evaluation.json
```

The projection embeds the validated plan and normalized log export, commits
their canonical bytes and the resulting run with SHA-256, and can therefore be
recomputed independently. Both output files are new mode-0600 files; existing
files are never overwritten, and a failed second write removes the first.

The adapter fails closed when:

- a record is not one of the two declared event types;
- a body or unknown field appears;
- resource identity disagrees with receiver or plan topology;
- event, node, or probe references are unknown;
- trace/span context is zero, malformed, or reused;
- source time is before the declared origin, after export generation, not
  millisecond-aligned, or outside the 24-hour campaign window; or
- the resulting run does not contain exactly one access observation per probe.

## Evidence boundary

A valid projection proves deterministic transformation of the embedded bytes.
It does not prove that instrumentation was complete, clocks were synchronized,
trace context was authentic, signals were transported, or access was actually
enforced. `ObservedTimestamp` is informational because OpenTelemetry defines it
on the collector's clock; comparing it directly with an origin-clock
`Timestamp` would introduce an unjustified clock-synchronization assumption.

For stronger integrity, create and sign the resulting evidence bundle with
LureScope, then register its checkpoint in the append-only LureRevoke registry.
