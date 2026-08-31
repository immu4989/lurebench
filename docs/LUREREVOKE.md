# LureRevoke: distributed revocation convergence for AI-agent control planes

An authorization decision can be correct at one gateway while a revoked agent,
session, credential, or device continues to operate through another. LureRevoke
makes that propagation gap measurable. It evaluates whether a synthetic
continuous-access signal reaches every declared policy enforcement node and
whether access is attenuated by a fixed deadline without blocking unrelated
subjects.

The reference campaign is deterministic, dependency-free, metadata-only, and
offline. It creates no Security Event Token (SET), performs no HTTP request, and
does not contact an identity provider, agent, policy engine, or target.

Production-like receiver and policy-gateway telemetry can be converted through
the strict [body-free OpenTelemetry workflow](LUREREVOKE_OPENTELEMETRY.md). The
conversion binds exact source bytes, enforces plan topology, and emits both an
independently recomputable projection and a normal LureRevoke run.

## Why this control matters

OpenID CAEP 1.0 defines events through which cooperating transmitters and
receivers can continuously attenuate access for human or robotic users,
devices, sessions, and applications. The final profile includes session
revocation, credential change, device-compliance change, and risk-level change
events. Shared Signals Framework 1.0 supplies the surrounding event-delivery
model. NIST SP 800-207A places policy enforcement points throughout cloud-native
applications rather than assuming one perimeter decision is sufficient.

LureRevoke connects those ideas to agent platforms without pretending to be a
wire-protocol implementation:

```text
externally authenticated signal metadata
                  │
                  ▼
        receiver / distribution plane
          │       │       │       │
          ▼       ▼       ▼       ▼
       tool     network credential storage     policy nodes
       PEP       PEP       PEP       PEP
          │       │       │       │
          └────── access probes ──────┘
                  │
                  ▼
 coverage · convergence · leakage · collateral denial
```

Primary references:

- [OpenID Continuous Access Evaluation Profile 1.0](https://openid.net/specs/openid-caep-1_0-final.html)
- [OpenID Shared Signals Framework 1.0](https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html)
- [NIST SP 800-207A](https://doi.org/10.6028/NIST.SP.800-207A)
- [CISA Zero Trust Maturity Model 2.0](https://www.cisa.gov/resources-tools/resources/zero-trust-maturity-model)

These references motivate the test surface. They do not endorse LureRevoke and
a passing evaluation is not evidence of standards conformance.

## Five-minute workflow

```bash
lurebench revocation-export --out revocation-plan.json
lurebench revocation-run \
  --plan revocation-plan.json \
  --engine-id your-receiver \
  --engine-version 1.0.0 \
  --out revocation-run.json
lurebench revocation-eval \
  --plan revocation-plan.json \
  --run revocation-run.json \
  --out revocation-evaluation.json
```

The built-in receiver is a harness self-test. Replace its run with observations
from your integration to measure the real distribution and enforcement path.
All files use canonical JSON, mode `0600` on POSIX, strict duplicate-key
rejection, bounded input, symlink rejection, and no overwrite.

## Reference campaign

The reviewed plan contains four synthetic subjects and the following CAEP event
type identifiers:

| Event | Attenuation represented |
|---|---|
| `session-revoked` | revoke one opaque session subject |
| `credential-change` | revoke one opaque credential subject |
| `device-compliance-change` | attenuate a noncompliant device subject |
| `risk-level-change` | attenuate a higher-risk workload subject |

Each event is projected to four declared policy nodes. The plan contains 64
access probes: before the event, during the permitted propagation window, after
the deadline, and against unrelated subjects. The reference run also submits a
digest-invalid signal followed by the valid signal and a duplicate, proving the
evaluator does not equate receipt with correct processing.

Event data is deliberately smaller than a SET. `signal_sha256` binds the exact
event type, opaque subject, relative occurrence time, stream sequence, and
attenuation reason. Authentication, JWT validation, issuer trust, audience
validation, transport acknowledgement, and clock synchronization remain the
integrator's responsibility.

## Independently derived metrics

The evaluator reconstructs first valid delivery for every event/node pair. It
does not trust submitted signal dispositions, expected decisions, reason codes,
or aggregate metrics.

| Metric | Meaning inside the submitted run |
|---|---|
| Delivery coverage | event/node pairs with a digest-valid applied observation |
| Max and p95 convergence | relative time from event occurrence to first valid application |
| Deadline misses | missing or late event/node applications |
| Post-deadline allows | revoked-subject probes allowed after the declared deadline |
| Revoked block recall | expected attenuations that were blocked |
| Pre-event allow rate | valid accesses not blocked before revocation existed |
| Collateral blocks | unrelated subjects incorrectly denied |
| Disposition accuracy | submitted `applied`, `duplicate`, and `invalid` labels independently agree |

A valid failing report exits `1`. Invalid input, unsafe I/O, or semantic
tampering exits `2`. A pass exits `0`.

## Integrating a real receiver

1. Authenticate and validate the SET outside LureRevoke, including issuer,
   audience, signature, time, event type, subject identifier, and replay rules.
2. Project only the permitted typed metadata into the plan/run contract. Never
   copy a bearer token, credential, reason message, target, or payload.
3. Record receiver application time from a monotonic clock mapped to the plan's
   relative epoch. Document clock error separately.
4. Emit one signal observation for every receiver disposition, including
   invalid and duplicate inputs. Do not relabel unknown delivery as applied.
5. Submit access decisions for every probe. The harness rejects missing, extra,
   or duplicate probe results.
6. Run `revocation-eval`, preserve the exact plan/run/report bytes, and have an
   independent party reproduce the metrics.

The reference `revocation-run` command does not call an external implementation.
It is an executable example of the observation contract, not a deployment test.

### Projecting externally verified CAEP claims safely

`project_verified_caep_event` is a narrow privacy adapter for deployments that
already authenticate and validate a SET. It deliberately rejects compact JWT
strings and does **not** decode a token, resolve a key, validate a signature,
discover an issuer, check replay state, or implement SSF push/poll transport.
Those checks must succeed before the decoded claims cross this function's trust
boundary.

```python
from lurebench.revocation_adapters import project_verified_caep_event

event = project_verified_caep_event(
    externally_verified_claims,
    verification={
        "signature_verified": True,
        "issuer_verified": True,
        "audience_verified": True,
        "time_verified": True,
        "delivery_method": "push",
    },
    expected_issuer=trusted_issuer,
    expected_audience=this_receiver,
    subject_hmac_key=campaign_key,  # at least 32 random bytes; never publish it
    sequence=1,
    epoch_seconds=campaign_epoch,
)
```

The adapter requires one supported, access-attenuating event and a structured
subject identifier. It validates issuer and audience equality again, rejects a
future event timestamp, converts wall time to a bounded campaign-relative time,
and replaces the raw subject and SET ID with domain-separated HMAC-SHA-256
commitments. The resulting event reconciles directly with `signal_sha256` in a
LureRevoke plan.

Use a cryptographically random, campaign-specific key, store it outside every
plan/run/report, and destroy it according to the campaign retention policy.
Reusing a key makes opaque identifiers correlatable across campaigns. HMAC
projection reduces disclosure in benchmark artifacts; it is pseudonymization,
not anonymization, and does not make a low-entropy identifier safe if the key is
disclosed. See the executable offline example:
[`examples/runtime/project_verified_caep.py`](../examples/runtime/project_verified_caep.py).

### Compose a campaign for your topology

Do not hand-copy a projected event into dozens of node/probe combinations.
Preregister the projected events, gateway topology, acceptance thresholds, and
relative probe schedule in the strict
[`lurerevoke-campaign-v1`](../spec/lurerevoke-campaign-v1.schema.json) contract,
then compose the exact benchmark plan:

```bash
lurebench revocation-compose \
  --campaign examples/runtime/revocation-campaign.json \
  --out revocation-plan.json
```

For each event and each declared node, the composer creates one pre-event and
one post-deadline probe. It also creates one within-window propagation probe and
one within-window probe and one unrelated-subject availability probe at every
declared node, for `events × 4 × nodes` probes total. This catches a receiver
that correctly preserves unrelated access or propagation semantics at one node
but behaves incorrectly at another. Event
occurrence times must increase strictly, stream
sequences must be contiguous, subjects must be distinct and opaque, signal
digests must reconcile, the within-window probe must precede the convergence
deadline, reserved control subjects cannot collide with event subjects, and all
probes must fit the 24-hour relative campaign window and 4,096-probe budget.
The generic plan validator also rejects a probe associated with one event that
uses another campaign event's subject as an availability control.

The output is deterministic, canonical, mode `0600`, and no-overwrite. Review
and approve the campaign file before collecting observations; changing its
topology, events, schedule, or thresholds changes the resulting plan digest and
therefore invalidates runs created for the prior plan. Composition performs no
SET validation, delivery, access probe, or agent action.

### Audit the declared enforcement surface

A convergence pass over an incomplete node list is not useful assurance. If
the deployment also uses a LurePermit Runtime profile, cross-check every
declared runtime mediation point before running the campaign:

```bash
lurebench revocation-topology-audit \
  --plan revocation-plan.json \
  --profile runtime-profile.json \
  --out revocation-topology-audit.json
```

The audit requires the same `system_id`, binds the exact plan and profile
digests, and independently maps each runtime mediation point's action types and
required sensors to all LureRevoke nodes naming that point. Missing mediation
points and plan nodes that map to no runtime point fail the audit. Multiple
nodes for one point are retained as replicas and counted; the tool does not
infer that replicas occupy independent processes, zones, credentials, or fault
domains.

The built-in four-node revocation example intentionally fails against the
broader nine-point runtime reference profile, making its narrower scope visible
instead of silently calling it complete. Compose a deployment plan containing
every relevant runtime mediation point to pass. Even then, a pass compares two
declared configurations—it does not discover hidden enforcement paths or prove
that a declared node exists, is reachable, or receives signals.

## Claims boundary

LureRevoke can show that the submitted observations satisfy a declared
distribution deadline and access-decision contract. It cannot prove:

- that the transmitter, receiver, node, clock, or observation was authentic;
- that every production event or access path was included;
- that a SET was valid or CAEP/SSF wire behavior was interoperable;
- that an allow/block decision was enforced on the underlying operation;
- that an organization satisfies NIST, CISA, FedRAMP, or any other requirement.

Use the result as a repeatable engineering measurement and evidence input, not
as certification or deployment authorization.
