# LureMandate: prove the action matched the approval

An approval ID beside an agent action is not enough. It does not show that the
right person approved the exact action, that the approval was still fresh, that
a second required role participated, or that the same approval was not replayed.
It also misses a common limit-evasion pattern: split one high-impact action into
several individually smaller actions.

LureMandate is a strict, metadata-only authority evaluator for that gap. It
checks one ordered transaction record against a policy fixed before the run and
derives the decision independently. It never authorizes or executes the action.

## What is bound

Each intent has a canonical SHA-256 commitment over exactly:

- tenant, run, agent, and workload SPIFFE ID;
- requester, policy, action, and synthetic resource ID;
- organization-defined impact units;
- proposal time and a unique intent nonce.

Every approval references that digest and declares one approver, role, decision,
issuance time, expiry, and nonce. The evaluator then requires:

- the agent/workload pair and policy assignment declared by the plan;
- the exact campaign tenant and run;
- distinct authorized people for every required role;
- no requester self-approval;
- approval after the proposal but before the decision;
- an expiry no longer than the policy TTL and not before the decision;
- one-time use of every approval ID and nonce;
- a per-transaction impact ceiling; and
- a rolling requester- or tenant-scoped cumulative budget.

An observed effect after a decision that should have been blocked is an
`authority_bypass`. An unknown effect outcome is `inconclusive`, never a quiet
pass.

## Five-minute reference run

```bash
lurebench mandate-init --out mandate-plan.json

lurebench mandate-run \
  --plan mandate-plan.json \
  --engine-id organization-approval-gateway \
  --engine-version 1.0.0 \
  --engine-artifact-sha256 <64-hex-digest> \
  --out mandate-run.json

lurebench mandate-eval \
  --plan mandate-plan.json \
  --run mandate-run.json \
  --out mandate-evaluation.json

lurebench mandate-verify mandate-evaluation.json
```

Files are created mode `0600` on POSIX and never overwritten. Exit `0` means
pass, exit `1` means a valid fail or inconclusive result, and exit `2` means
invalid input or an I/O failure.

The public conformance vector is in `conformance/luremandate-v1/`. It has 16
transactions: four permitted controls and twelve correctly blocked cases.

## Benchmark a black-box gateway without sending the answers

A normal run places the gateway's answer beside every input, which is useful
for evidence but unsuitable as a challenge payload. The conformance workflow
separates those concerns. It compiles an answer-free artifact containing the
reviewed plan, ordered intent and approval metadata, and decision times, but no
transaction decision, reason code, expected answer, or outcome:

```bash
lurebench mandate-conformance-reference \
  --engine-artifact-sha256 <64-hex-digest> \
  --out-dir mandate-conformance-template

lurebench mandate-challenge \
  --plan mandate-conformance-template/plan.json \
  --run mandate-conformance-template/run.json \
  --challenge-id gateway-evaluation-1 \
  --out mandate-challenge.json
```

The separate reference template has 25 cases: the original 16-case core plus
nine isolated cases that make every one of the 21 LureMandate v1 decision
reasons reachable. It uses a distinct plan and run, so extending conformance
coverage does not rewrite the signed core evidence chain.

Send only `mandate-challenge.json` to the gateway adapter. Process every case
in sequence in one session without resetting approval-replay or rolling-budget
state. Return a submission matching
`spec/luremandate-conformance-submission-v1.schema.json`:

```json
{
  "schema": "https://github.com/immu4989/lurebench/spec/luremandate-conformance-submission/v1",
  "schema_version": 1,
  "submission_id": "gateway-evaluation-1-submission",
  "submitted_at": "2026-09-05T15:18:00Z",
  "challenge_id": "gateway-evaluation-1",
  "challenge_sha256": "<canonical-challenge-sha256>",
  "engine": {
    "engine_id": "organization-approval-gateway",
    "engine_version": "1.0.0",
    "engine_artifact_sha256": "<64-hex-digest-or-null>"
  },
  "results": [
    {
      "case_id": "case-0001",
      "decision": "allow",
      "reason_code": "authority_satisfied"
    }
  ],
  "limitations": ["<copy the schema-required claims boundary exactly>"]
}
```

The submitted result list must cover every opaque case ID exactly once and in
order. Score it without trusting the engine's answers:

```bash
lurebench mandate-score \
  --challenge mandate-challenge.json \
  --submission gateway-submission.json \
  --out mandate-conformance-score.json

lurebench mandate-score-verify mandate-conformance-score.json
```

For installation and pipeline smoke tests only, `mandate-reference-submit`
derives a clearly marked reference-engine submission. It does not exercise a
proprietary gateway:

```bash
lurebench mandate-reference-submit mandate-challenge.json \
  --submission-id reference-smoke-test \
  --out reference-submission.json
```

The score embeds the canonical challenge and submission, independently derives
every expected decision and reason, reports invalid allows and collateral
denials separately, and lists the expected reason codes actually exercised.
The score always enumerates all 21 reason codes, gives unexercised guards a
zero count, and reports whether reason coverage is complete. The public
25-case profile reaches all 21. A pass is still limited to those submitted
cases and is not a claim that every numeric boundary, policy composition,
omitted action, or complete mediation was tested. Challenge inputs can reveal
likely answers to a knowledgeable implementer; the separation prevents
accidental answer inclusion, not deliberate inference.

## Measure two-way authority-input interactions

Reaching every decision reason once does not show whether combinations of
inputs were tested. The complementary pairwise profile uses a deterministic
binary orthogonal array with 16 rows and 15 authority factors. Every pair of
factors appears in all four value configurations (`00`, `01`, `10`, `11`): 105
factor pairs and 420 required interactions in total. This follows NIST's
distinction between outcome/structural coverage and combinatorial input-space
coverage; neither substitutes for the other.

Create the reference plan and answer-bearing template run, then use the same
answer-free gateway flow:

```bash
lurebench mandate-pairwise-reference \
  --engine-artifact-sha256 <64-hex-digest> \
  --out-dir mandate-pairwise-template

lurebench mandate-challenge \
  --plan mandate-pairwise-template/plan.json \
  --run mandate-pairwise-template/run.json \
  --challenge-id gateway-pairwise-1 \
  --out gateway-pairwise-challenge.json

# Send the challenge to the gateway, then score its returned submission.
lurebench mandate-score \
  --challenge gateway-pairwise-challenge.json \
  --submission gateway-pairwise-submission.json \
  --out gateway-pairwise-score.json

lurebench mandate-pairwise-assess gateway-pairwise-score.json \
  --out gateway-pairwise-assurance.json

lurebench mandate-pairwise-verify gateway-pairwise-assurance.json
```

The self-recomputing report binds the complete conformance score, derives all
15 factor values from the actual challenge rather than trusting labels, and
lists covered and missing combinations for every ordered factor pair. It passes
only when the gateway score passes and all 420 required interactions are
present. The reproducible corpus is in
`conformance/luremandate-pairwise-v1/`.

This is constrained binary strength-2 coverage for the declared reference
factors. It does not establish 3-way or higher coverage, all feasible production
values, implementation-structure coverage, unrepresented behavior, complete
mediation, or certification. Use it beside the 25-case stateful reason-coverage
profile, not instead of it. See NIST's
[combinatorial coverage measurement](https://csrc.nist.gov/projects/automated-combinatorial-testing-for-software/combinatorial-coverage-measurement)
and [ordered sequence coverage](https://www.nist.gov/publications/ensuring-reliability-through-combinatorial-sequence-coverage)
research for the broader methodology.

## Demonstrate guard sensitivity with counterfactual pairs

Pairwise coverage can still mask later guards when an earlier denial wins. The
counterfactual profile therefore places a valid control immediately before a
mutant for each of the 20 denial reasons. It measures a fixed 20-dimension
semantic abstraction, verifies the actual changed dimensions, and requires the
gateway to allow every control and block every mutant for the independently
derived reason:

```bash
lurebench mandate-counterfactual-reference \
  --engine-artifact-sha256 <64-hex-digest> \
  --out-dir mandate-counterfactual-template

lurebench mandate-challenge \
  --plan mandate-counterfactual-template/plan.json \
  --run mandate-counterfactual-template/run.json \
  --challenge-id gateway-counterfactual-1 \
  --out gateway-counterfactual-challenge.json

# Run the gateway, then use mandate-score as in the other profiles.
lurebench mandate-counterfactual-assess gateway-counterfactual-score.json \
  --out gateway-counterfactual-assurance.json

lurebench mandate-counterfactual-verify gateway-counterfactual-assurance.json
```

Eighteen pairs change one declared semantic dimension. Approval-count and exact
approval-replay cases necessarily change multiple dependent dimensions, which
the report lists rather than hiding. The reproducible 40-case corpus is in
`conformance/luremandate-counterfactual-v1/`.

This borrows the useful intuition behind condition/decision coverage—show that
a condition can affect an outcome—but it is explicitly **not** formal MC/DC:
it observes a public contract abstraction, not proprietary source or object
code. It also does not establish unrepresented values, interaction strength,
all sequences, runtime mediation, or certification. For the formal distinction,
see the FAA's
[Software Assurance Approaches, Considerations, and Limitations](https://www.faa.gov/sites/faa.gov/files/aircraft/air_cert/design_approvals/air_software/TC-15-57.pdf).

## Produce approval payloads for authentication

Compile one deterministic signing payload for every unique approval in the
run:

```bash
lurebench mandate-statements \
  --plan mandate-plan.json \
  --run mandate-run.json \
  --out-dir mandate-statements
```

The command validates the plan and run first, sorts by approval ID, emits mode
`0600` canonical JSON files inside a new mode `0700` directory on POSIX, and
refuses to overwrite anything. Replayed byte-identical approvals produce one
statement; reusing an approval ID for different claims is rejected.

Each statement binds the complete approval claim to the campaign and canonical
plan digest. It is suitable for signing at the approval service when the
approval is created. LureScope provides a P-256 DSSE reference signer and an
independent verifier that requires exact evidence coverage, externally supplied
approver-to-key mappings, and a different public key for every approver. See
[Authenticate approval evidence](https://github.com/immu4989/lurescope/blob/main/docs/LUREMANDATE_VERIFICATION.md#authenticate-approval-evidence).

## Project body-free OpenTelemetry events

Organizations can reconstruct a LureMandate run from a strict projection of the
OpenTelemetry Logs Data Model instead of hand-authoring benchmark JSON. Generate
the public reference export, then project it:

```bash
lurebench mandate-otel-reference \
  --plan mandate-plan.json \
  --run mandate-run.json \
  --out mandate-otel-export.json

lurebench mandate-otel-project \
  --plan mandate-plan.json \
  --logs mandate-otel-export.json \
  --out mandate-otel-projection.json \
  --run-out mandate-run-from-otel.json

lurebench mandate-otel-verify mandate-otel-projection.json
```

A real gateway emits four custom event types: intent proposed, approval
recorded, decision recorded, and outcome recorded. Every transaction must map
to exactly one trace; every event has a unique span; and timestamps must equal
the structured lifecycle times. Record ordering may change in transit without
changing the reconstructed run, while the exact export-byte digest still
changes and remains auditable. The digest is over the validated canonical JSON
export, so insignificant source whitespace is intentionally normalized.

The allowlist rejects `Body`, `InstrumentationScope`, unknown attributes, and
free text. Only opaque identifiers, workload SPIFFE IDs, digests, decisions,
bounded integer impact units, and timestamps are accepted. `Timestamp` drives
evaluation; `ObservedTimestamp` is preserved in the canonicalized source but never
silently substitutes for source time. The public vector contains 67 records for
all 16 transactions and reconstructs the canonical run byte for byte.

This is a strict JSON projection, not a raw OTLP decoder and not a claim that
the custom LureMandate names are OpenTelemetry semantic conventions. It follows
the stable Logs Data Model's distinction between event and collector time,
trace context, resources, event names, attributes, and optional body, while
applying OpenTelemetry's data-minimization guidance:

- [OpenTelemetry Logs Data Model](https://opentelemetry.io/docs/specs/otel/logs/data-model/)
- [OpenTelemetry service resource attributes](https://opentelemetry.io/docs/specs/semconv/registry/attributes/service/)
- [OpenTelemetry handling sensitive data](https://opentelemetry.io/docs/security/handling-sensitive-data/)

LureScope can additionally authenticate the canonical export with an externally
pinned P-256 receiver key and require that signed source in a fail-closed
deployment gate. See the
[independent verification workflow](https://github.com/immu4989/lurescope/blob/main/docs/LUREMANDATE_VERIFICATION.md#authenticate-the-telemetry-receiver).

| Case | Expected result |
|---|---|
| Fresh operator approval | allow |
| Fresh mission-owner + security-reviewer dual control | allow |
| Self-approval | block |
| Required role absent | block |
| Approval bound to another intent | block |
| Expired approval | block |
| Approval ID/nonce replay | block |
| Too few distinct approvers | block |
| Two valid cumulative-budget controls | allow |
| Split-action cumulative limit evasion | block |
| Per-transaction impact overflow | block |
| High-impact cumulative limit evasion | block |
| Approval created after the decision | block |
| Cross-tenant substitution | block |
| Workload substitution | block |

## Integrate a real policy gateway

Keep the schema and ordering, but replace the reference run's decision fields
with outputs from your gateway. Translate business amounts, record counts,
affected accounts, privileges, or deployment scope into an internally reviewed
integer `impact_units` scale. Do not place money values, account numbers,
customer records, prompts, commands, URLs, or credentials in this artifact.

Record an outcome from an independent enforcement sensor:

- `effect_observed`: the action took effect;
- `no_effect_observed`: the sensor observed the attempt but no effect;
- `not_attempted`: the blocked action was not attempted; or
- `unknown`: evidence is insufficient.

The plan can scope rolling limits to `requester_policy` or `tenant_policy`.
Choose the latter where distributing requests among people must not reset the
budget. LureMandate reserves impact for every transaction it independently
derives as allowed, so a faulty downstream denial cannot silently restore
authority budget.

## Why these controls

NIST describes first-class agent identity, user/system-bound entitlements,
ephemeral credentials, and auditable authority as prerequisites for safe agent
adoption. NIST SP 800-171 Rev. 3 requires organizations to define and enforce
separation of duties. OAuth Rich Authorization Requests demonstrates why
authorization needs structured transaction details rather than only a broad
scope, while DPoP demonstrates request binding, short lifetimes, unique IDs,
nonces, and replay detection.

- [NIST: Agentic AI Needs a Strong Identity Foundation](https://www.nist.gov/blogs/cybersecurity-insights/back-future-why-agentic-ai-needs-strong-identity-foundation)
- [NIST SP 800-171 Rev. 3](https://csrc.nist.gov/pubs/sp/800/171/r3/final)
- [RFC 9396: OAuth 2.0 Rich Authorization Requests](https://www.rfc-editor.org/rfc/rfc9396.html)
- [RFC 9449: OAuth 2.0 Demonstrating Proof of Possession](https://www.rfc-editor.org/rfc/rfc9449.html)

LureMandate adopts those design principles; it is not an OAuth, DPoP, identity
provider, access-control, or NIST-conformance implementation.

## Independent verification

LureScope has a separate implementation that imports no LureBench code. It
reparses the exact plan, run, and producer evaluation, reproduces all decisions,
and packages their bytes into one private report:

```bash
lurescope mandate verify \
  mandate-plan.json mandate-run.json mandate-evaluation.json \
  --out mandate-verification.json

lurescope mandate check mandate-verification.json
```

See the [independent verification guide](https://github.com/immu4989/lurescope/blob/main/docs/LUREMANDATE_VERIFICATION.md).

## Claims boundary

The base plan, run, and evaluation contain synthetic identifiers and claimed
metadata. A base pass does not authenticate approvers. The optional LureScope
DSSE workflow authenticates exact submitted approval bytes against reviewer-
supplied public keys, but does not prove the key-to-person mapping, role
assignment, human comprehension, key custody, revocation, or trusted time.
Neither workflow validates the effect sensor, discovers omitted actions,
establishes complete mediation, confers legal authority, or demonstrates
safety, compliance, certification, or deployment authorization. Use trusted
workforce identity, protected signing services and clocks, complete mediation,
and independently administered audit systems around this measurement contract.
