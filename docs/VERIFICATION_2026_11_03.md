# Input boundary verification

The source branch now checks JSON breadth and numeric-token length before
allocating decoded objects. This supplements byte limits and the existing
128-level nesting guard. These changes are unreleased; package version 0.11.0 is used
only for temporary verification builds, not a new published release.

## Reproduction and behavior

The initial regressions demonstrated that the old evidence reader entered
`json.loads` for a document containing over one million empty objects and for
a 5,003-character fractional token. The runtime application also reached its
decision engine for an array exceeding the new request budget. All three
baseline tests failed at explicit forbidden-work sentinels.

The general reader admits at most 1,000,000 nodes, counting each container,
object key, and scalar value. Runtime decision requests use 4,096 nodes;
Safetensors headers use 4,500,000 nodes within their existing 8 MiB byte limit.
Unquoted tokens are limited to 4,096 characters. String contents are not counted
as structure, and strict decoding still rejects malformed JSON, duplicate keys,
and nonfinite numbers after the resource preflight.

The scanner uses constant auxiliary state over the decoded UTF-8 text. It does
not impose byte limits on direct Python callers, authenticate evidence, or bound
total process memory, request concurrency, or parsing latency. Existing input
files and canonical identities are not rewritten. Previously accepted documents
above the new limits can fail admission.

## Verification

- Full suite: 2,134 passed, 40 skipped, 15 existing dependency warnings.
- New complexity tests: 31 passed, including exact node/token boundaries,
  escaped strings and keys, strict syntax retention, 400 seeded structures,
  pre-decode rejection, and no runtime decision/receipt on rejection.
- A 25,000-tensor rank-32 Safetensors header exceeds the general node budget
  but passes its specialized budget and all existing shape/offset checks.
- Ruff and `git diff --check` pass.
- Offline wheel and source-distribution builds pass; the wheel verifier matches
  158 exact authority-source files. Installed core checks pass on Python 3.12
  and 3.13 under `-I -S`, outside the checkout, with optional imports forbidden.
  The installed smoke includes complexity rejection and normal decoding.

The temporary build directory is `/private/tmp/lure-json-20261103.GKQhe1`.
Tests use synthetic local inputs and no provider calls or credentials.

## Research basis

[Python's JSON documentation](https://docs.python.org/3/library/json.html)
warns that untrusted JSON can consume substantial CPU and memory.
[RFC 8259 section 9](https://www.rfc-editor.org/rfc/rfc8259.html#section-9)
permits implementation limits. The exact budgets here are project decisions,
not a standard's mandated thresholds or a certification claim.

## Runtime HTTP admission

The runtime handler now rejects ambiguous length/type/encoding headers,
transfer coding, unsupported expectations, folded headers, and incomplete bodies
before decision evaluation. Five-second body deadlines use a monotonic clock
and do not reset with partial arrival. Responses close connections and redact
request-derived framework and processing errors. Socket idle timeouts do not
provide a total header deadline or bound concurrency.

The initial 27-case test set failed against the old implementation; cases
covered new admission behavior, fixed diagnostics, and explicit connection-close
metadata, including previously rejected inputs whose response contract changed.
The final 43 HTTP tests pass. They exercise the actual standard-library HTTP
parser over deterministic socket-like streams and three real socket-pair cases:
complete body, truncated body, and stalled body. Other cases cover an absolute
deadline across partial reads, receipt preservation after a valid request, and
no receipt/state change after framing rejection. The packaged OpenAPI response
descriptions match the runtime endpoint.

Final full suites: LureBench 2,177 passed, 40 skipped, 15 dependency warnings;
paired LureScope 1,439 passed, 16 dependency warnings; browser 107 passed.
Total: 3,723 passed. Ruff, whitespace checks, 26 historical producer pins, and
10 independently verified authority artifacts pass. Offline wheels and source
distributions build, with 158/167 exact authority-source files and 19 browser
inputs verified. Installed core smokes, including real HTTP-parser framing and
redaction, pass under Python 3.12/3.13 `-I -S` without optional imports. Installed
LureScope model/proof, authentication/JSON admission, and browser checks pass.
The verification build is `/private/tmp/lure-runtime-http-20261103.JxVzp0`.

An additional synthetic fault audit found that the previous application could
advance decision state after receipt-log open failure and then persist sequence
2 as the first log record. HTTP processing errors are now redacted, but this
HTTP milestone did not repair that persistence gap. Operators must treat failures
as uncertain outcomes, not allowed decisions or automatic retry authorization.
The following milestone adds fail-stop behavior after storage failure.

## Runtime audit failure fail-stop

The runtime now latches persistence failures and uncertain decision-engine errors.
Later valid requests cannot enter the engine on that instance; `/health` reports
503 after the latch is set. A dedicated, unused engine is required for a new
receipt log. Private, single-link regular-file metadata is checked before engine
entry and around append; successful return requires a full write, flush, fsync,
close, and final path check. Unexpected file changes fail closed.

Thirty new audit tests cover storage-stage faults, partial writes, interruptions,
file replacement and permission changes, descriptor cleanup, concurrent waiters,
and contiguous concurrent success. The HTTP suite now has 44 passing cases,
including an actual application storage fault followed by unavailable health
and decision responses. Invalid input does not poison a healthy instance.

Full suites: LureBench 2,208 passed, 40 skipped, 15 dependency warnings;
LureScope 1,439 passed, 16 dependency warnings; browser 107 passed.
Combined: 3,754 passed. Ruff and whitespace checks pass. Offline wheel and
source builds pass; archive checks match 158/167 authority-source files and
19 browser inputs. Installed core checks pass on Python 3.12/3.13 under
`-I -S`, including a storage failure that remains latched after fault removal.
Installed LureScope model/proof, authentication/JSON, and browser checks pass.
Build artifacts are in `/private/tmp/lure-audit-failure-20261103.xo4Y1E`.

These are synthetic fault tests, not power-loss durability tests. Readiness is
a nonblocking latch snapshot, not a live storage or stalled-I/O probe. Partial
or uncertain bytes are preserved for operator review; there is no automatic
rollback, replay-state restoration, or exactly-once delivery guarantee. Parent
directories and exclusive engine ownership remain operator responsibilities.

## Dependency security and supported interpreter baseline

The source now requires Python 3.11+, following Python 3.10 end-of-life and the
patched filelock line's Python requirement. The initial unconstrained-interpreter
resolution failed for Python 3.10; no conditional vulnerable fallback was added.
Package metadata, both CI matrices, README, lint target, and the current NIST
draft agree on the new minimum. Historical release notes are not rewritten.
CI installs use `--locked` to reject stale lockfiles.

The lock selects certifi 2026.10.23, filelock 4.2.7, and setuptools 84.2.1.
Five new security-floor/build tests initially failed across the repositories.
Final floor and interpreter tests pass; both locks pass `uv lock --check --offline`.
Unrelated remaining versions are unchanged; obsolete Python 3.10 branches were
removed. See [the dependency review](DEPENDENCY_SECURITY.md) for advisory links,
resolution scope, and the unresolved Accelerate alert.

A fresh locked Python 3.11.15 dev/train environment exposed a runtime HTTP
compatibility bug: early malformed-version errors suppressed the status line
and headers through the standard library's HTTP/0.9 fallback. The handler now
frames those error responses explicitly. The HTTP suite has 49 passing cases
on Python 3.11 and 3.13, and the installed smoke covers the malformed-version path.

Full LureBench suites: 2,217 passed, 40 skipped on both Python 3.11 and 3.13
(5 and 15 dependency warnings respectively). Paired LureScope passes 1,442 on
Python 3.11 and 3.12; browser tests pass 107. Combined distinct suite count:
3,766, not the sum of repeated interpreter runs. The frozen released-producer
LureScope environment passes 1,382 with 60 newer-producer-dependent skips;
pairing the source producer removes those skips.

Offline CA-bundle loading and filelock exclusive-acquire/release smokes pass with
the new packages. These are compatibility checks, not exploit reproductions or
proofs for all lock variants/operating systems. No model frameworks or weights
were downloaded and no provider was called. Wheels and source archives build;
wheel metadata rejects Python 3.10 and retains the dependency-free Bench core.
Authority archive checks (158/167 files), 19 browser source inputs, 26 historical
producer pins, 10 independent authority artifacts, static stamps, and Ruff pass.
Artifacts and logs are in `/private/tmp/lure-dependencies-20261103.25aZ2O`.

Nothing was committed, pushed, released, deployed, or dismissed on GitHub in this
milestone. The full Scope alert lookup timed out in permission review twice;
only the locally verified fixes are claimed, not closure of all remote alerts.

## Runtime capacity admission — 4 November 2026

The initial three regressions exposed unbounded TCP worker creation, an absent
decision-wait control, and Unix health blocked behind a stalled receipt write.
The first reproduction admitted a seventeenth worker while sixteen handlers
were held at a synthetic barrier; the Unix health request timed out before the
write was released. No third-party service or real user data was involved.

Both transports now have 16 worker slots by default (configurable 1..256).
Excess accepted sockets close before parsing or worker creation. Decision-lock
admission waits at most the configured interval (default one second; 0..30),
then returns a fixed `runtime_busy` 503 without entering the engine or changing
replay/receipt state. This is admission control, not cancellation of active work
or a real-time latency guarantee. Unix workers permit independent health
handling when capacity remains. Explicit IPv6 loopback selects AF_INET6.

The 37 capacity cases cover default limits on all three transports, invalid
configuration before side effects, real timed admission, latch precedence,
slot recovery, capacity closure, CLI forwarding, and interruption/error both
before and after thread creation. Ambiguous start failures close further
admission instead of speculatively releasing an already-running worker's slot.
The 50 HTTP cases include actual busy responses and unchanged replay/receipt
state. Real IPv4, IPv6, and private Unix listeners pass saturation/recovery
checks; these tests required explicit local-listener permission in the sandbox.

Full suites: LureBench 2,255 passed with 40 skips on Python 3.11 and 3.13;
LureScope 1,446 passed; browser 107 passed. Distinct combined count: 3,808.
The existing dependency warnings remain (Bench 5/15 by interpreter, Scope 16).
Consumer regressions reject busy/unavailable JSON substituted for receipts and
missing receipts presented as a passing evaluation, even after digest repair.
Receipt schemas and historical authority identities are unchanged.

Installed core smokes pass on Python 3.11, 3.12, and 3.13 with optional imports
forbidden, including capacity rejection, busy-state preservation, and audit
fail-stop. Model/proof, authentication/JSON, and browser installed smokes pass.
Offline archives build; authority archive checks (158/167 files), 19 browser
source inputs, 26 producer pins, 10 independent artifacts, static stamps, Ruff,
and whitespace checks pass. Artifacts are in
`/private/tmp/lure-capacity-20261103.uXAcey` (the run began before local midnight).

Limits do not reserve health capacity, impose a total header deadline, bound
process memory or lifetime replay state, or cancel blocked storage. Shutdown
does not join stuck daemon workers. These remain explicit pilot boundaries;
see [runtime admission](RUNTIME_AGENT_AUTHORIZATION.md#bounded-connection-and-decision-admission).
All changes remain local and unreleased.

## Session lifetime and pre-push verification — 4 November 2026

The v1 schema already limited receipt sequence to 512, but the old engine
advanced its nonce/sequence history before rejecting receipt 513. A receipt
timestamp that predated its request likewise consumed state before validation
failed. Three baseline regressions reproduced these failures and the service's
accidental uncertain-state shutdown instead of planned exhaustion.

The engine now checks the ceiling before evaluation and publishes a single
immutable state snapshot after receipt validation, hashing, and history
allocation. Direct calls are serialized. The service supports a smaller
`max_decisions` budget (CLI `--max-decisions`, default 512), a distinct fixed
`runtime_exhausted` response, and additive health budget counts. Existing failure
latches take precedence. No history eviction, reset, automatic rotation, durable
recovery, or transactional storage guarantee is introduced.

Twenty-one lifetime cases cover a complete 512-receipt chain, unchanged state
after rejection/preparation faults, immutable old snapshots, retained replay
protection, concurrent direct calls, concurrent final-slot admission, logged and
memory-only exhaustion, invalid configuration before side effects, and final
receipt persistence failure. HTTP tests cover the last valid response, subsequent
fixed exhaustion error, health budget, and unchanged log. LureScope rejects an
exhaustion response substituted for a receipt even when hashes are repaired.

Final full suites: LureBench **2,277 passed, 40 skipped** on Python 3.11 and 3.13;
LureScope **1,447 passed**; browser **107 passed**. Distinct total: **3,831 passed**.
Dependency warnings remain (Bench 5/15 by interpreter; Scope 16). Ruff, whitespace,
26 producer pins, 10 independent authority artifacts, and static stamps pass.
Offline wheels/source archives build; 158/167 exact authority sources and 19
browser source inputs pass archive checks. Installed core checks pass on Python
3.11/3.12/3.13 with optional imports forbidden, including the new session ceiling.
Installed model/proof, auth/JSON, and browser checks pass outside the checkout.

Logs and verification archives: `/private/tmp/lure-push-20261104.BAkBgj`.
This verification prepares the pending changes for the user's requested branch
push. It does not publish a release, deploy the service, merge into `main`, or
establish that all dependency alerts have been resolved.
