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

## Complete HTTP request-head admission — 4 November 2026

Three baseline tests returned HTTP 200 where rejection was required: a
synthetic slow trickle exceeded five seconds, a 20 KiB header reached health,
and EOF before the terminating blank line still reached health. The existing
socket idle timeout and framework per-line/count limits did not impose the
project's new total head deadline or aggregate byte ceiling.

All paths now collect a complete request head before framework parsing, with
a 16 KiB wire-byte budget and five-second total monotonic deadline. Collection
requests at most 4 KiB per read and at most one sentinel byte beyond the head
budget. It then replays the complete head and any prefetched body prefix;
subsequent body bytes are preserved exactly and retain their separate deadline.
Oversized lines/heads, expiration, incomplete EOF, and transport read errors
have fixed 414/431/408/400 responses before policy or readiness work. HTTP/0.x
is refused, rather than returning unframed JSON. Existing framework syntax
and header-count checks remain in place.

Forty new tests cover exact byte boundaries, many small headers, wire-byte
counting, field-count limits, five read-fragment sizes with CRLF/LF line endings,
full-size body preservation, ignored pipelined data, EOF/read/write failures,
HEAD body suppression, normalized HTTP/1 versions, separate head/body deadlines,
and final-chunk expiry. Three real IPv4/IPv6/private-Unix tests verify total
deadline closure and subsequent worker-slot recovery. A client that continues
writing after close can legitimately observe TCP reset; delivery of an error
response is not guaranteed. No request content is reflected by these errors.

LureScope adds five independent rejection cases for head-error objects
substituted for receipts, including repaired artifact hashes. Historical
receipt schemas/identities and stateful decision semantics are unchanged.

Full suites: **2,317 passed, 40 skipped** in LureBench on Python 3.11 and 3.13;
**1,506 passed** in paired LureScope; **107 browser tests passed**. Distinct total:
**3,930 passed**. Existing dependency warnings remain (Bench 5/15 by interpreter,
Scope 16). Ruff, whitespace, 26 producer pins, 10 independent authority artifacts,
and static stamps pass. Offline archives build; 158/167 exact authority sources
and 19 browser source inputs pass archive checks. Installed core checks pass on
Python 3.11/3.12/3.13 with optional imports forbidden, including oversized,
incomplete, versionless, and late request heads. Installed model/proof,
authentication/upload, and browser checks also pass outside the checkout.

Artifacts and logs: `/private/tmp/lure-head-20261104.Dx6rnl`.
The control is not a general-purpose HTTP parser, process-memory bound, fair
admission policy, guaranteed response latency, or prevention of all denial of
service. It does not cancel engine/storage work or reserve health capacity.
See [HTTP admission and references](RUNTIME_AGENT_AUTHORIZATION.md#http-admission-and-failure-handling).
At completion of this verification, these changes were local; no commit, push,
release, or deployment had occurred.

### Requested branch-push verification

Before the subsequent user-requested push, the full suites were rerun:
LureBench Python 3.13 **2,317 passed, 40 skipped**, paired LureScope Python 3.12
**1,506 passed**, and browser **107 passed**. Existing dependency warnings
remain. Ruff, whitespace, producer pins, independent authority artifacts, and
static stamps pass. Both feature branches match their fetched remote tips before
committing. Logs: `/private/tmp/lure-push-verify-20261104.dN5UAF`.
This prepares branch publication, not a merge, package release, or deployment.

## Unix-socket lifecycle ownership — 4 November 2026

Five initial regressions failed against the prior implementation: shutdown and
application-startup failure deleted replacement files; activation failure and
application interruption left the service's socket behind; a mode-0755 parent
was admitted. All reproductions used synthetic entries in owned temporary
directories, not user sockets or services.

Unix startup now requires an existing mode-0700 directory owned by the effective
UID, opened without following the final component. A retained non-inheritable
directory descriptor anchors no-follow entry inspection and cleanup. Binding
captures socket identity/metadata, then sets mode 0600 before listening. Existing
entries are refused; observed replacements or metadata changes are not reclaimed.
Cleanup ownership is transferred once, including concurrent/repeated close, and
the original directory remains the target after a rename. Activation/application
failures and interruption close resources. Cleanup failure retains the original
exception with a note; CLI errors expose the fixed cleanup notice, and an
interruption with failed cleanup returns exit 2 rather than silent success.

The **54 new tests** cover the initial failures, replacement files/directories/
symlinks/sockets, dangling and pre-existing entries, private-parent mode/owner
checks, relative paths and changed working directories, parent replacement,
permission and bind collisions, metadata changes, missing paths, platform
capability refusal and the no-follow-chmod fallback, concurrent/idempotent close,
descriptor closure after cleanup failure, primary-error preservation, and CLI
interruption/error reporting. A real Unix HTTP health request verifies successful
service, cleanup, and restart. Installed-wheel checks independently exercise
private socket mode, normal cleanup, replacement preservation, and parent refusal.

Final full suites pass **2,371 tests with 40 skips** in LureBench on both Python
3.11 and 3.13, **1,506** in paired LureScope on Python 3.12, and **107** browser
tests: **3,984 distinct passed tests**. Existing dependency warnings remain
(Bench 5/15; Scope 16). Ruff, whitespace, 26 producer pins, 10 independent
authority artifacts, static stamps, offline builds, 158/167 exact wheel sources,
and 19 browser archive inputs pass. Installed core checks pass on Python
3.11/3.12/3.13 with optional imports forbidden; installed model/proof,
authentication/upload, and browser checks pass outside the checkout.

Verification is local macOS evidence, not a Linux execution claim. Docker's
daemon socket was unavailable, so Linux runtime verification remains pending.
A first overlapping Scope build/test attempt failed because pytest discovered
the backend's temporary source-distribution tree, creating import mismatches
and racing archive collection of bytecode. That generated tree was moved to
the verification directory, retained rather than deleted. Sequential full tests
and a fresh offline build pass. Future workflow isolation remains a separate
improvement; this result does not claim the discovery collision was fixed.

Logs, built/installed packages, and retained failed-build artifacts:
`/private/tmp/lure-unix-20261104.LuV629`.
This is not atomic compare-and-unlink, protection from malicious same-UID or
privileged mutation, validation of directory ACLs/mounts, or termination of
already-running daemon workers. Uncertain setup or cleanup can leave an entry
for operator inspection. See [ownership and recovery boundaries](RUNTIME_AGENT_AUTHORIZATION.md#unix-socket-ownership-and-cleanup).
All changes from this milestone remain local and uncommitted; no push, release,
deployment, or schema/receipt-identity change occurred.

## Source-test reproduction and archive gates — 4 November 2026

The preceding concurrent build/test failure was reproduced with synthetic
generated package trees: default pytest discovery imported their `conftest.py`
in both repositories. Both default-discovery tests failed before configuration
changed, while explicit test selection already worked. Default discovery now
starts at `tests/`; documentation checks enumerate the reviewed first-party
roots rather than walking backend staging trees. Explicit paths still work.

A standard-library source checker now compares selected reproduction inputs to
the checkout without extracting or executing members. It requires the matching
package/version root and exact source bytes, rejects duplicates/noncanonical
paths, links/special/sparse entries and configured transient/credential filenames,
and caps compressed size, member size/count, and declared expanded bytes. It
checks 553 LureBench and 506 companion inputs, including test fixtures, scripts,
schemas, public documentation/assets and workflow definitions. This is not
publisher authentication, comprehensive secret scanning, or a parser sandbox
for arbitrary untrusted compressed input.

CI now runs the archive gate and the full suite from a locally built source
distribution outside the checkout. The existing read-only release build also
checks source and wheel contents before handing artifacts to publishing jobs;
no publishing permissions were added. CONTRIBUTING documents trusted-local-build
reproduction and the limits of default discovery/concurrent builds.

The companion archive audit found missing test fixtures/helpers, workflows,
public scorecard data and linked blog content. Its repaired archive passes the
full suite; its wheel now includes the scorecard JSONL, and negative wheel tests
enforce scorecard/pilot data bytes. Across both repositories this milestone adds
**82 tests** (40 producer, 42 consumer), covering default/explicit discovery,
documentation scope, missing/stale/duplicate/unsafe archive entries, size/count
budgets, source symlinks, corrupt archives, and workflow gate wiring.

Checkout suites: **2,411 passed, 40 skipped** in LureBench on Python 3.11 and 3.13;
**1,548 passed** in paired LureScope; browser **107 passed**. Distinct checkout
total: **4,066 passed**. From extracted archives: **2,405 passed, 46 skipped**
in LureBench and **1,548 passed** in LureScope. The six additional producer skips
are existing tests for deliberately unbundled `data/full` shards, not omitted
test modules; total collected cases are unchanged. Existing optional-reference
and dependency skips/warnings remain. Both producer and consumer imports were
confirmed to resolve inside the extracted source roots, using the provisioned
test environments rather than claiming a hermetic dependency installation.

The actual overlapping LureScope build/full-test run now passes. Ruff, whitespace,
offline lock consistency, 26 producer pins, 10 independent authority artifacts,
static stamps, 158/174 exact wheel inputs and 19 browser archive inputs pass.
Installed core checks pass on Python 3.11/3.12/3.13 with optional imports forbidden;
installed model/proof, authentication/upload and browser checks pass. The installed
scorecard sample matches the reviewed source bytes. No dependency versions changed.

Logs, source archives/extracted trees, wheels and isolated installation:
`/private/tmp/lure-source-20261104.qo1H9R`.
Results are local macOS execution evidence; the changed GitHub workflows have
not run remotely, and the prior Linux-runtime verification gap remains. All
new changes, including the preceding Unix lifecycle milestone, remain local
and uncommitted. No push, release, merge or deployment occurred in this milestone.

## Admitted OCI image identity and Linux verification — 4 November 2026

Both adapters previously inspected a local image ID but launched the original
reference later. Two real Docker reproductions failed: after a synthetic tag
was moved from image A to image B between construction and first use, the
detector returned B's score and the boundary monitor returned B's marker while
their recorded ID still named A. These were owned synthetic fixtures, not
third-party detectors or live attacks. An initial deterministic regression set
also failed 44 cases covering identity drift and invalid admission types.

The adapters now share local image inspection/validation and launch the admitted
full ID, including after a clean close/restart. A removed image fails without
tag fallback or implicit pulls. Podman's documented bare 64-hex `.Id` is
normalized to the existing prefixed evidence format and passed back to Podman
as a full native ID. Four additional pre-fix Podman contract cases failed.
Development opt-in requires an actual boolean; CPU/timeout values reject
booleans, wrong types, non-finite numbers, and oversized integers before
inspection. CLI report schemas and artifact digest bindings are unchanged.

The 89 new deterministic tests cover Docker/Podman command shapes, full ID
normalization, retag/restart behavior, removal without fallback, inspection
failure, malformed IDs, resource/override validation, and CI wiring. Existing
CLI schema tests now cover both runtimes' native inspection output. Two new
opt-in real Docker tests check response markers and daemon `.Image` for initial
execution and restart, then verify a newly admitted adapter selects B. Both pass
from the checkout and again from the installed wheel outside the checkout.
The existing container CI job now builds the synthetic fixtures and runs those
tests; remote CI has not run these unpushed changes. Two consumer regressions
confirm a same-name changed/omitted artifact cannot alter a bound evidence bundle.

Full checkout suites: **2,502 passed, 42 skipped** on Python 3.11 and 3.13;
paired LureScope **1,550 passed**; browser **107 passed**. Of the 42 producer
skips, 40 are the existing optional/reference skips and two are the opt-in Docker
tests, which passed separately. Across checkout Python/browser and explicit
Docker runs, **4,161 distinct tests pass**; this milestone adds 95 test cases.
Extracted archives pass **2,496/48** (producer passes/skips) and **1,550**
consumer tests; six additional producer skips cover deliberately unbundled
datasets. Existing dependency warnings remain; no dependency versions changed.

Docker Desktop 29.6.1 is now available. A cached Linux Python 3.11 image running
as UID/GID 65532, with no network, read-only source/test-dependency mounts,
dropped capabilities and temporary test storage, passes **242 focused tests**:
identity admission, real pipe deadlines, HTTP request-head limits, runtime
capacity, and all 54 Unix lifecycle tests. This closes the earlier Unix-platform
execution gap, not a claim that the entire optional-dependency suite ran on
Linux. The test runner reused pure-Python pytest dependencies; no model or
provider workload was run. Podman is not installed, so its actual runtime remains
unverified despite the documented-format and command-contract regressions.

Offline builds, unchanged locks, 558/506 exact source inputs, 159/174 wheel
inputs, 19 browser archive inputs, producer pins, independent authority artifacts,
static stamps and browser checks pass. Installed core checks pass on Python
3.11/3.12/3.13 with optional imports forbidden, now including both OCI adapters;
installed model/proof, auth/upload and browser checks pass as well.

Artifacts and logs: `/private/tmp/lure-oci-20261104.ySttcb`. Local synthetic
images were built from the cached base with a per-command legacy-builder setting
to avoid registry resolution; no global Docker settings changed. Tests remove
only their unique temporary aliases and ownership-checked containers; the two
fixture images are retained. No pre-existing image or container was deleted.
All new changes remain local and uncommitted. This is execution-target binding
under a trusted caller/runtime, not remote attestation, vendor authentication,
daemon containment, or retroactive repair of earlier mutable-tag evidence.
See [identity semantics and primary references](CONTAINER_DETECTORS.md#inspected-identity-is-the-execution-target).

## Ownership-checked daemon lifecycle — 4 November 2026

Four new real-Docker regressions failed against the prior cleanup: normal close
and response timeout, for each adapter, left a daemon workload behind after its
synthetic PID 1 was stopped with SIGSTOP. Reaping the attached CLI did not remove
that workload. The fixtures are owned synthetic protocol responders, not live
attacks or third-party models; their independent cleanup removed the leftovers.

Both adapters now create a uniquely named and labelled stopped container, verify
its full ID, admitted image, name and ownership marker, then attach/start by ID.
Close verifies ownership again, force-removes only the exact full ID and associated
anonymous volumes, and requires a successful absence query. It never removes by
name, prunes resources, or removes images/named volumes. A timed-out create with
no confirmed ID retains uncertain recovery state even when a lookup is empty;
a later close can clean a verified late arrival, but evaluation cannot resume.

Creation/verification and daemon cleanup each share a separate ten-second command
budget. CLI/pipe cleanup is attempted even after daemon-control failure. Original
startup, protocol and context exceptions retain priority, with recovery notes
when cleanup also fails. Concurrent adapter operations are refused before lazy
startup. The CLIs do not publish evaluation reports after uncertain teardown.

The new deterministic suite passes **82 cases**, covering Docker/Podman control
contracts, identity/ownership mismatch, malformed metadata, ambiguous lookup,
uncertain/late creation, interruption, control failures, false removal replies,
shared deadlines, retry-only cleanup, concurrency, context errors and both CLIs'
report suppression. Four added real-Docker tests cover SIGSTOP cleanup. All six
real-Docker tests, including the preceding tag-drift cases, pass from both the
checkout and the isolated installed wheel. One final verification attempt failed
at fixture inspection; a separate read-only inspection and a rerun succeeded.
That first error is retained in the logs; its underlying cause was not established.

Full checkout: **2,584 passed, 46 skipped** on Python 3.11 and 3.13; paired
LureScope **1,550 passed**; browser **107 passed**. Six producer skips are the
explicit Docker cases verified separately; 40 are existing optional/reference
skips. Combined distinct passed count is **4,247**. This milestone adds 86 cases.
Extracted-source suites pass **2,578/52** producer passes/skips and **1,550**
consumer tests; the six extra producer skips concern deliberately unbundled
datasets. Existing dependency warnings remain. Linux Python 3.11 passes all
**324 focused tests**, including the new lifecycle suite, with no network,
unprivileged execution, and read-only source/test-dependency mounts.

Offline builds and unchanged locks, 561/506 exact source inputs, 160/174 wheel
inputs, 19 browser archive inputs, 26 producer pins, 10 independent authority
artifacts and static stamps pass. Installed producer core checks pass Python
3.11/3.12/3.13 with optional imports blocked; installed consumer model/proof,
authentication/upload and browser checks pass. Post-test runtime queries found
no test-owned containers or temporary tag aliases; supplied fixture images and
unrelated resources remain untouched. Artifacts: `/private/tmp/lure-lifecycle-20261104.m2ySvP`.

These are trusted-runtime lifecycle checks, not hard wall-clock guarantees,
daemon-admin isolation, or remote cleanup attestation. Runtime connections must
remain stable; process/host failure still requires external supervision. Actual
Podman execution and remote CI remain unverified. No dependency version, report
schema, historical receipt, release or deployment changed. All new work remains
local and uncommitted; nothing was pushed in this milestone.

## Companion visualization dependency verification — 4 November 2026

The companion's approved GitHub lookup found 41 Pillow alerts whose fixed version
is 13.0.0. Its optional Matplotlib stack now requires that Pillow floor in the
`viz` extra and locks 13.0.0; only that dependency version changed. LureBench's
reviewed lock has no Pillow entry and was not modified. A companion wheel-metadata
check and an offline resolver rejection of `pillow<13` confirm the floor applies
to the built optional extra, without adding imaging to its default API graph.
No alert was dismissed, and this does not resolve the separate Accelerate issue.

Three manifest/graph/CI tests and three real synthetic rendering cases were
added to the companion. Its full paired suite passes **1,556 tests each** on
Python 3.11/3.12/3.13 in isolated locked dev/viz environments. Without visualization
dependencies, **1,553 pass and 3 intentionally skip**. These are compatibility
checks, not provider experiments, refreshed benchmark numbers, exploit tests or
claims about deployed systems. Source-only rendering helpers are tested from
the checkout and extracted source archive, not falsely claimed to ship in wheels.

Producer checkout passes **2,584/46** and extracted source **2,578/52** passes/skips;
the six extra archive skips concern unbundled datasets. Consumer extracted source
passes **1,556**, browser **107**. Distinct Python/browser passes total **4,247**,
excluding unchanged prior real-Docker checks and repeated interpreter runs.
Ruff, whitespace, offline builds/locks, 561/508 exact source inputs, 160/174 wheel
inputs, consumer pins/independence/static gates and installed checks pass. Producer
installed core still runs with optional imports forbidden. Existing warnings
remain. Artifacts: `/private/tmp/lure-pillow-20261104.TT0wcu`.
All new work remains local and uncommitted; no push, release, deployment, default
API-environment update or remote CI run occurred.

## Companion scorecard outcome accounting — 4 November 2026

LureScope's research scorecards now follow the producer's existing missing-outcome
semantics: abstentions remain unknown, incomplete eligible cohorts have a null
primary evasion rate with logical completion bounds, and no clean catches means
no rate. Invalid scores, missing result entries and ambiguous panels fail closed.
Counts and coverage are explicit in Markdown and gray masked chart cells. These
bounds are not confidence intervals; different clean-catch cohorts are not a
ranking of overall detector quality. Historical scorecards and provider caches
remain unchanged; the complete bundled sample retains its previous numeric rates.

The producer adds one exhaustive regression enumerating 121 outcome patterns and
all binary completions, with no production measurement change. The companion adds
64 outcome and two rendering cases; 39 baseline cases failed before its fix.
Producer checkout: **2,585 passed, 46 skipped**; extracted source: **2,579/52**,
including six extra unbundled-data skips. Companion final default suite:
**1,617 passed, 5 intentional viz skips**; final extracted-source dev/viz suite:
**1,622 passed**. Its focused selection passes **77** on Python 3.11/3.13, and its
browser suite **107**. Distinct Python/browser passes total **4,314**, without
multiplying interpreter repeats or adding unchanged earlier Docker runs.

Offline locks/builds, Ruff/whitespace, 561/511 exact source inputs, 160/175 wheel
inputs, browser packaging, pins, authority independence and static checks pass.
Installed producer core runs with optional imports forbidden; installed companion
model/proof, authentication/upload and browser checks pass. Its installed new
standard-library measurement helper passes with site packages disabled on Python
3.11/3.12/3.13. Final rebuilt wheels retain the tested member bytes; only verification
documentation changes in the final source archives. Existing warnings remain.
Artifacts: `/private/tmp/lure-scorecard-20261104.dEwJXf`.
No provider call, historical evidence rewrite, dependency update, push, merge,
release, deployment or remote CI run occurred. All new work remains local.

## Companion whole-file cohort admission — 4 November 2026

The consumer's scorecard loaders now validate the complete bounded regular-file
input before sampling; 62 regressions failed against the prior permissive paths.
The 107 new cases cover exact labels, ambiguous/non-finite JSON, excluded/trailing
records, selection parameters, resource limits, source/ordered-cohort commitments,
no-call preflight and preservation of outputs after failure. The producer's schema,
Hub loading, data, production code and evidence identities are unchanged here.

The consumer admits the existing 2,056-record core/test input and preserves both
loaders' record selection/order at limits 0, 1 and 120 (cross-model phishing cap 50).
Its new `--validate-corpus` command succeeds on the sample and core inputs without
provider calls. Counts and unsalted digests are not privacy protection, signatures,
label verification or a representative-sampling guarantee. Historical reports and
caches were not rewritten, and no new benchmark performance claim was produced.

Producer checkout passes **2,585/46**, extracted source **2,579/52** passes/skips.
Consumer checkout/extracted dev-viz suites pass **1,729**; default checkout
**1,724/5** passes/skips. Browser **107**; distinct paired Python/browser passes
**4,421**. Consumer focused scorecard checks pass **184** on Python 3.11/3.13.
Ruff/whitespace, offline locks/builds, 561/514 exact source inputs, 160/176 wheel
inputs, consumer pins/independence/static/browser gates and installed checks pass.
Its installed corpus helper runs with site packages disabled on 3.11/3.12/3.13.
Final wheel member bytes remain unchanged from the tested candidates; only
verification documents change in final source archives. Prior Docker tests were
not rerun and are not added to the count. Existing warnings remain.
Artifacts: `/private/tmp/lure-cohort-20261104.gTXhWV`.
No dependency updates, paid work, pushes, releases, deployments or remote CI runs
occurred; all new work remains local and uncommitted.

## Companion cache replay and push verification — 6 November 2026

The companion cross-model driver now starts its portable baseline correctly,
binds versioned score/paraphrase caches to declared experiment configuration and
implementation/runtime identities, and offers explicit no-key cache-only replay.
It rejects legacy/mismatched caches before provider construction, validates fresh
outputs, shares duplicate text work without dropping input observations, and
bounds parallel admission. Cache files publish independently with private atomic
replacement; this is not provider attestation, a multi-file transaction or a
concurrent-writer guarantee. No producer production code changed in this cache
milestone. The companion adds 77 cache cases; eight initial regressions failed
against its earlier implementation. Historical evidence remains unchanged.

Final producer checkout passes **2,585 with 46 skips**, and extracted source
**2,579/52** passes/skips, including six additional unbundled-data skips. Consumer
checkout and extracted-source suites pass **1,806** with visualization enabled;
browser **107**. Distinct paired Python/browser passes total **4,498**. Consumer
focused scorecard checks pass **261 each** on Python 3.11 and 3.13 against its
locked public producer. Existing warnings remain; no provider calls ran.

Ruff/whitespace, offline locks/builds, 561/517 exact source inputs, 160/177 wheel
inputs, consumer pins/independence/static/browser gates and installed checks pass.
Installed producer core runs with optional imports blocked; the new installed
consumer cache helper runs with site packages disabled on Python 3.11/3.12/3.13.
Final rebuilt wheels retain the tested member bytes; only verification documents
change in the final source archives. Prior Docker checks were not rerun or added
to these counts. Artifacts: `/private/tmp/lure-push-20261106.hj5OhJ`.

This is local pre-push verification of the accumulated feature-branch changes,
not evidence of a main-branch merge, release, deployment or remote CI success.
Earlier milestone notes describe their historical state. The continuous
improvement goal remains paused.
