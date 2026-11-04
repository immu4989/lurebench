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
