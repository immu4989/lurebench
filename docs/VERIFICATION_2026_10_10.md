# Local verification on 10 October 2026

Unreleased changes based on `a501504cec002ffbaff810742e14e2dd002ed543` update the
optional urllib3 lock from 2.7.0 to 2.8.0 and add a uv resolution floor. At
verification time, the changes were local and uncommitted; the default branch,
published packages, and remote security alerts were unchanged.

The upstream advisories identify 2.8.0 as the patched release for
[unbounded chunk-size-line buffering](https://github.com/advisories/GHSA-vxq7-64xx-v4gw)
and the [chunked Deflate loop](https://github.com/advisories/GHSA-gh4c-6fx4-qh6g).
Only urllib3 changed version during lock resolution. The existing HTTPX2 floor
remains, and the core harness still has no required third-party dependencies.

## Results

| Check | Result |
| --- | --- |
| Offline uv lock consistency | Passed across 120 resolved packages |
| HTTPX2 and urllib3 floor tests | Both passed; all matching lock entries checked |
| Full suite with temporary urllib3 2.8.0 ahead of the development environment | 1,438 passed, 39 skipped, 9 warnings |
| Ruff and Git whitespace checks | Passed |

The compatibility run verified the imported version and temporary package path
before running tests. It did not replace packages in the existing development
environment. Thirty-six skips concern the optional Safetensors reference reader,
two require unavailable full corpus shards, and one concerns missing schemas in
the installed STIX validator. Existing solver-option and joblib/NumPy warnings
remain. Passing these tests is not a complete runtime reachability assessment.

The uv floor does not constrain independently resolved pip environments or upgrade
existing installations. Consumers need to update their own affected HTTP stack.
The optional Accelerate advisory still lists no patched release and remains
unresolved; see [dependency security](DEPENDENCY_SECURITY.md). No alerts were
dismissed, no provider endpoints were called, and no models were downloaded.

## Detector container protocol follow-up

Local changes based on `624a3e2` address two reproduced protocol weaknesses:
duplicate `score` keys previously selected the last value, and the reader checked
the size limit only after reading an unbounded line. Response intake now uses a
bounded text read, applies the exact 64 KiB UTF-8 limit before JSON decoding,
requires one newline-terminated record, and rejects duplicate keys, nonfinite
numbers, and excessive JSON nesting. Protocol errors fail evaluation instead of
becoming abstentions.

The follow-up suite passed **1,462 tests**, with the same 39 skips and 9 warnings,
using temporary urllib3 2.8.0. All 29 container-detector tests passed, including
an actual local subprocess pipe that emits oversized unterminated output and
stays alive, exact byte boundaries with multibyte text, duplicate escaped keys,
huge integer scores, and CLI failure without a report. The pipe check does not
exercise Docker/Podman isolation. Ruff and whitespace checks passed.

The rebuilt wheel matched 153 exact source files. Installed-wheel smoke checks
outside the checkout passed valid scoring and malformed-response rejection, plus
the existing panel replay/alteration check with optional imports blocked. The
response timeout at that checkpoint still started after request writes and did
not bound blocked input writes or teardown; the next section records the fix.
Follow-up changes remained
local at verification time, with no provider calls, image pulls, or release.

## Container deadline follow-up

A child that never consumed stdin kept a 1 MiB request blocked beyond one second,
despite a configured 0.1-second timeout. Both OCI adapters now share one deadline
for request writes, flushes, and bounded response reads. Cleanup stops the local
runtime CLI before closing pipe streams, uses bounded termination/reaping and
worker-join waits, and surfaces incomplete cleanup. Failed sessions cannot restart
implicitly; malformed request serialization occurs before runtime startup.
Both CLIs now finish runtime cleanup before printing or saving evaluation
reports, with regression checks that neither report nor success output appears
when cleanup fails.

Real local-pipe tests cover blocked writes, silent readers, sequential roundtrips,
invalid UTF-8, interruption, invalid protocol output, and a child ignoring SIGTERM.
Deterministic tests cover shared write/flush budgets, concurrent-exchange rejection,
unreaped processes, blocked-worker cleanup, and retaining failed cleanup handles
without allowing further scoring. These checks do not establish OCI isolation.

The final full suite passed **1,486 tests**, with 39 existing skips and 9 existing
warnings, using temporary urllib3 2.8.0. The 56 focused container tests, Ruff, and
Git whitespace checks passed. LureScope was unchanged during this follow-up;
its MIME-limit verification is recorded in that repository.

The rebuilt wheel matched **154 source files**, including the shared I/O module.
An installed-wheel check from outside the checkout under `python -I -S` enforced
the blocked-write timeout and closed both streams after reaping the child. Final
installed checks also exercised both actual adapter classes with real subprocess
pipes and verified their failed-session guards, not just the shared helper. The
installed panel replay/alteration check also passed with optional imports blocked.
Docker's local daemon socket was absent, so no new Docker/Podman run was performed.
Startup, serialization, OS scheduling, and daemon-owned container cleanup still
require external supervision; this is not a hard real-time or sandbox guarantee.

## Dataset source commitment follow-up

A deterministic file replacement between the former hash and parse opens
reproduced a mismatch between the source digest and consumed records. Container
evaluation and core-v2 corpus construction now validate and hash the same bounded
byte stream. The committed loader rejects symlinks and observed identity or
metadata changes; ordinary Hub-compatible loading retains symlink support.

The full suite passed **1,519 tests**, with 39 existing skips and 9 existing
warnings, using temporary urllib3 2.8.0. All **33 new commitment tests** passed:
both consumer paths, exact raw-byte hashing, limits, malformed late records,
single-open behavior, nonregular files, descriptor cleanup, and source mutation
or replacement during reading and closing. Invalid and empty datasets fail
before container startup. Ruff and whitespace checks passed.

The offline wheel matched **154 exact source files**. Fresh installed checks
outside the checkout under `python -I -S` passed exact-byte hashing, core-v2
commitment binding, symlink rejection, and panel replay/alteration rejection.
These checks do not authenticate dataset provenance, freeze returned mutable
records, or establish an atomic filesystem or multi-source snapshot. The local
0.11.0 build is a verification artifact, not a new published release.
