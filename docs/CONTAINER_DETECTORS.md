# Evaluate a private detector without integrating its code

`lurebench container-eval` gives vendors, agencies, and researchers a small,
language-independent benchmark boundary. A detector can remain proprietary and
use any implementation language. LureBench sends one JSON object per line and
receives one score; it never shares the answer key with the container.

## Privacy and anti-cheating boundary

The request contains exactly these fields:

```json
{
  "protocol": "lurebench-detector-v1",
  "request_id": "request-00000001",
  "task": "fraud",
  "text": "Review the attached invoice.",
  "language": "en",
  "channel": "email"
}
```

The original record ID, fraud label, human/AI provenance, typology, generator,
persuasion tags, source metadata, and dataset path are withheld. `request_id` is
an opaque per-run sequence and cannot be joined to corpus IDs.

The response must be either a score:

```json
{"protocol":"lurebench-detector-v1","request_id":"request-00000001","score":0.82}
```

or an explicit abstention:

```json
{"protocol":"lurebench-detector-v1","request_id":"request-00000001","score":null,"abstain":true}
```

Each response must end with a newline and fit within **64 KiB of UTF-8**, including
that newline. The reader stops after at most 65,537 decoded characters instead of
waiting for an unbounded line; the exact byte limit is then checked before JSON
decoding. This character cap is not a claim that the text reader allocates only
64 KiB: multibyte characters and buffering also consume memory.

Unknown fields, duplicate keys (including escaped spellings), non-finite values,
JSON nesting beyond 128 containers, scores outside `[0,1]`, mismatched request IDs,
invalid UTF-8, oversized output, and response timeouts fail the run. Abstentions
are excluded from metrics and reported as `n_skipped`; always inspect that count.
Protocol errors do not count as abstentions. The CLI exits with an input/runtime
error and does not write a successful evaluation report. Existing integrations
that omit a trailing newline or repeat fields must correct their output.

## Runtime isolation

Images are local and, for reportable runs, must use
`name@sha256:<digest>`. LureBench will not pull an image. It invokes Docker or
Podman with:

- no network;
- no host mounts or injected environment variables;
- a read-only root filesystem and a small `noexec,nosuid` temporary filesystem;
- all Linux capabilities dropped and `no-new-privileges` set;
- memory, CPU, and PID limits, plus a shared request/response I/O deadline.

`--timeout` now covers writing the request, flushing it, and reading the response
together. A child that never consumes stdin cannot bypass the deadline. Failed
exchanges and malformed responses permanently invalidate that adapter instance;
create a new detector for a deliberate new run, rather than retrying a failed
session and risking acceptance of an old response.

The adapter creates a stopped container with a unique name and ownership label,
then verifies its full container ID, admitted image ID, name and ownership marker
before starting an attached, interactive session. It no longer depends on
`docker run --rm` or CLI termination to remove a daemon-managed workload.

Cleanup rechecks those ownership fields, force-removes **only that full container
ID**, and confirms its absence with a successful runtime query. This is immediate
workload termination (SIGKILL), not a graceful application checkpoint. Associated
anonymous volumes are removed; images, named volumes, and unrelated containers
are not targets. No prune, broad removal filter, name-based removal, daemon socket
mount, or shell command is used. An already-absent known ID is safe to close;
a different container reusing its name is never adopted.

Creation/identity verification share a **10-second control-command budget**;
daemon cleanup has a separate shared 10-second budget. CLI/pipe cleanup is still
attempted when daemon cleanup fails: signal the CLI, wait up to one second,
escalate to kill with another one-second wait, then wait at most one more second
for its I/O worker. These budgets are additional to the request/response timeout.
An unreaped CLI or still-blocked worker is also an explicit cleanup error.

Malformed or ambiguous runtime metadata, daemon errors/timeouts, ownership
mismatch, or unconfirmed removal fail closed. A timed-out creation can complete
later at the daemon: an empty lookup is **not** proof of successful cleanup when
no container ID was confirmed. The failed adapter retains its unique recovery
name/marker and handles; a later `close()` may clean a verified late arrival,
but scoring cannot resume. Errors name the recovery container. The original
protocol/startup/context exception is preserved with a cleanup note if cleanup
also fails. Concurrent adapter operations are rejected before lazy startup;
callers must coordinate completion before attempting cleanup again.

The detector and boundary-monitor CLIs finish cleanup before printing or writing
evaluation reports. Failed or uncertain cleanup leaves no new report and exits
nonzero. See Docker's [create](https://docs.docker.com/reference/cli/docker/container/create/),
[start](https://docs.docker.com/reference/cli/docker/container/start/), and
[removal](https://docs.docker.com/reference/cli/docker/container/rm/) semantics,
[Podman removal](https://docs.podman.io/en/latest/markdown/podman-rm.1.html), and
Python's [subprocess lifecycle rules](https://docs.python.org/3/library/subprocess.html).

These checks require a stable, trusted runtime/daemon connection and calling
process. Do not change Docker contexts, connection settings, or runtime stores
mid-run. Serialization, process creation, OS scheduling and daemon behavior are
not covered by a hard wall-clock guarantee. Process death, host failure or a
compromised daemon can still leave uncertain resources; use an external job
supervisor and inspect the reported ownership marker after such failures. The
ownership label is not remote attestation or protection against daemon admins.
The evaluator is a sequential client, not a multi-tenant execution service.

This substantially narrows the interface; it is not a VM or a proof of perfect
isolation. The JSON evaluation record preserves the runtime image ID, dataset
SHA-256, isolation settings, task, threshold, abstentions, and metrics. Its
strict schema is [`spec/container-evaluation-v1.schema.json`](../spec/container-evaluation-v1.schema.json).

### Inspected identity is the execution target

Both detector and boundary-monitor adapters resolve the local image once at
construction, then launch **that full image ID**, not the supplied tag. The
original `image_reference` remains a provenance label; `image_id` is the admitted
execution target. Retagging between inspection and first use, or between close
and restart, cannot select another image. If the admitted image disappears, the
run fails without pulling, re-resolving, or falling back to the current tag.
A new adapter deliberately performs a new admission.

Docker's prefixed ID and Podman's documented full bare-hex ID are handled without
shortening either. Reports keep the existing `sha256:<64 lowercase hex>` form;
the boundary evaluation's `monitor.artifact_sha256` contains the same 64 hex
characters without the prefix. There is no receipt/schema migration.

`--allow-mutable-image` remains a development-only opt-in, not permission for an
image to drift during a run. Python callers must pass an actual boolean, not
`"false"`, `1`, or other truthy objects. CPU/timeout settings require bounded
non-boolean real numbers; invalid types, non-finite numbers, and oversized
integers fail before image inspection.

The runtime, daemon connection/image store, and calling process remain trusted.
This is not remote attestation, protection against a compromised daemon, or
vendor authentication. A local image ID is not interchangeable with a registry
manifest/index digest: do not turn `.Id` into `name@sha256:...`. The current
[OCI specification](https://github.com/opencontainers/image-spec/blob/main/config.md#imageid)
explicitly leaves ImageID interpretation to implementations. See also
[Docker's ID/digest distinction](https://docs.docker.com/reference/cli/docker/image/ls/#list-image-digests---digests)
and [Podman's inspection format](https://docs.podman.io/en/latest/markdown/podman-image-inspect.1.html).

Earlier mutable-tag runs may have executed a different image than the recorded
ID if a tag moved after inspection. A hash/signature on such a report cannot
repair that provenance gap. Re-run affected evidence with the fixed producer;
do not silently rewrite historical reports or preregistered plans.

The dataset digest comes from the same bounded read that validates the evaluated
records, including comments and original line endings. Invalid, empty, symlinked,
or observably changed sources fail before runtime startup. This commits source
bytes, not their provenance; see [dataset intake](DATASET_INTAKE.md#exact-source-commitments)
for filesystem and mutability limits.

## Run the reference implementation

```bash
docker build -t lurebench-reference-detector:local examples/container-detector

# Mutable tags are allowed only for local development.
lurebench container-eval \
  --dataset data/samples/lures.jsonl \
  --image lurebench-reference-detector:local \
  --allow-mutable-image \
  --out container-evaluation.json
```

For a reportable run, push or archive the image through your normal controlled
process, resolve its digest, and pass the digest-qualified reference. The runtime
still uses only the already-present local image.

## What a score does and does not establish

The contract prevents direct label leakage and makes the executable identity
auditable. It does not prove that a benchmark resembles deployment traffic,
that a vendor did not previously train on public test data, or that local kernel
isolation is flawless. Use a private held-out split for procurement or assurance,
preserve the report, and publish abstention and uncertainty alongside accuracy.
