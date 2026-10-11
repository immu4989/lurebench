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

Cleanup signals the local runtime CLI before closing its pipes, waits up to one
second, escalates to kill with another one-second wait, and waits at most one more
second for the I/O worker. Those cleanup waits are additional to `--timeout`.
An unreaped process or still-blocked worker raises an explicit cleanup error;
the failed instance retains its handle for another cleanup attempt, not scoring.
The detector and boundary-monitor CLIs finish cleanup before printing or writing
evaluation reports. Cleanup failure leaves no new report and exits nonzero.
See Python's [subprocess lifecycle rules](https://docs.python.org/3/library/subprocess.html).

Serialization, runtime startup, OS scheduling, and daemon-managed containers are
not covered by a hard wall-clock guarantee. Stopping the CLI does not establish
that the daemon removed its container: `--rm` applies when the container exits.
Use an external job deadline and runtime-level lifecycle supervision, especially
for processes that ignore termination or descendants that retain pipes. The
evaluator is a sequential protocol client, not a multi-tenant execution service.

This substantially narrows the interface; it is not a VM or a proof of perfect
isolation. The JSON evaluation record preserves the runtime image ID, dataset
SHA-256, isolation settings, task, threshold, abstentions, and metrics. Its
strict schema is [`spec/container-evaluation-v1.schema.json`](../spec/container-evaluation-v1.schema.json).

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
