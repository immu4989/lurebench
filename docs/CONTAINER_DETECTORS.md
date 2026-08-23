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

Unknown fields, non-finite values, scores outside `[0,1]`, mismatched request IDs,
invalid UTF-8, oversized output, and response timeouts fail the run. Abstentions
are excluded from metrics and reported as `n_skipped`; always inspect that count.

## Runtime isolation

Images are local and, for reportable runs, must use
`name@sha256:<digest>`. LureBench will not pull an image. It invokes Docker or
Podman with:

- no network;
- no host mounts or injected environment variables;
- a read-only root filesystem and a small `noexec,nosuid` temporary filesystem;
- all Linux capabilities dropped and `no-new-privileges` set;
- memory, CPU, PID, and per-record time limits.

This substantially narrows the interface; it is not a VM or a proof of perfect
isolation. The JSON evaluation record preserves the runtime image ID, dataset
SHA-256, isolation settings, task, threshold, abstentions, and metrics. Its
strict schema is [`spec/container-evaluation-v1.schema.json`](../spec/container-evaluation-v1.schema.json).

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
