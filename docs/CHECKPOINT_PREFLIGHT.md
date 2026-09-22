# Offline checkpoint preflight (unreleased)

Inspect an already-local sharded Safetensors checkpoint before considering a
model load. This command opens no network connections, imports no model
frameworks, and never executes checkpoint code or interprets tensor values.

```sh
lurebench checkpoint-inspect /trusted-parent/checkpoint \
  --max-bytes 1073741824 --out checkpoint-inspection.json
```

The output must be a new file; it is created with owner-only permissions.
Exit 0 means the inspected files passed this **bounded structural profile**.
Exit 2 means rejection or an I/O error, not a finding of malicious intent.
Use `--json` to print the deterministic report. CLI rejection messages omit
private tensor names and paths. The report includes shard basenames, sizes,
SHA-256 hashes, counts, limits, and explicit limitations, but no tensor names
or absolute source paths. Basenames and hashes can still be sensitive.

## What is checked

- A bounded `model.safetensors.index.json` with exact shard/tensor membership.
- Portable ASCII shard basenames, without paths, traversal, reserved device
  names, or case-insensitive aliases.
- Directory-relative, no-follow opens on POSIX; regular files only. Symlinks,
  directories, and FIFOs are rejected without waiting on FIFO writers.
- Bounded header lengths before allocation; strict JSON without duplicate keys.
- Supported byte-aligned dtypes; exact shape/byte relationships; contiguous
  tensor ranges without holes, overlaps, or unindexed suffixes.
- Aggregate shard bytes (32 GiB default; configurable up to 1 TiB), at most
  1,024 shards, 100,000 indexed tensors, 4 MiB index, and 8 MiB per header.
- Full shard and header hashes; file identity checks during and after reading.

This deliberately narrower profile supports BOOL, signed and unsigned integers
of 8/16/32/64 bits, F16/BF16/F32/F64, F8_E4M3, and F8_E5M2. Rank is limited to
32 and each dimension to 2^31−1. Scalars and zero-length tensors are supported;
empty shards and sub-byte dtypes are not. Some valid Safetensors checkpoints
therefore fail this profile. Single-file unindexed checkpoints are not supported.

## Trust boundary

Use a trusted parent directory and a read-only snapshot that cannot be mutated
by another actor. File identity checks detect many changes, but are **not an
atomic snapshot or a guarantee about what a later loader will open**. A later
loader must consume the same protected bytes; this tool does not enforce that.

A pass is not model safety, publisher authentication, provenance verification,
or deployment authorization. Tensor values, tokenizer/configuration files,
custom code, and unreferenced files are not inspected. Hashes alone authenticate
nobody. A report is an unsigned claim unless independently reproduced against
the checkpoint and compared with a separately trusted artifact manifest.

For byte-preserving transfers, the companion source-branch
[`lurescope checkpoint-verify`](https://github.com/immu4989/lurescope/blob/feat/lurepermit-lurerange/docs/CHECKPOINT_VERIFICATION.md)
requires a separately approved SHA-256 of the exact report bytes, validates
report accounting, and rehashes the recipient's files. It imports no producer
code, but trusts the pinned report's structural inspection; it is not a second
Safetensors parser. The linked documentation is available after this branch is pushed.

This is not a fix for the unresolved Accelerate advisory. Keep library updates,
least privilege, offline loading, and resource isolation as separate controls;
see [dependency security status](DEPENDENCY_SECURITY.md).

## Verification

The tests cover malformed shapes, offsets, duplicate JSON, shard membership,
path aliases, symlinks/FIFOs, byte budgets, and mutations. An optional reference
suite compares supported layouts against the actual Safetensors reader without
loading tensors or downloading model weights:

```sh
uv run --with safetensors==0.8.0 pytest -q tests/test_checkpoint_reference.py
```

Protocol references: [Safetensors format](https://github.com/safetensors/safetensors/blob/main/README.md)
and [Accelerate checkpoint-path report](https://github.com/huggingface/accelerate/issues/4067).
