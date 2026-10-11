# Strict dataset intake and atomic output (unreleased)

Benchmark labels and provenance should fail validation before expensive scoring.
`load_jsonl` and `iter_jsonl` now use the same bounded strict JSONL parser:

- Reject duplicate JSON object keys, including nested metadata keys, nonstandard
  `NaN`/`Infinity`, overflowing numeric literals, and nesting above 128 containers.
- Require object records and correctly typed core fields. Labels are binary
  integers, not booleans, floating-point values, or strings. Metadata is an
  object; persuasion is a list of strings. IDs are nonempty strings of at most
  512 characters without control characters. Core text fields reject lone
  Unicode surrogates rather than failing later during cache-key encoding.
- Read only opened regular files, with nonblocking open where supported to avoid
  waiting on a FIFO. Bound each line and the complete file, including comments,
  whitespace, and newline bytes. Completed iteration checks for observed size or
  timestamp changes to the opened file.
- Report the failing line number without repeating its content or metadata keys.

Defaults are **256 MiB per file and 32 MiB per line**. The latter preserves known
historical public-corpus records above 16 MiB; it is not a recommended model
context size. Scoring/model limits are separate. Python callers can explicitly
choose positive integer `max_bytes` and `max_record_bytes` on either loader and
on `save_jsonl`. The CLI uses defaults. Shard larger corpora or use the Python
API with reviewed limits; bounds are never silently disabled.

Empty files, blank lines, `//` comment lines, Unicode text, and unknown top-level
extension fields remain compatible. Unknown top-level fields are ignored as
before; put information that must survive a round trip in `meta`. The loader
does not silently deduplicate IDs or texts, resolve contradictory annotations,
or validate scientific provenance. Use manifests, leakage audits, and review.

## Streaming and filesystem limits

`iter_jsonl` yields records as they are parsed. A caller that scores immediately
can spend money before discovering a later invalid line or final file-change
check. Use `load_jsonl` to finish validation before expensive work. Neither
interface authenticates the file's producer or provides an atomic filesystem
snapshot. A stable open descriptor can refer to the original file even if its
pathname is replaced; trust and manage parent directories.

Unlike signed-evidence intake, dataset reads intentionally support symlinks to
regular files because local Hub caches use them. This is not a confinement or
path-ancestry security boundary. No downloads or provider calls occur in parsing.

## Exact source commitments

`load_jsonl_with_digest` returns validated records and a SHA-256 digest from the
same bounded read. Container evaluation and core-v2 corpus construction use it
instead of hashing a file and reopening it for parsing. Validation finishes
before container startup or corpus gating.

```python
from lurebench.schema import load_jsonl_with_digest

records, source_sha256 = load_jsonl_with_digest("reviewed-source.jsonl")
```

The digest includes every source byte: comments, blank lines, unknown extension
fields, and original line endings. It is not a digest of normalized or
reserialized records. Empty or comment-only files have a digest but no records;
container evaluation rejects them before starting its runtime.

Unlike the Hub-compatible loaders above, this loader rejects source symlinks and
an immediate symlink parent. It checks the opened file's identity against the
path before reading and again after closing, in addition to the shared byte and
timestamp checks. Keep parent directories trusted: these checks detect observed
changes, not every possible filesystem race, and do not authenticate provenance
or provide an atomic snapshot across multiple corpus sources. Returned records
remain mutable; their source digest does not commit later in-memory edits.

## Atomic writes

`save_jsonl` validates even mutated dataclasses, writes strict finite JSON to a
private temporary file in the destination directory, flushes/fsyncs it, and only
then atomically replaces the destination. An invalid record, iterator exception,
serialization error, byte-limit violation, or failed replacement leaves previous
destination bytes intact and cleans the temporary file. Outputs may not be
symlinks or nonregular files. The immediate parent may not be a symlink.

Trust parent directories and use one writer per destination. There is no
cross-process lock, universal path-race protection, or power-loss durability
guarantee. Replacement changes the inode and uses owner-only file permissions;
set sharing permissions explicitly after review if needed. No historical corpus
has been rewritten by this implementation change.
