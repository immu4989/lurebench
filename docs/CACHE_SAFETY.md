# Cache replay, concurrency, and cost safety (unreleased)

The source-branch cache implementation now fails before provider work when an
existing cache is malformed, unreadable, nonregular, a symlink, or larger than
64 MiB. Missing files start empty only in writable mode. Previously malformed JSON silently
started a new cache, potentially spending money to reproduce lost results.

Preserve a rejected cache. Restore a reviewed backup, or explicitly choose a
new path and budget for the resulting calls. There is no automatic destructive
repair or implicit paid retry of invalid cached scores/completions.

## Trained model identities

TF-IDF score caches now bind the scoring contract, task, ordered class labels,
exact loaded artifact SHA-256, and reported Python/scikit-learn/NumPy/SciPy/joblib
versions. Replacing a model under the same filename cannot silently reuse the
old model's scores. Identical bytes at another path keep the same identity under
the same runtime; reserialization or version changes conservatively change it.
This identity describes configuration, not identical floating-point behavior
across hardware or proof of the model's publisher, training data, or safety.

The loader captures a nonempty regular non-symlink file of at most **64 MiB**,
hashes that snapshot, and deserializes those same bytes. Optional
`expected_sha256=` must match before joblib loading. Use an independently trusted
expected digest when you need this check; calculating a digest of an untrusted
download does not establish trust. The file limit does not bound decompressed
memory, execution time, or arbitrary code run by joblib. Parent directories and
the model itself must be trusted; observed file changes are rejected, but this
is not a filesystem isolation mechanism.

Newly trained or injected in-memory pipelines need a reviewed lowercase SHA-256
`cache_context=` for **persistent** caching. The context must identify fitted
weights, preprocessing, custom code, and relevant numerical settings. It is a
caller assertion, not an automatic inspection. Alternatively, save a trusted
trained artifact and construct a new detector from that file to obtain its
byte-bound identity. Plain scoring and in-memory caching require no context.
Do not mutate a pipeline's parameters after wrapping it in a cache; construct a
new detector and cache identity for changed models.

Legacy name-only caches and caches for a different context fail without scoring
or rewriting the old file. Preserve them; deliberately select a new cache path
for a new experiment. For historical replay, use the original recorded identity
and do not label old observations as results from the new contract.

## Read-only replay without model construction

Use the exact detector display name, task, and (for context-bound scores)
`cache_namespace` from the trusted original experiment configuration:

```sh
lurebench cache-replay --dataset records.jsonl --cache scores.json \
  --detector-name 'original-display-name' --task fraud --plan
lurebench cache-replay --dataset records.jsonl --cache scores.json \
  --detector-name 'original-display-name' --task fraud --threshold 0.5
```

Add `--cache-namespace` with the original 64-character lowercase SHA-256
identity when applicable. This command constructs no live detector or provider;
it never fills missing entries or writes the cache. A missing file, invalid
relevant score, or incomplete replay stops evaluation with exit status 2.
`--plan` reports aggregate coverage, including duplicate texts and cached
abstentions; an incomplete but valid plan exits successfully. It neither emits
record text/identifiers nor increments hit/miss counters. Cached abstentions
remain missing measurements in the evaluation report, not negative decisions.

The cache does not authenticate its producer or validate the operator's chosen
task. Its identity must be obtained from trusted experiment records, not guessed.
Replay describes previously observed scores, not a fresh independent experiment.

Python users can construct `ReplayDetector(path, name=..., task=...,
cache_namespace=...)` and call `plan(records)` or use the normal harness.
`CachedDetector(..., cache_only=True)` and
`cached_complete_fn(..., cache_only=True)` similarly prohibit callbacks on
misses, but cannot undo side effects incurred while constructing their supplied
detector/provider. Prefer `ReplayDetector` for provider-free score replay.

## Bounded admission for new work

`CachedDetector`, `CompletionCache`, and `cached_complete_fn` accept
`max_new_calls=N`. The shared `JsonDiskCache` exposes the same control as
`max_computations=N`. Only nonnegative integers or `None` (unlimited) are accepted.
Admission is atomic across threads within one cache instance: hits and concurrent
same-key followers consume no additional units. Failed computations and empty
uncached completions consume their admitted unit; budgets are not refunded.
Zero permits existing hits only. Exhaustion raises `ComputationBudgetExceeded`
before invoking another callback. `prewarm` checks existing selected cache values
before new work, permits at most `workers` outstanding tasks, and stops further
admission after a worker failure. It cancels queued tasks where possible, waits
for already-running callbacks, and then flushes completed work before propagating
the failure. Running callbacks cannot be cancelled or refunded by this scheduler;
see [Python executor shutdown semantics](https://docs.python.org/3/library/concurrent.futures.html#concurrent.futures.Executor.shutdown).
Provider timeouts must bound callbacks that could otherwise hang. Controls are
strict integers: 1–128 workers and a nonnegative progress interval; zero disables
progress output. The complete dataset is validated and copied, including nested
metadata, before scheduling. Mutations through callback records do not propagate
to caller-owned records; this is not a sandbox or an atomic concurrent snapshot.

This is a **callback count, not a provider request, token, or dollar cap**.
Internal retries may issue multiple requests. Limits reset with a new instance,
are not shared across processes, and do not constrain constructor side effects.
Configure billing controls with the provider separately. Coverage plans count
unique missing score keys, not the cost of obtaining them.

`cache-replay --decision-counts` exports a compact versioned six-outcome report
for LureScope's offline review-capacity planner. Unlike a confusion matrix alone,
it preserves positive/negative abstentions. The task, detector name, and threshold
are explicit; LureScope rejects provenance-task exports for fraud planning. The
format is [decision-counts.schema.json](../spec/decision-counts.schema.json).

## Concurrent requests and persistence

- Concurrent same-key requests share one computation **within one cache
  instance**; distinct keys remain concurrent. A cached detector abstention is
  a real result. Empty completion strings are not persisted.
- Computation failures are shared with current waiters but not cached; a later
  explicit request can retry. Persistence failures are different: a successfully
  computed value remains in memory even if its automatic flush raises. Cache
  hit/miss counters include coalesced requests and do not constitute a provider
  billing ledger.
- Flush snapshot capture and file replacement are serialized. An older flush
  cannot overwrite a later snapshot from the same instance.
- Temporary files are uniquely created with owner-only permissions, flushed
  and fsynced, then atomically replaced. Before replacement, the exact staged
  bytes must pass the same strict JSON parser used at restart. Ambiguous keys
  after JSON coercion and nesting beyond 128 containers cannot replace a valid
  cache. Failed writes preserve the previous destination and pending work.
- `cached_complete_fn` persists each nonempty successful response, including
  runs shorter than the former 25-response flush interval. Direct
  `CompletionCache` and `CachedDetector` users must still call `flush()` when
  using batched persistence.

Use one owning cache instance per file in a process and trusted parent
directories. There is no cross-process/file-owner coordination, distributed
lock, complete path-ancestry protection, or guarantee of recovery after power
loss. Multiple instances writing the same path can still overwrite each other.
An API response received immediately before a process crash may still need
another call if it was not persisted.

## Recovering from a failed flush

`CacheWriteError` (a `ValueError`) means the in-memory snapshot cannot be written
as bounded, restart-readable JSON. Its message omits private nested keys. Keep
the existing file and cache instance. Correct an invalid value deliberately or
resolve the storage problem, then call `flush()` again; do not discard the cache
and start an implicit paid rerun. A cache hit after a failed automatic flush does
not itself retry persistence. The retained result must still be flushed before
process exit, and callbacks already running for other keys are not cancelled.

The writer reads at most 64 MiB plus one byte from its staged file and parses
those bytes before replacement. This adds read/parse work and transient memory
to each flush; it is not a 64 MiB bound on Python heap use. Valid JSON coercions
remain compatible (for example tuples reload as lists and integer object keys
as strings). Successful serialization does not promise Python type identity or
an atomic snapshot of nested objects that callers mutate concurrently.

## Research interpretation

A cache replays one observed result. It does not prove that an uncached model
is deterministic, even at temperature zero. Do not count replayed responses as
independent replicates. Keep separate cache files for distinct providers,
configurations, prompts, and replicate identities unless the cache key explicitly
binds those differences. Scores and generated text can be sensitive; a hash key
does not anonymize the stored response.

Completion-cache inputs containing NUL separators are rejected before provider
work, preventing ambiguous legacy prompt-key framing without silently changing
ordinary existing cache keys. LLM score caches additionally bind their strict
parser and provider configuration; see [detector outcomes](DETECTOR_OUTCOMES.md).

Tests use synthetic providers only: coalescing success/failure, independent-key
concurrency, stale-flush ordering, malformed input, write failures, permission
restrictions, and one-response restart replay. No paid requests are needed.
