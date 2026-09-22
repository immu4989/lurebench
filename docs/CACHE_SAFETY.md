# Cache replay, concurrency, and cost safety (unreleased)

The source-branch cache implementation now fails before provider work when an
existing cache is malformed, unreadable, nonregular, a symlink, or larger than
64 MiB. Missing files still start empty. Previously malformed JSON silently
started a new cache, potentially spending money to reproduce lost results.

Preserve a rejected cache. Restore a reviewed backup, or explicitly choose a
new path and budget for the resulting calls. There is no automatic destructive
repair or implicit paid retry of invalid cached scores/completions.

## Concurrent requests and persistence

- Concurrent same-key requests share one computation **within one cache
  instance**; distinct keys remain concurrent. A cached detector abstention is
  a real result. Empty completion strings are not persisted.
- Failures are shared with current waiters but not cached; a later explicit
  request can retry. Cache hit/miss counters include coalesced requests and do
  not constitute a provider billing ledger.
- Flush snapshot capture and file replacement are serialized. An older flush
  cannot overwrite a later snapshot from the same instance.
- Temporary files are uniquely created with owner-only permissions, flushed
  and fsynced, then atomically replaced. Failed writes preserve the previous
  destination and leave pending work available for a later flush.
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
