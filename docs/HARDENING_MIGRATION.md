# Source-branch hardening: migration and verification

These changes are **unreleased**. They are not in the existing PyPI 0.11.0
distribution, and local test wheels retaining that version are not release builds.
Do not silently replace historical results with measurements from this new contract.

## What changes for researchers

Moderation now rejects incomplete or malformed category results without
converting the boolean flag into a score. Its reviewed profile requires all 13
current categories; alternative taxonomies are not implicitly accepted. New
context-bound caches reject legacy names-only scores. Review the
[moderation contract](DETECTOR_OUTCOMES.md#moderation-category-contract), retain
historical evidence, and deliberately choose new cache paths for new evaluation.
When serving through LureScope, deploy the updated companion adapter as well;
upgrading the service alone does not replace an older installed LureBench parser.

Loading a trained TF-IDF artifact now preserves its saved task. An explicit
`task=` must match rather than relabel the model, and missing metadata or classes
other than the integer pair 0/1 are rejected. Full probability rows are validated
before selecting the positive column. Review the
[trained-model contract](DETECTOR_OUTCOMES.md#trained-binary-classifier-semantics)
before loading legacy artifacts; this does not make joblib deserialization safe
for untrusted files. Training/saving already emits the required task metadata.

TF-IDF persistent caches additionally bind exact loaded model bytes and runtime
versions. Legacy name-only or different-model caches stop without a new score or
overwrite. Choose a new cache path deliberately. In-memory trained/injected
pipelines need a reviewed `cache_context=` for persistence, or save and reload a
trusted artifact to obtain its byte-bound identity. Model intake now requires
a nonempty regular non-symlink file of at most 64 MiB; optional
`expected_sha256=` rejects a mismatch before deserialization. See
[trained-model cache identities](CACHE_SAFETY.md#trained-model-identities) for
the exact identity, rotation procedure, and trust/decompression limits.

Binoculars no longer imports and constructs its upstream backend by default.
Use a reviewed backend or deliberate `allow_unsafe_upstream=True` in an isolated
research environment. Invalid raw scores now raise; over-length inputs abstain
instead of being silently truncated. Persistent score caches require a reviewed
backend context and a new cache path. The retained linear output is a provenance
proxy, not calibrated probability; see [the full migration contract](DETECTOR_OUTCOMES.md#binoculars-provenance-baseline).

| Area | New behavior | Operator action |
| --- | --- | --- |
| Dataset intake | Strict JSON/field types, bounded regular-file reads, atomic validated writes | Review [dataset compatibility and limits](DATASET_INTAKE.md); finish validation before paid work |
| Replay and comparison | No provider construction for explicit cache-only CLI workflows | Use [cache replay](CACHE_SAFETY.md) and [paired comparisons](PAIRED_COMPARISON.md) with trusted original identities |
| Leakage audit | Complete candidates at zero threshold and for empty shingle sets | Review [the audit's exact meaning](LEAKAGE_AUDIT.md); old frozen corpora are not regenerated |
| Missing detector scores | Abstention is not a benign prediction, evasion, or confident detection | Handle `DetectorAbstainedError`; inspect answer coverage and missing-outcome bounds |
| Harness inputs | Validated per-record copies and separately captured IDs/targets precede callbacks | Keep annotations outside callback mutations; account for preparation memory and use explicit valid tasks |
| LLM judges | Only canonical ASCII integers 0–100 are accepted | Preserve old results; explicitly budget any experiment under the new parser |
| Cached LLM scores | Parser, prompt, provider configuration, and model identity are bound | A legacy/mismatched cache stops before provider work; choose a new path deliberately |
| Corrupt caches | Fail closed instead of starting an empty paid run | Preserve the rejected file; restore a reviewed backup or budget a new run |
| Cache persistence | Staged bytes must pass the strict restart reader before replacement | Keep the instance after a failed flush; correct the cause and flush retained work without a new callback |
| Calibration | No silently dropped abstentions, duplicate record IDs, or invalid values | Resolve missing outcomes and audit sampling before creating a policy |
| Empirical thresholds | Tie-aware sweep, unit-interval thresholds only | An unattainable FPR budget raises rather than exporting an unusable policy |
| Adaptive attacks | Missing scores/generation stop explicitly | Do not reinterpret a failed experiment as resistance; review intent preservation separately |
| Provider transport | HTTPS by default, no redirects, bounded strict responses | Configure the canonical endpoint; plain HTTP needs explicit local-operator opt-in |
| Container transport | One deadline includes writes, flushes, and reads; failed sessions cannot restart | Create a new adapter for a new run and supervise daemon cleanup; see [container limits](CONTAINER_DETECTORS.md#runtime-isolation) |

Ordinary headline metrics remain conditional on answered records. New coverage
and logical-completion bounds disclose what unanswered observations could change;
they are not confidence intervals. Replicate ranges do not prove independence.

## Non-executing model intake

`checkpoint-inspect` checks a narrow sharded Safetensors profile and hashes exact
bytes without importing model frameworks. Its portable report can be checked by
LureScope against an externally trusted report hash. See
[checkpoint preflight](CHECKPOINT_PREFLIGHT.md) for supported layouts and explicit
trust/TOCTOU limits. A passing report is not publisher authentication, benign-model
evidence, deployment approval, or a patch for a vulnerable model-loading library.

## Offline verification

The [2026-09-22 local verification record](VERIFICATION_2026_09_22.md) lists actual
suite counts, installed-package checks, historical compatibility, and exclusions.

From this source checkout, using the development environment:

```sh
python -m pytest -q
ruff check lurebench tests scripts
python -m build --no-isolation
python scripts/check_mandate_wheel.py dist/lurebench-0.11.0-py3-none-any.whl --package lurebench
```

The optional `tests/test_checkpoint_reference.py` suite compares synthetic layouts
against the native Safetensors reader. CI runs it with Safetensors 0.8.0. Tests
neither download model weights nor need paid provider calls.

For cross-project checkpoint interoperability, make both source packages
importable and run `python scripts/check_checkpoint_interop.py`. It uses a tiny
synthetic checkpoint, verifies byte equality, and rejects two substitution cases.

## Remaining boundaries

- Cache coalescing is per instance, not cross-process locking or exactly-once billing.
- Provider timeouts are not total deadlines; retries can incur additional cost.
- Filesystem checks require trusted parents and cannot make later model loading atomic.
- Unique IDs do not prove independent samples, correct labels, or no dataset leakage.
- Default core use remains dependency-free; optional model stacks have separate risk.
- The [Accelerate advisory](https://github.com/advisories/GHSA-4j2p-28q2-5m79)
  still lists no patched version when rechecked on 2026-09-22. Do not dismiss it
  because this branch adds preflight. See [dependency review](DEPENDENCY_SECURITY.md).

Further details: [outcome contract](DETECTOR_OUTCOMES.md),
[cache safety](CACHE_SAFETY.md), and [provider boundaries](PROVIDER_BOUNDARIES.md).

External invariant, coverage, incident-response, boundary, and conformance files
now use bounded opened-file reads with observed-change checks. Their published
size limits remain unchanged. Receipt CLI key intake uses the same mechanism,
with a 64 KiB bound and owner-only POSIX permissions for private keys. Supplied
empty key paths fail instead of silently choosing an unsigned operation. Public
verification keys need not be private. Trusted parent directories remain required;
these checks do not establish an atomic filesystem snapshot or key ownership.
# Producer policy files (unreleased)

`DecisionPolicy.load` now checks regular non-symlink files up to 64 KiB using
strict JSON. It rejects duplicate keys, nonfinite numbers, coerced controls,
unsupported fields, invalid timestamps, excessive counts, off-grid risk-control
thresholds, and inconsistent declared risk arithmetic. Optional
`expected_sha256=` binds the exact bytes to a separately reviewed lowercase
SHA-256 digest. Without an external pin, validation establishes structure and
count consistency, not provenance, honest sampling, or deployment safety.

`DecisionPolicy.save` validates before writing a private temporary file and
atomically replacing the target. Failed validation or replacement preserves the
old file. Output symlinks/special files are rejected. Parent directories must be
trusted, and concurrent writers or power-loss durability are not guaranteed.

Legacy schema-1 policy IDs remain unchanged for detector names of at most 243
characters. Longer names now use a truncated ID prefix to fit the published
256-character contract; the full detector name still contributes to the ID hash
and remains in `detector`. Do not treat a policy ID as a content digest: empirical
schema-1 identity historically excludes score/threshold bytes. Pin the full
artifact when exact approval matters. Historical schema-1 files are not upgraded
to risk-controlled policies simply by reading them.

## Lineage uncertainty from existing caches

The additive `uncertainty-cached` and `verify-uncertainty` commands require no
provider calls. They default to whole declared-lineage resampling, retain
abstentions, and return null for undefined metrics, including zero-denominator
MCC. Legacy scored-record interval values retain their metric conventions;
`eval --bootstrap` now preserves unavailable intervals explicitly and validates
bounded configuration before detector construction. The strict report interval
API continues to raise on unavailable statistics; the additive
`confidence_interval_results` API returns per-metric availability. See
[interval compatibility and limits](VALIDITY.md#confidence-intervals).
See [the method, limits, and reproduction guide](CLUSTER_UNCERTAINTY.md) before
interpreting nominal intervals as population evidence.
