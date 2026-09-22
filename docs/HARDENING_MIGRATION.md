# Source-branch hardening: migration and verification

These changes are **unreleased**. They are not in the existing PyPI 0.11.0
distribution, and local test wheels retaining that version are not release builds.
Do not silently replace historical results with measurements from this new contract.

## What changes for researchers

| Area | New behavior | Operator action |
| --- | --- | --- |
| Missing detector scores | Abstention is not a benign prediction, evasion, or confident detection | Handle `DetectorAbstainedError`; inspect answer coverage and missing-outcome bounds |
| LLM judges | Only canonical ASCII integers 0–100 are accepted | Preserve old results; explicitly budget any experiment under the new parser |
| Cached LLM scores | Parser, prompt, provider configuration, and model identity are bound | A legacy/mismatched cache stops before provider work; choose a new path deliberately |
| Corrupt caches | Fail closed instead of starting an empty paid run | Preserve the rejected file; restore a reviewed backup or budget a new run |
| Calibration | No silently dropped abstentions, duplicate record IDs, or invalid values | Resolve missing outcomes and audit sampling before creating a policy |
| Empirical thresholds | Tie-aware sweep, unit-interval thresholds only | An unattainable FPR budget raises rather than exporting an unusable policy |
| Adaptive attacks | Missing scores/generation stop explicitly | Do not reinterpret a failed experiment as resistance; review intent preservation separately |
| Provider transport | HTTPS by default, no redirects, bounded strict responses | Configure the canonical endpoint; plain HTTP needs explicit local-operator opt-in |

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
