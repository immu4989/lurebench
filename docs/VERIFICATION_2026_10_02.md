# Local verification on 2 October 2026

This records offline checks of the unreleased work on `feat/lurepermit-lurerange`,
based on commit `a0f5c84cfa5559f40e1d018a470de063c34cba29`. The changes remain local
and uncommitted. These results do not describe the published PyPI package, live
GitHub Actions, or deployed services. Local distribution files still use version
0.11.0 for testing and must not be uploaded over an existing release.

## What changed

- Paired comparisons can swap model outcomes by declared lineage rather than
  treating related rewrites as independent observations. Exact integer sign-flip
  tests disclose their stronger exchangeability assumption and resource limits.
- Planned cached panels retain every declared comparison, apply Holm adjustment,
  and expose both pairwise missingness and the common answered cohort. A synthetic
  tutorial exercises the reporting contract without measuring a real model.
- Effective-input fingerprints bind used probabilities, targets, text hashes,
  grouping, thresholds, and detector identities. `verify-panel` reproduces every
  saved report field from local inputs; matching does not authenticate a producer.
- Risk-controlled calibration rejects repeated negative-class declared lineage
  before detector construction. Passing that check does not prove independence.
- Llama Guard parses complete documented verdicts only, abstains on malformed
  output, rejects oversized input without truncation, and strengthens loading and
  cache identity controls. No model was downloaded or executed for these tests.
- Cache warming bounds outstanding tasks, checks selected existing values before
  new work, and stops admission after failure. Running callbacks are awaited and
  completed cache entries are flushed; provider requests are not refunded.
- External assurance inputs and CLI keys use bounded regular-file reads. Private
  key permissions are checked on POSIX; parent directories must remain trusted.

## Checks and results

The local Python interpreter was 3.13.15.

| Check | Result |
| --- | --- |
| Full Python suite | 1,437 passed, 39 skipped, 9 warnings |
| Ruff over package, tests, and scripts | Passed |
| Git diff whitespace check | Passed |
| Exact wheel source check, including nested modules | 153 files matched |
| Installed authority self-test outside checkout | 7 of 7 profiles passed |
| Installed panel replay under `python -I -S` | Match accepted; altered report rejected |
| Capacity producer and consumer integration | Six outcomes and synthetic workload conserved |
| Policy producer and consumer integration | Three objectives and rejection probes passed |
| Checkpoint producer and consumer integration | Byte match and two substitution probes passed |

Installed panel checks forbid model-framework and provider-SDK imports and use
fixed synthetic callbacks. Unit tests independently enumerate sign assignments,
binary missingness completions, and Holm closed-testing cases. These arithmetic
oracles are stronger than replaying the same implementation, but do not validate
sampling assumptions or the accuracy of any deployed detector.

Warnings include scikit-learn/SciPy solver-option and joblib/NumPy deprecations.
Skipped tests are not passing coverage. No paid-provider calls, model downloads,
production mutations, commits, or pushes were performed in this work cycle.
The skips comprise 36 optional Safetensors reference-reader cases, two checks
requiring unavailable full corpus shards, and one STIX-validator check whose
installed validator cannot locate its own reference schemas.

## Reproduce and review

```sh
python -m pytest -q -rs
ruff check lurebench tests scripts
python scripts/run_comparison_demo.py --out /tmp/lurebench-panel-review
lurebench compare-panel --dataset /tmp/lurebench-panel-review/messages.jsonl \
  --plan /tmp/lurebench-panel-review/plan.json > /tmp/lurebench-panel-replay.json
lurebench verify-panel --dataset /tmp/lurebench-panel-review/messages.jsonl \
  --plan /tmp/lurebench-panel-review/plan.json --report /tmp/lurebench-panel-replay.json
```

Choose new output paths so shell redirection does not overwrite existing evidence.
The demo's scores are label-based fixtures, not model predictions. Preserve that
qualification when showing its plain replay output to others.

Before release, review the local diff, run protected CI on the intended revision,
choose a new version, rebuild, and repeat installed-package checks. Publishing,
remote review, and production trials are separate actions.

The optional Accelerate dependency still has an unresolved upstream advisory;
see [dependency security](DEPENDENCY_SECURITY.md). Safetensors and remote-code
restrictions do not resolve it. These changes do not establish government
certification, procurement eligibility, population fraud accuracy, or deployment
safety. See [paired comparison limits](PAIRED_COMPARISON.md),
[risk-control assumptions](RISK_CONTROL.md), and [cache safety](CACHE_SAFETY.md).
