# Local verification on 12 October 2026

This source-branch milestone adds whole-lineage uncertainty analysis from saved
scores and exact local report reproduction. It remains unreleased.
Local wheels retain version 0.11.0 only as test artifacts; they must not replace
the existing public distribution.

## Statistical and input checks

`tests/test_uncertainty.py` passes 63 tests. An independent expanded-sample oracle
enumerates all 27 ordered resamples of three unequal groups at thresholds 0,
0.5, and 1. Weighted counts and AUC agree, including ties and abstentions.
A separate seeded expanded bootstrap checks all eight interval endpoints and
defined-draw counts. Further checks cover whole-group duplication, input-order
invariance, singletons, single-class data, wholly abstaining groups, one-group
unavailability, deliberately absent defined resamples, strict controls, bounded
work, fingerprints, and unchanged cache/input bytes.

CLI tests cover both fraud and provenance targets, default lineage and explicit
record units, duplicate IDs, missing caches without provider fallback, and
distinct verifier match/mismatch/input-error exits. Report alterations include
metrics, extra fields, limitations, task, seed, and integer-to-float substitutions.
The JSON schema is checked against generated reports and rejects negative
probability intervals. Schema validity alone does not reproduce the statistics.

## Repository and package checks

- Full Python suite after the callback-isolation fixes: **1,698 passed, 39 skipped**, with nine existing sklearn and
  NumPy/joblib warnings. The run used the existing temporary urllib3 2.8.0 overlay;
  the repository virtual environment was not changed.
- Focused final uncertainty and wheel-contract checks: **80 passed**.
- Ruff over package, tests, and scripts, plus `git diff --check`: passed.
- Final offline wheel: **156 exact source/schema/reference files** verified.
- Installed CLI checks outside the checkout passed under Python **3.12.13** and
  **3.13.15**, using `-I -S` with model/provider libraries forbidden. They exercise
  cache replay, unavailable AUC with useful recall, group counts, full-report
  reproduction, tampering rejection, and the installed schema.

The skips remain the 36 optional Safetensors-reference checks, two full-corpus
checks with unavailable data, and one optional STIX schema check. Synthetic tests
are contract evidence, not measured model performance or calibration coverage.

## Experiment preflight and callback isolation

All 35 tests in `test_experiment_isolation.py` passed. They cover invalid shared
leaderboard inputs before detector construction, cached and uncached slice
stability, prewarm record validation and nested-copy isolation, failure isolation
between detectors, task overrides, robustness clean/attacked record separation,
invalid attack output, and CLI rejection before output or detector construction.
The full suites above and installed-wheel checks were rerun before the requested
source-branch push. These copies do not sandbox arbitrary Python callbacks or
provide an atomic snapshot of concurrently modified caller objects.

## LureScope integration

The companion source branch displays grouped uncertainty in its local Evidence
Explorer. Its six-record, three-group fixture exactly matches the producer output
at 97 replicates and seed 41. The browser displays unavailable/conditional
intervals and points to `verify-uncertainty`; it does not rerun the bootstrap or
authenticate sources. Companion checks passed **1,174 Python tests** and
**107 browser tests**, including the real parser-to-renderer path without
outbound report requests. A loopback browser preview confirmed the rendered
cards and warnings. The preview server was stopped afterward.

## Interpretation and release boundaries

Whole-group resampling requires independent, representative groups; annotations
do not establish either assumption. Intervals remain nominal and conditional
when undefined draws are excluded. Few groups, selective abstention, boundary
estimates, label errors, selection, and distribution shift require scientific
review. Verification required no paid experiments, model downloads, package uploads,
release, public deployment, or government certification were performed.
See [the method and reproduction guide](CLUSTER_UNCERTAINTY.md).
