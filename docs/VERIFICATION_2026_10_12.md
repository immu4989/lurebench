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
review. Verification required no paid experiments or model downloads. No package
upload, release, public deployment, or government certification was performed.
See [the method and reproduction guide](CLUSTER_UNCERTAINTY.md).

## Subsequent local evaluation preflight milestone

After the requested source-branch push, the next local milestone added complete
leaderboard specification parsing before execution, bounded bootstrap preflight
before evaluation constructors, explicit per-metric interval availability, and
count-only MCC/recall/FPR resampling calculations. This subsequent work is
uncommitted and unpushed at verification time.

- **64 new regression tests passed**, including zero-constructor rejection,
  unavailable AUC without report loss, zero/one answered observations, wholly
  undefined draws, invalid singleton observations, strict seeds and work bounds,
  exact legacy interval equality at three thresholds, and deterministic CLI JSON.
- A separate seeded pairwise AUC oracle agrees on quantiles and undefined-draw
  counts; resampling leaves the global random state unchanged. Unexpected
  statistic exceptions still propagate rather than becoming unavailable results.
- Full LureBench suite: **1,762 passed, 39 skipped, 9 existing warnings**, using
  the same temporary urllib3 overlay described above.
- Companion LureScope suite: **1,174 passed, 16 existing warnings**. Its source
  was unchanged in this milestone.
- Ruff and whitespace checks passed. The rebuilt wheel matched **156 exact
  files**. Installed checks passed outside the checkout under Python **3.12.13**
  and **3.13.15**, with optional provider/model imports forbidden. They include
  preflight constructor guards and a single-class evaluation with unavailable AUC.

A local synthetic check over 128 observations, 200 replicates, and three count
metrics returned exactly equal old/new intervals. Full metric sweeps took about
0.149 seconds versus 0.043 seconds for count-only calculations in that one run;
these timings are not a general performance guarantee. The statistical contract
remains legacy scored-record resampling, not lineage-adjusted uncertainty. See
[interval behavior and limits](VALIDITY.md#confidence-intervals).

## Subsequent local provenance adapter milestone

Binoculars now requires a reviewed backend or explicit unsafe-upstream loading
opt-in, rejects invalid raw scores before clipping, and checks the full tokenized
input before inference. Persistent caches require an external reviewed backend
identity. The historical finite-score transform remains an uncalibrated proxy;
its decision threshold is not the upstream `predict()` operating point.

- **57 adapter tests passed** using in-process synthetic backends, including
  default/import guards, configuration rejection, raw-score validation, text and
  token limits, malformed tokenization, stable method tokenizers, changed backend
  controls, cache identity, legacy-cache rejection, and cached abstention replay.
- The pre-fix reproduction showed a NaN raw score becoming `1.0`. Invalid raw
  outputs now raise and leave the score cache empty. Valid historical finite
  proxy values remain exactly equal on the tested boundary/interior anchors.
- Full LureBench suite: **1,819 passed, 39 skipped, 9 existing warnings**, using
  the previously documented temporary urllib3 overlay.
- Full sibling LureScope suite: **1,234 passed, 16 existing warnings**; five new
  boundary checks cover fraud-route rejection before construction and catalog
  guidance. Its **107 browser tests** also passed.
- Ruff and whitespace checks passed in both repositories. Wheels matched
  **156 LureBench** and **164 LureScope** exact files. Both wheels were installed
  together outside the checkouts. Benchmark checks passed with optional model
  imports blocked on Python **3.12.13** and **3.13.15**; installed Scope scoring,
  proof, and authentication checks passed on Python **3.12.13**.

The advisory review on this date still found no listed patch for Accelerate
GHSA-4j2p-28q2-5m79; no dependency alert was dismissed. No real Binoculars model
was downloaded, imported, loaded, or exercised. Backend execution, artifact
provenance, remote-code safety, hardware compatibility, and thread safety require
separate review. This local milestone was not committed, pushed, or released.
