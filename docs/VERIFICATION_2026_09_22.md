# Local hardening verification — 2026-09-22

This records a local source-branch verification session, not a published release,
third-party security audit, production trial, or government certification.
At verification time, changes were uncommitted/unpushed on
`feat/lurepermit-lurerange` in both projects. Subsequent commits or pushes do not
change the local-only scope of the checks recorded here.

Starting commits:

- LureBench: `85e4c1ec5b8cfbf524aa33e481b2ee45b1885d7a`.
- LureScope: `4b9d7a6077298d4ba81f3a3bb924f50906341f7f`.

## Results

| Check | Observed result |
| --- | --- |
| LureBench full Python suite, Python 3.13.15 | 1,063 passed, 39 skipped |
| LureScope full Python suite, Python 3.12.13, pinned public LureBench dependency | 747 passed |
| LureScope full suite with both new source trees on `PYTHONPATH` | 747 passed |
| Browser engine and evidence explorer | 54 passed |
| Optional native Safetensors 0.8.0 differential tests | 36 passed separately |
| Installed LureBench authority CLI | 7/7 profiles plus rejection probes |
| Installed LureScope independent authority CLI | 10/10 profiles plus rejection probes |
| Exact source/wheel authority packaging | 125 LureBench and 154 LureScope source files matched |
| Pinned producer contract | 26 artifact pins verified |
| Authority import independence | 10 artifacts verified with producer imports forbidden |
| Installed portable default model | Passed with pickle/joblib/sklearn/NumPy/Torch imports blocked |
| Installed cross-project checkpoint check | Byte match passed; both substitution probes rejected |
| Pre-change operational pilot bundle verified by new code | Passed, preserving the old model pin |
| Lint and whitespace checks | Both projects passed |
| Source distributions and wheels | Both built successfully from source distributions |

The default LureBench run skips the 36 optional native-reference tests plus three
other optional tests; the native-reference tests were run separately, not silently
counted as default-suite passes. Existing warnings remain: sklearn/SciPy solver
options, NumPy/joblib deprecations during trusted-reference tests, and the
Starlette test-client transport deprecation. These checks were local, not a new
GitHub Actions run. Docker images and the full multi-Python CI matrix were not run
as part of this session.

## Numerical and historical checks

- Portable TF-IDF weights retain full precision. Over 1,000 inputs match the
  trusted bundled sklearn model within 1e-12 absolute probability; top feature
  ordering matches. The exporter reproduces the checked-in JSON digest exactly.
- A real synthetic pilot bundle was generated from an archive of the committed,
  pre-change LureScope code and then accepted by the new verifier. New receipts
  cannot substitute the other approved model pin without matching their manifest.
- Threshold selection matches exhaustive four-record ternary-score cases. A
  10,000-record regression ensures the full metric bundle is computed only once.
- One local 1,000-record synthetic timing sample returned identical selected
  threshold/metrics: committed selection took 1.883 seconds; the new sweep took
  0.00369 seconds. This is one local observation, not a general speed guarantee.
- Missing-outcome bounds are checked against exhaustive binary completions.
  Ranking metrics are also compared with independent brute-force calculations.

## Cost, privacy, and release boundaries

No paid provider requests, model downloads, production calls, GitHub writes,
commits, pushes, package publication, or reset-credit redemption were performed.
Provider/concurrency tests use synthetic in-process stubs; model conversion uses
the already bundled trusted artifact. Temporary pilot bundles contain synthetic
messages and temporary signing material, not production inboxes.

Local artifacts still carry the existing `0.11.0` version for package testing.
They must not be uploaded over the existing release. Before a future release:
review the source diff and migration notes, choose a new version, run the protected
branch CI matrix and container checks, and explicitly authorize publishing.

The Accelerate advisory remains unresolved; checkpoint preflight is a separate
bounded control, not an upstream patch or proof that vulnerable paths cannot be
reached. See [dependency security](DEPENDENCY_SECURITY.md) and
[migration requirements](HARDENING_MIGRATION.md).
