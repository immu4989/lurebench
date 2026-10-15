# Local verification 13 October 2026

Status notes within earlier sections describe each verification milestone at
that time. Those changes were subsequently pushed through `ebbc26c`; the paired
enforcement and numerical milestones at the end remain local and unreleased.

The moderation adapter now rejects incomplete or malformed numeric evidence,
instead of substituting the `flagged` boolean or silently discarding invalid
categories. Valid complete category maxima retain their previous numeric values;
they remain content-safety proxies, not calibrated fraud probabilities. These
changes and the preceding local milestones are uncommitted and unpushed.

## Contract and regression evidence

The reviewed text profile uses the 13 categories in the
[official moderation response guidance](https://developers.openai.com/api/docs/guides/moderation#understand-moderation-results).
It requires exactly one result, a boolean flag, and a complete finite numeric
category map. Unknown or duplicate aliases fail closed. Persistent cache identity
binds this parser/profile, model, endpoint, SDK version, task, and optional
reviewed context; legacy contexts are rejected without rewriting their files.

Before implementation, **54 of 61 initial regressions failed**. They reproduced
boolean fallback, partial maps, ignored invalid values, position-dependent NaN
masking, and ambiguous multi-result handling, and exercised the new constructor
and cache controls. The final **69-case** contract suite passed in the companion
Python 3.12 environment, including actual Pydantic alias serialization. It uses
synthetic responses and clients, not live API traffic or real credentials.

## Full and installed verification

- LureBench: **1,970 passed, 40 skipped, 15 warnings**. One skip is the optional
  Pydantic compatibility test, separately passed in the companion environment;
  the other 39 skips and warning categories are unchanged. The existing temporary
  urllib3 overlay from the 12 October verification remains in use.
- The companion service's **seven moderation-route tests** passed, including
  actual source-branch parser failures and valid-zero recovery. Those three
  paired cases explicitly skip with an older companion parser; four independent
  route/error tests still run. Scope's full suite passed **1,262 tests**, with
  16 existing warnings and no skips under the paired source configuration.
- All **107 browser tests**, **26 producer artifact pins**, and **10 independent
  authority artifacts** passed. Ruff and whitespace checks passed in both repos.
- Wheels matched **156 Bench** and **164 Scope** exact package/authority files.
  The Bench source archive retained byte-exact moderation tests and installed
  smoke code; the Scope archive retained **19 browser reproduction inputs**.
- Both wheels were installed together outside the checkouts. Bench checks passed
  on Python **3.12.13** and **3.13.15** with `-I -S` and optional SDK/model imports
  blocked, including invalid-moderation rejection without a cached score.
  Installed Scope model/proof, authentication, and browser checks passed.
- An additional paired installed ASGI check used the real adapter with a
  synthetic client: score, attack, and triage returned redacted `502`; proof
  creation returned `400` before another client call. Replacing the invalid
  category with a valid zero restored successful scoring at exactly zero.

## Limits and deployment

The pinned OpenAI SDK was unavailable in the offline package cache, so a temporary
SDK installation attempt could not complete. Actual SDK compatibility and live
provider behavior were not exercised. Pydantic serialization, SDK-shaped test
objects, constructor stubs, and the actual local parsing code were exercised.
These checks validate client-exposed values, not raw HTTP bytes or transformations
already performed by an SDK. The parser intentionally rejects other taxonomies.

A model alias does not pin remote weights, and metadata/context hashes do not
authenticate a provider. Updating LureScope alone cannot fix a previously
installed LureBench parser; deploy compatible builds together after release
review. No public package, deployment, historical cache, or model artifact was
modified. Local version 0.11.0 wheels are verification artifacts, not releases.

## Subsequent calibration preflight and evidence identity milestone

Calibration now rejects invalid controls before validation-file reads and rejects
unusable populations before constructing a detector. The task declared by the
constructed detector must match the requested task before any scores are taken.
New empirical and risk-controlled policy IDs commit to labels, scores, selected
threshold, and policy evidence using full SHA-256. Historical policy IDs and
schema v1/v2 files remain unchanged on load. The ID does not bind deployed model
weights, prompts, or provider configuration.

- **20 of 21 initial regression tests failed** before implementation. The final
  preflight/identity file has **43 passing tests**. Together with selection and
  lineage tests, **74 cases passed**. Coverage includes output preservation,
  redacted input errors, constructor/score non-invocation, invalid ignored
  controls, both tasks, exact canonical identity reproduction, long names, and
  changed scores that retain the same threshold but change the policy ID.
- At a 1% target, the preflight accepts **299 negatives at 95% confidence** and
  **459 at 99%**, with a positive observation also required. Those runs match
  the existing selector's threshold, metrics, and risk-control object exactly.
  One fewer negative is rejected before selection. A subnormal positive target
  is rejected without overflowing a minimum-sample calculation.
- Full LureBench: **2,013 passed, 40 skipped, 15 warnings**, with the previously
  documented urllib3 overlay. Paired-source LureScope: **1,268 passed, 16
  warnings**. **107 browser tests**, Ruff, whitespace, **26 producer pins**, and
  **10 independent authority artifacts** passed.
- Built wheels matched **156 Bench** and **164 Scope** package/authority files;
  the Scope source archive retained **19 browser inputs**. Installed Bench
  checks passed under Python **3.12.13** and **3.13.15**, outside the checkouts
  with `-I -S` and optional imports blocked. Installed Scope loaded generated
  policies for all three objectives, preserved their IDs, and reported name-only
  binding without configuration verification. Installed model/proof,
  authentication, and browser checks passed.

The preflight does not test unseen detector scores, guarantee i.i.d. sampling,
preflight output permissions, or impose a provider billing cap. Threshold
selection and finite-sample inference mathematics are unchanged. No provider
requests or historical-artifact migrations were performed. This milestone is
local and unreleased; its 0.11.0 wheels are verification artifacts only.

## Subsequent configuration-bound policy milestone

Schema v3 binds validation evidence to a declared exact portable artifact,
installed inference source, and runtime profile. It supports empirical and
risk-controlled objectives without changing their selection mathematics.
V3 loaders recompute the full evidence identity and retain existing grid,
count, and statistical-bound checks. Legacy builders and historical IDs remain
compatible. The low-level builder records a caller-supplied binding; actual
portable-score collection is implemented by the companion `lurescope calibrate`.

- **28 new producer tests** passed: all objectives and schema validation,
  load/save preservation, binding changes, evidence-ID mismatch, malformed or
  unsupported bindings, legacy-schema rejection of bindings, risk arithmetic,
  and equivalent integer/float probability representations.
- Full Bench: **2,043 passed, 40 skipped, 15 warnings**, using the documented
  urllib3 overlay. Paired-source Scope: **1,305 passed, 16 warnings**. Scope's
  **34 new binding tests** cover actual portable calibration, immutable model
  state, mismatches before scoring, recheck before publication, explicit override
  semantics, redacted HTTP failures, proof refusal, and shared schema bytes.
- **107 browser tests**, Ruff, whitespace, **26 historical producer pins**,
  **10 independent authority artifacts**, and static asset checks passed.
  Existing wheel-test fixtures were expanded to exercise the required v3 schema;
  missing/stale schema coverage was added without weakening the verifier.
- Wheels matched **157 Bench** and **166 Scope** exact package/authority files,
  including the v3 schema. Scope's source archive retained **19 browser inputs**.
  Installed Bench checks passed under Python **3.12.13** and **3.13.15** with
  optional imports blocked. Installed Scope loaded bound policies for all three
  objectives, verified matches, and rejected a changed runtime identity. Existing
  model/proof, authentication, and browser checks also passed.
- Outside both checkouts, the installed `lurescope calibrate` command generated
  a v3 policy from two synthetic text records under Python **3.12.13** with
  `-I -S`. The installed service matched and scored under that runtime. Under
  **3.13.15**, the same policy loaded but reported `mismatch` and scoring failed.
  Installed HTTP `/policy` and `/score` also verified the matching 3.12 workflow.

These are contract and deployment-boundary tests, not new fraud-accuracy results.
No paid provider, new model training, public release, or deployment was involved.
The binding assumes trusted installed code and runtime, does not attest arbitrary
process mutations or hardware, and does not verify sampling or upstream text
extraction. A trusted policy hash/signing process remains necessary for origin
and replacement control. This milestone remains local and unpushed.

## Paired deployment enforcement verification

The companion LureScope source now supports mandatory pinned v3 policies and an
optional risk-controlled evidence floor. Its new admission checks reject client
threshold/detector overrides and require a separate worker for exploratory
attacks and proof generation. LureBench's risk-control guide documents the
producer-to-deployment workflow without claiming that evidence alone forces
clients to use a policy. No calibration mathematics or producer schema changed.

The **42 new Scope enforcement tests** and full paired suites passed:
**2,059 Bench tests** with 40 skips/15 warnings using the existing urllib3 overlay,
**1,367 Scope tests** with 16 warnings, and **107 browser tests**. Ruff, whitespace,
26 producer pins, 10 independent authority artifacts, and static asset checks
passed. Built wheels matched 157 Bench and 166 Scope exact files; installed Bench
checks passed under Python 3.12.13 and 3.13.15 with optional imports blocked.
Installed Scope checks, including an independent HTTP/fresh-process CLI exercise,
verified approved scoring and rejection after pin removal without providers.

This establishes source-branch admission behavior, not deployment suitability,
sampling independence, new fraud accuracy, or regulatory compliance. The new
documentation and companion implementation remain local and unpushed.

## Streaming binomial arithmetic milestone

The prior recurrence could reach a subnormal fixed point: multiplying the
smallest positive binary64 number by a ratio near one kept returning that same
number. This extended the tail loop and could produce spurious positive tails.
It also retained every relative weight in a list. The replacement streams two
sums and continues the subnormal recurrence in log space until actual floating
underflow. Zero-event upper bounds use the stable closed form with one outward
floating-point step; the nonzero-event inversion method is unchanged.

- **39 new numerical tests** pass. The initial 31-case suite reproduced seven
  failures before the fix. Oracles include 100-digit Decimal finite sums,
  SciPy binomial CDF values, and beta-quantile confidence bounds. All optional
  SciPy oracle cases ran in the verification environment; none were skipped.
- A fixed 200,000-trial, probability-0.5 CDF calculation returned exactly the
  same float before and after the change. A local `tracemalloc` comparison measured
  **8,026,280 bytes** peak for the pushed implementation versus **880 bytes** for
  the streaming implementation. A separate 10-million-trial central-tail check
  used **904 bytes** and agreed with SciPy within the declared 2e-11 relative
  tolerance. These are local traced-allocation measurements, not RSS or latency
  guarantees. The automated 200,000-trial regression requires less than 512 KiB.
- Three companion Scope tests accept consistent zero-event count evidence at
  400, 100,000, and 9,999,999 negatives. These are counts-only synthetic artifacts,
  not evaluations of millions of messages. Both consumers retain historical
  schemas and do not rewrite old policy identities.
- Full Bench: **2,098 passed, 40 skipped, 15 warnings** with the existing urllib3
  overlay. Paired Scope: **1,370 passed, 16 warnings**. Including **107 browser
  tests**, **3,575 tests passed**. Ruff, whitespace, 26 historical producer pins,
  10 independent authority artifacts, and static assets passed.
- Wheels match **157 Bench** and **166 Scope** exact source/authority files;
  Scope retains **19 browser archive inputs**. Installed Bench checks under
  **Python 3.12.13 and 3.13.15** include numerical regressions with optional imports
  blocked. Installed Scope model/proof, enforced admission, authentication, and
  browser checks also pass.

The implementation remains dependency-free and uses the same exact-binomial
statistical method; floating-point arithmetic is not arbitrary-precision interval
arithmetic. Newly generated evidence may differ in its last floating-point digits.
See the [numerical implementation and primary references](RISK_CONTROL.md#numerical-implementation).
No provider call, model download, training run, release, push, or production
configuration change was performed. The new work remains local and uncommitted.

## Strict risk acceptance boundary

Numerical consistency tolerance no longer expands the statistical acceptance
limits. Both reported and recomputed p-values and upper bounds must satisfy the
unrelaxed criteria. The selector refuses results whose computed upper bound
exceeds the target, including extreme-confidence rounding contradictions.

Four producer and four consumer cases reproduced tolerance-budget acceptance
before the fix. They cover actual violations, understated serialized evidence,
and reported-only violations. A corrected selector regression independently
reproduced the old function returning an upper bound of approximately 5.42e-20
for a requested 1e-30 target. All nine final regressions pass; publication tests
also preserve existing output bytes after rejection.

Full verification passed **2,103 Bench tests** (40 skips, 15 warnings with the
existing urllib3 overlay), **1,374 Scope tests** (16 warnings), and **107 browser
tests**, totaling **3,584**. Ruff, 26 historical producer pins, 10 independent
authority artifacts, and static assets passed. Installed checks on Python 3.12
and 3.13 passed, including a separate dependency-free installed producer/consumer
rejection and selector-refusal check. Scope's installed model/proof, enforcement,
authentication, and browser checks passed.

This intentionally tightens acceptance of borderline artifacts; it does not
rewrite their files or promise exact machine arithmetic. The change and preceding
local milestones remain uncommitted and unpushed.
