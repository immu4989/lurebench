# Local verification 13 October 2026

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
