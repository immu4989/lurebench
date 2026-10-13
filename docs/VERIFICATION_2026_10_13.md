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
