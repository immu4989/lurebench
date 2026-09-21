# LureMandate validation and release checklist

This describes unreleased source-branch functionality. It is a reproducible
validation procedure, not a statement that a public release or remote CI run
has passed. No model-provider keys or production endpoints are needed.

## What the reference campaigns establish

| Campaign | Scope | Important exclusion |
| --- | --- | --- |
| Core authority | 16 transactions; approval binding, dual control, replay, budgets, observed outcomes | Does not authenticate the people or sensors |
| Black-box guard coverage | 25 cases reaching all 21 declared decision reasons | Does not cover every policy or numeric boundary |
| Pairwise inputs | 16 cases covering 420 binary combinations across 105 factor pairs | Not higher-order or production-domain coverage |
| Counterfactual guards | 40 cases: 20 control/mutant pairs | Two pairs change coupled dimensions; not MC/DC |
| Ordered operations | 20 priming cases and 26 measured cases covering 25 ordered pairs | Measured requesters are isolated; not shared-state transition coverage |
| Shared-state transitions | 41 cases over ten replay/budget scenarios | Bounded scenarios, not arbitrary concurrent histories |

The typed telemetry reference adds 67 lifecycle events for the 16-transaction
core. Signed references in LureScope add key-possession and source-byte checks
under configured pins. Neither signatures nor benchmark passes establish
complete mediation, legal authority, compliance, or deployment safety.

## Reproduce the local checks

From an installed development environment at the checkout root:

```sh
python -m ruff check lurebench tests scripts
python -m pytest -q
lurebench mandate-selftest --json
```

The self-test checks seven reference profiles and four rejection probes per
profile. Every profile must pass, and every mutation must be rejected. Its JSON
output names the input artifact and hashes the exact bytes that were parsed.
It does not connect to or assess your gateway.

The regression suite separately includes:

- explicit golden decisions for the shared-state scenarios;
- seven injected state-machine defects that the campaign must detect;
- 80 seeded traces of 64 transactions each, checked against a small
  integer-time model that does not call the production decision function;
- factor/type/digest/timestamp tampering, allocation bounds, canonical base64
  checks in the consumer, and controlled malformed-JSON failures;
- adapter ordering, input-copy isolation, lifecycle failures, async/generator
  rejection, no retries, error redaction, and output protection.

The seeded traces vary requester/tenant scope and positive integer impact-unit
scaling. This is deterministic bounded regression coverage, not a formal proof,
random production sample, or evidence about an external product.

## Check the built distribution, not only the checkout

Use a fresh output directory. With build dependencies already installed:

```sh
python -m build --no-isolation --outdir /path/to/new-build-directory
python scripts/check_mandate_wheel.py \
  /path/to/new-build-directory/lurebench-VERSION-py3-none-any.whl \
  --package lurebench
```

Replace `VERSION` with the actual built version. The archive check compares
authority code, schemas, and corpus bytes against source and rejects missing,
stale, or duplicate members. Install that trusted local wheel into a fresh
target with `uv pip install --offline --no-deps --target TARGET WHEEL`; then,
from outside the checkout, run:

```sh
/path/to/dev-environment/bin/python \
  /path/to/lurebench/scripts/check_installed_mandate.py \
  --package lurebench --installed-root /path/to/TARGET
```

The caller's environment supplies dependencies. The check requires the package
and distribution metadata to resolve inside the new target, executes the CLI,
checks profile/rejection completeness, and rejects source-checkout fallbacks.
This is an offline packaging test, not a clean dependency-resolution test or
software supply-chain attestation. CI repeats the installed check on Python 3.12.

## Validate an actual gateway without turning a test into authorization

1. Select a disposable environment and a reviewed adapter. Keep production
   mutation endpoints out of it; configure transport timeouts and disable
   automatic decision retries.
2. Use the [adapter guide](MANDATE_GATEWAY_ADAPTER.md). Preserve one session
   across each challenge's ordered cases; use a fresh session for each campaign.
3. Record the engine ID, version, and declared build digest. These are claims
   unless independently bound to the actual deployment.
4. Score the complete submission. A successful export is not a passing score.
   Retain failing results, including collateral denials from overblocking.
5. Have LureScope independently verify the exact challenge, submission, and
   score. If provenance is needed, apply its separately pinned signing workflow.
6. Investigate every failure and rerun in a new isolated session after fixes.
   Do not promote a reference pass into production approval.

Before publishing, rerun both repositories' tests, installed checks, consumer
import-independence audit, browser tests, and exact shared-schema comparisons.
Review changes to trust pins and document compatibility changes. A new release
needs its own version and review; do not upload a changed build as an existing
published version.
