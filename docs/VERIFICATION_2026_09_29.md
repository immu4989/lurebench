# Local verification and handoff — 2026-09-29

Unreleased working-tree changes on `feat/lurepermit-lurerange`. No commits, pushes,
releases, paid model calls, model downloads, or production deployments this turn.
Work stopped when the account usage check reported 9% remaining (requested stop:
10%). All temporary local serving processes started for this work were stopped.

## Completed checks

- LureBench: **1,290 passed, 39 skipped**, 9 dependency warnings; Python 3.13.15.
- LureScope: **912 passed**, 16 dependency warnings; Python 3.12.13.
- LureScope also passed 912 tests against the adjacent updated LureBench source
  before the final core-v2 dedup-lineage-only change.
- Both repository lint checks and tracked `git diff --check` passed.
- Browser calculation/adapter/evidence tests: **62 passed**. Python/JavaScript
  capacity outputs matched on 80 synthetic configurations and seven prevalences.
- Synthetic producer/consumer capacity and three-objective policy checks passed.
- Pinned producer checks: 26 contracts; independent authority verifier: 10 artifacts.
- Earlier in this turn both distributions built, wheel checks verified 126 and
  156 exact files, and out-of-checkout installs passed 7 LureBench and 10 LureScope
  authority profiles plus the data-only default-model check. **Those builds precede
  the final policy, inbox, uncertainty, and lineage changes: rebuild/reinstall
  checks are still required before publishing this final tree.**

## Research and implementation

Read-only cache replay and callback budgets; aggregate paired comparisons;
strict bounded/atomic dataset intake; corrected lexical and transitive ancestry
audits; lineage-disjoint cross-generator folds; ancestry-preserving exact dedup;
strict policy loading/saving and optional exact-byte pins. LureScope adds bounded
strict HTTP intake, proof/key hardening, consistent inbox reads, local capacity
planning, and optional simultaneous expected-review-demand bounds.

The [paired-corpus study](lineage-study-2026-09-29.json) records observed input and
source hashes plus runtime versions. Historical split results are reproduced but
explicitly distinguished from the new lineage-disjoint cohorts. The comparison
does not establish model improvement, population equivalence, or deployment safety.

## Remaining release checks

1. Review the uncommitted diff, including compatibility changes in migration docs.
2. Rebuild both final wheels and rerun isolated installed-package/interop checks.
3. Complete desktop/mobile browser visual QA. The browser tool blocked access to
   its failed-navigation page; automated DOM-double tests do not replace visual QA.
4. Run live protected-branch CI and deployment checks only after a separately
   authorized push/review. Local 0.11.0-named wheels are not published releases.

No government certification, compliance approval, model safety guarantee, or
production accuracy claim follows from these checks.
