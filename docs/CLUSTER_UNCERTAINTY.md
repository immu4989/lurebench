# Detector uncertainty with declared lineage

`uncertainty-cached` estimates uncertainty from an existing score cache while
keeping related messages together. It is intended for evaluation teams reviewing
a fixed detector on held-out data. A hundred rewrites from one seed do not become
a hundred independent resampling units. This source-branch feature is unreleased
and is not part of PyPI 0.11.0.

## Run without model calls

```sh
lurebench uncertainty-cached --dataset test.jsonl --cache detector-cache.json \
  --detector-name 'original-display-name' --task fraud \
  --threshold 0.5 --replicates 2000 --confidence 0.95 --seed 4989
```

Supply the original `--cache-namespace` for a context-bound cache. Missing entries
stop the analysis; a stored `null` remains an observed abstention. No provider is
constructed, cache refilled, network contacted, or input file changed. Scores
are assumed to match the declared task and detector; replay cannot establish
that provenance. See [cache safety](CACHE_SAFETY.md).

The default `--resampling-unit lineage` uses transitive components of populated
`family_id`, `scenario_id`, `parent_id`, `seed_id`, and `rewrite_of` annotations.
Records with no links become singletons, not proven-independent samples.
`--resampling-unit record` explicitly samples individual messages. Unlike these
commands, the legacy `eval --bootstrap` and `Report.confidence_intervals` still
use their original record-level procedure and metric conventions.
Their controls are now bounded, and the CLI returns explicit unavailable-interval
statuses instead of losing the entire report; see [legacy intervals](VALIDITY.md#confidence-intervals).

For a fully offline tutorial, reuse the existing synthetic panel fixtures:

```sh
python scripts/run_comparison_demo.py --out /tmp/lure-uncertainty-demo
lurebench uncertainty-cached \
  --dataset /tmp/lure-uncertainty-demo/messages.jsonl \
  --cache /tmp/lure-uncertainty-demo/selective.json \
  --detector-name synthetic-selective --task fraud --replicates 200
```

The demo directory must not already exist. These label-based fixture scores are
not predictions or measured detector performance. The example has 16 records,
eight declared families, and 50% answer coverage. Python callers can supply
`bootstrap_uncertainty(truths, scores, groups=groups)` with three mappings keyed
by identical record IDs. Omitting `groups` in Python means record-level units.

## Resampling and metric definitions

Each replicate selects K groups independently and uniformly with replacement
from the K declared groups, retaining every member of each selected group.
Unequal group sizes therefore produce different numbers of records per replicate.
This is the whole-cluster procedure described in
[Pang et al., section 2.3](https://www.frontiersin.org/journals/veterinary-science/articles/10.3389/fvets.2023.1274786/full).
It is not a hierarchical bootstrap with additional within-group resampling or a
class-stratified bootstrap. Select a method appropriate to the actual sampling
design; case-control studies with fixed class totals may need another procedure.

Metrics are **record-weighted**, not equal-family-weighted. Accuracy, MCC,
recall, FPR, and AUC concern answered records. Overall and class-specific answer
coverage include abstentions in their denominators. Entirely abstaining groups
remain in the resampling population. The report also retains the original six
decision counts, group sizes, largest-group fraction, and numbers of groups
containing each class or an answer.

All metrics share the same draws. AUC uses weighted positive–negative pairs with
half credit for ties. Integer group multiplicities avoid expanding a repeatedly
selected large family in memory, and scores are sorted only once. No threshold
selection or model fitting occurs inside the resamples.

## Read unavailable and conditional results

A zero denominator gives `estimate: null`, not zero. In particular, AUC needs
both answered classes; recall needs answered positives; FPR needs answered
negatives; MCC needs nonzero observed and predicted class margins. This MCC
convention deliberately differs from the historical summary metric's zero
fallback. One undefined metric does not abort the other metrics.

Each metric reports `defined_replicates` and `undefined_replicates`. Percentiles
use only defined draws. If any draws are undefined, `conditional_on_defined` is
true: the interval is conditional on those draws, not an unconditional coverage
guarantee. If no draw defines a metric, its interval is null. Fewer than two
resampling units execute no draws and return no intervals, even for a defined
point estimate. The statuses distinguish these cases.

For m sorted defined draws, zero-based endpoints are
`floor(alpha*m)` and `min(m-1, ceil((1-alpha)*m)-1)`, where
`alpha = (1-confidence)/2`. There is no quantile interpolation, forced inclusion
of the point estimate, or simultaneous confidence adjustment. Record IDs and
group labels are sorted before sampling, making results invariant to mapping
insertion order. Reproduction uses the same Python `random.Random(seed)`
algorithm; cross-runtime bit-for-bit portability is not promised.

## Reproduce a saved report

Save stdout in a private file using your normal output controls. Shell
redirection itself can overwrite files and use permissive permissions; these
commands do not manage output paths. To reproduce a saved report, provide the
same explicit input paths, identity, and analysis controls:

```sh
lurebench verify-uncertainty --dataset test.jsonl --cache detector-cache.json \
  --detector-name 'original-display-name' --task fraud --threshold 0.5 \
  --replicates 2000 --confidence 0.95 --seed 4989 --report saved-report.json
```

Exit 0 means every field matches a local replay; 1 means mismatch; 2 means invalid
or unavailable input. Controls are not taken from the supplied report. Added
annotations, changed limitations, or integer-to-float alterations also mismatch.
This is same-implementation reproduction, not independent statistical validation,
a digital signature, or proof that a study was preregistered.

The effective-input fingerprint commits to sorted record IDs, targets, scores,
group labels, threshold, and resampling mode. It omits raw text; the cached
wrapper separately hashes the exact dataset bytes in the same bounded read used
to parse them. Unused cache entries and cache file formatting do not affect the
analysis. Reported detector identity and task come from caller configuration.
Fingerprints neither authenticate inputs nor anonymize them against guessing.
Output excludes raw record IDs, group labels, message text, and local paths.

The companion LureScope source-branch Evidence Explorer can open the report
locally and display group counts, coverage, intervals, and conditional-draw
warnings. It does not rerun the statistical analysis. Its strict JavaScript
number boundary requires `seed <= 9007199254740991`; use the Python CLI for larger
seeds. Existing hosted labs may not yet support this unreleased format.

## Limits and scientific review

Supported bounds are 1–50,000 records, 1–10,000 replicates, at most 50 million
record-replicate work units, an unsigned 64-bit seed, and confidence strictly
between zero and one. Excess work fails before random draws, without truncation
or automatic approximation. The report reader is limited to 64 KiB. Input files
use the existing bounded dataset/cache readers and require trusted directories;
the dataset must be a regular non-symlink file. The JSON schema provides structure
checks, not arithmetic verification.

The intervals are nominal, not finite-sample guarantees. Independence between
groups and representative sampling must be justified externally. Few or dominant
groups, boundary estimates such as perfect accuracy, missing ancestry, selective
abstention, label errors, selection on test results, and distribution shift can
invalidate an interpretation. A zero-width interval is not proof of certainty.
The method does not establish detector superiority, deployment safety, or
government compliance. Review these conditions before using the report in
procurement or operational decisions.
