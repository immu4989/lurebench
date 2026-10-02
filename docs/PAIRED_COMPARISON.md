# Compare detectors on the same records (unreleased)

`compare-cached` asks a narrow, useful question: how do two fixed binary decision
rules differ on the same labeled messages? It does not construct a provider or
model, refill caches, choose thresholds, or declare a deployment winner.

```sh
lurebench compare-cached --dataset test.jsonl --task fraud \
  --baseline-cache baseline.json --baseline-name 'original-baseline-name' \
  --candidate-cache candidate.json --candidate-name 'original-candidate-name' \
  --baseline-threshold 0.5 --candidate-threshold 0.5
```

Use exact display names and add `--baseline-namespace` / `--candidate-namespace`
for context-bound score caches. Both caches must contain every dataset score
key. A stored `null` is an observed abstention; an absent key is incomplete
evidence and stops the command. Duplicate record IDs are rejected before making
record mappings. See [cache replay](CACHE_SAFETY.md) for identity/trust boundaries.

## Reading the result

- All differences are **candidate minus baseline** at the supplied thresholds.
- The correctness table reports both correct, baseline-only correct,
  candidate-only correct, and both wrong on **co-answered** records.
- Accuracy differences use the same co-answered denominator, never each model's
  own answered subset. Positive-class accuracy is recall; negative-class accuracy
  is specificity, so its difference has the opposite sign to an FPR difference.
- Coverage and abstention counts are reported overall and by ground-truth class.
- All-record bounds enumerate the best/worst possible binary decisions on
  abstained records, retaining known outcomes when only one model answered.
  These are logical completion bounds, **not confidence intervals** and not a
  recommendation to coerce missing decisions to a class.

## Declared lineage is the default sampling block

The CLI defaults to `--pairing-unit lineage`. It connects every populated
`family_id`, `scenario_id`, `parent_id`, `seed_id`, and `rewrite_of` transitively,
then swaps baseline/candidate outcomes for a whole connected component at once.
Absent ancestry does not establish independence; records without connections
become singleton blocks. The grouping must be scientifically justified before
seeing outcomes, and it cannot discover missing lineage or shared-user effects.

For each block, sum candidate-minus-baseline correctness on co-answered records.
The statistic is the absolute sum of these block differences. Its exact null
distribution assigns every block difference either sign with equal probability;
the inclusive tail gives the two-sided p-value. This is the paired sign-flip
construction described in [SciPy's permutation-test documentation](https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.permutation_test.html),
applied here to declared-block totals. It requires joint invariance under those
blockwise swaps, a stronger null than merely equal average accuracy. Grouping
alone does not validate that assumption.

Metrics remain **record-weighted**, not equally family-weighted. A larger family
contributes more to the observed effect but does not create additional independent
sign assignments. One hundred wins in a single declared family give a two-sided
p-value of one. This is a synthetic sanity check, not model evidence.

Zero-difference blocks do not change the null distribution. The report preserves
their count but omits their redundant sign assignments from the denominator.
Integer convolution avoids random seeds and floating-point tie ambiguity, and
decimal-string tail/assignment counts preserve the exact rational probability.
The final `p_value` is a floating-point rendering. More than 1,000 nonzero blocks,
or `nonzero_blocks * (2 * sum_absolute_block_differences + 1) > 2,000,000`, yields
`status: exact_computation_limit` and `p_value: null`. This is **not** evidence
of no difference. There is no silent approximation. No co-answered records also
give `null`, with a distinct status.

## Explicit record level inference

With `--pairing-unit record`, the exact conditional two-sided McNemar test uses the discordant correctness
counts `b` and `c`: `min(1, 2 * P[Binomial(b+c, 0.5) <= min(b,c)])`.
This is the binomial version described in the
[statsmodels method documentation](https://www.statsmodels.org/v0.14.4/generated/statsmodels.stats.contingency_tables.mcnemar.html).
It returns one for a nonempty cohort with no discordances and `null` if there
are no co-answered records. Probabilities use finite-precision arithmetic; an
extremely small tail may underflow to zero. The report makes no automatic
significance, equivalence, noninferiority, or safety decision. For example,
improving from wrong to correct on one record gives a difference of one but a
two-sided p-value of one—not strong evidence of a population improvement.

## Conditions and limits

Record-level inference assumes independent, representative record pairs. Duplicate messages,
shared generation families, or repeated users can invalidate that assumption;
distinct IDs alone do not establish independence. Resolve leakage and choose an
appropriate sampling unit before inference. Cached scores are not fresh model
replicates. With abstentions the test concerns only the co-answered subset;
it does not establish population behavior for the missing records.

Choose the task, models, thresholds, and planned comparisons before looking at
test results. P-values are unadjusted for multiple comparisons and repeated
inspection. Data reuse, post-selection, distribution shift, label errors, and
provider changes are not corrected by this test. Keep held-out evaluation and
operational safety review separate.

Python API: `lurebench.comparison.compare_paired(truths, baseline, candidate)`
accepts three mappings with identical nonempty record-ID sets. Score mappings
contain finite probabilities or `None`; missing/extra IDs are errors, not a
silent intersection. Thresholds can be supplied as keyword arguments. Pass
`groups={record_id: block_id, ...}` for blockwise inference; Python defaults to
the original record-level test when groups are omitted. Group keys must match
exactly. No raw
text or record IDs are emitted in its aggregate report.

Tests independently enumerate small binomial probabilities, symmetry under
swapping models, and every binary completion for two-record missingness patterns.
Block tests enumerate all sign assignments for small cases, cross-check SciPy,
verify singleton equivalence to McNemar, and exercise cancellation, missingness,
invalid grouping, and explicit resource-limit outcomes.

## Planned model panels

For a runnable, provider-free tutorial from a source checkout:

```sh
python scripts/run_comparison_demo.py --out /tmp/lurebench-panel-demo
lurebench compare-panel --dataset /tmp/lurebench-panel-demo/messages.jsonl \
  --plan /tmp/lurebench-panel-demo/plan.json
```

The output directory must not exist and its parent must be trusted. The script
creates 16 synthetic records, three fixed-score caches, a plan, and an explicitly
marked demonstration report. Scores deliberately depend on fixture labels: they
are not predictions or evidence of detector performance. Replay is read-only.
The example illustrates four related positive families rather than eight
independent wins, a selective candidate's abstentions, and the common cohort.

The companion LureScope source-branch Evidence Explorer can open `report.json`
locally and display these outcomes without uploading it. The view is descriptive,
does not recompute p-values or authenticate caches, and labels this example
synthetic. This integration is unreleased; existing hosted labs may not support it.

`compare-panel` evaluates every declared candidate against one baseline, from
existing caches only. Declare the family and thresholds before looking at results.
This example is a configuration template, not a measured experiment:

```json
{
  "schema_version": 1,
  "task": "fraud",
  "pairing_unit": "lineage",
  "baseline": {"id": "baseline", "name": "original-baseline-name", "cache": "baseline.json", "threshold": 0.5},
  "candidates": [
    {"id": "candidate-a", "name": "original-candidate-a-name", "cache": "candidate-a.json", "threshold": 0.5},
    {"id": "candidate-b", "name": "original-candidate-b-name", "cache": "candidate-b.json", "threshold": 0.5}
  ]
}
```

Save the reviewed plan beside its cache files, then run:

```sh
lurebench compare-panel --dataset test.jsonl --plan comparison-plan.json
```

Cache paths resolve relative to the plan, not the working directory. Context-bound
caches need their original `namespace` field in each descriptor. Unknown fields,
duplicate JSON keys, coerced controls, duplicate IDs, and missing cache coverage
reject the panel. Nothing is downloaded or refilled. Supported bounds are a
64 KiB regular non-symlink plan, 1–32 candidates, and 1–50,000 records. A strict
plan hash identifies the supplied bytes, not when they were chosen or who approved
them. Output omits cache paths, message text, and record IDs; it is not differentially
private or authenticated evidence.

Cached panels also emit `input_fingerprint` with profile
`lurebench-panel-effective-inputs-v1`. It hashes the **already-loaded effective
inputs**, not a later reread of files: task, pairing unit, baseline ID, detector
descriptors without cache paths, and records sorted by ID. Each record contributes
its ID, SHA-256 of UTF-8 message text, task target, effective lineage group (or its
ID for record-level pairing), and every validated score including abstentions.
Detector descriptors are sorted by ID. The object is encoded with LureEval's
deterministic JSON encoder (UTF-8, sorted keys, compact separators, no nonfinite
numbers) and hashed with SHA-256.

This catches changed scores even when the classifications and aggregate results
stay equal. Record/candidate reordering, whitespace, cache locations, unused cache
entries, and metadata unused by the analysis do not change the fingerprint.
It is not an exact-byte dataset/cache digest, signature, timestamp, proof of
independence, or anonymity mechanism. Someone with candidate inputs can test for
a match. Preserve the private dataset, caches, plan, software version, and review
record separately; the fingerprint alone cannot reconstruct an experiment.

To check a saved report against the same local inputs without model calls:

```sh
lurebench compare-panel --dataset test.jsonl --plan comparison-plan.json > panel.json
lurebench verify-panel --dataset test.jsonl --plan comparison-plan.json --report panel.json
```

`verify-panel` accepts a strict regular non-symlink report up to 1 MiB and replays
the entire comparison. Exit code 0 means every field matches, 1 means the report
differs, and 2 means invalid inputs or unavailable replay. Formatting and object-key
ordering may differ; numeric types and every field must match, including the exact
plan-byte hash. Added annotations are not silently ignored. The tutorial's annotated
`report.json` therefore does not match: first use `compare-panel` to write a plain
replay report to a **new** output file, keeping the synthetic example label with
any published interpretation. Earlier source-branch report formats may require
their original software revision.

This is reproduction using the same implementation, not an independent statistical
audit or signature verification. Matching attacker-supplied caches and a report
does not authenticate either. The command never repairs/refills caches, updates
the supplied report, or selects an available subset when inputs are missing.

`family_adjustment.adjusted_p_values` uses Holm's step-down Bonferroni correction:
sort the planned p-values, multiply each by its remaining family size, take the
running maximum, and cap at one. See the
[statsmodels reference implementation](https://www.statsmodels.org/stable/_modules/statsmodels/stats/multitest.html).
Raw pairwise results remain in `comparisons`. An unavailable test occupies a slot
as one for adjustment but its reported adjusted value stays **null**. Dropping
such a candidate would shrink the planned family after seeing outcomes.

Adjustment requires valid marginal tests and does not repair invalid sampling,
block exchangeability, selected thresholds, omitted trials, or repeated inspection.
Each candidate may have a different co-answered cohort. The panel does not rank
models, choose a winner, infer equivalence, or authorize deployment. The Python
API is `lurebench.panel.compare_panel`, with explicit per-candidate thresholds.

`all_models_coanswered` also reports descriptive accuracy on the same subset for
every model, with coverage, excluded counts, and class composition. If that subset
is empty, all accuracies are null. This helps distinguish an accuracy difference
from a difference in which messages a model answered. It adds no significance
tests and does not change the planned Holm family. The common subset is selected
by model behavior, is not automatically representative, and changes when models
are added or removed. Retain the pairwise missingness and completion bounds too.
