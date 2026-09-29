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

The exact conditional two-sided McNemar test uses the discordant correctness
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

Inference assumes independent, representative record pairs. Duplicate messages,
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
silent intersection. Thresholds can be supplied as keyword arguments. No raw
text or record IDs are emitted in its aggregate report.

Tests independently enumerate small binomial probabilities, symmetry under
swapping models, and every binary completion for two-record missingness patterns.
