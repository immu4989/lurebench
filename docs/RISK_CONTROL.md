# Finite-sample false-positive risk control

An observed 1% false-positive rate is not evidence that the population rate is
at most 1%. On a small validation set, that number may be one favorable sample;
choosing the best of many thresholds on the same sample makes the claim weaker.

LureBench's `risk_controlled_fpr` objective turns a threshold into a testable
deployment policy. For a target false-positive rate $\alpha$ and confidence
$1-\delta$, it returns a threshold $\hat{t}$ only when the validation evidence
supports

$$
\Pr\left\{\operatorname{FPR}(\hat{t}) \leq \alpha\right\} \geq 1-\delta.
$$

The probability is over repeated draws of the validation sample. It is not the
probability that one particular message is benign, and it is not a guarantee
under distribution shift.

## Create a policy

Freeze the detector and preprocessing pipeline first. Then run:

> The tracked v1 core snapshot has no independent materialized validation shard,
> and its bundled model was trained on the full tracked training file. Do not
> split that file after training and call the result validation. Use newly
> collected external validation data, or rebuild the three-way corpus and retrain
> before running this command. See [benchmark validity](VALIDITY.md).

```bash
lurebench calibrate \
  --validation validation.jsonl \
  --detector tfidf-logreg \
  --model-path models/tfidf-logreg-fraud.joblib \
  --objective risk_controlled_fpr \
  --target-fpr 0.01 \
  --confidence 0.95 \
  --threshold-grid-size 1001 \
  --out policies/tfidf-1pct-fpr-95.json
```

The default grid is fixed before looking at the data: 1,001 evenly spaced
thresholds from 1.000 down to 0.000. LureBench tests them from strict to
permissive and returns the least-strict consecutive threshold that passes. If
the first threshold does not pass, no policy is written.

Use the older `target_fpr` objective for exploratory operating-point selection.
It constrains the *observed* validation FPR but carries no population-risk
guarantee. The two objectives are intentionally named differently.

## Statistical method

For threshold $t_j$, let $x_j$ be the number of false positives among $n_0$
validation negatives. LureBench tests

$$
H_j: \operatorname{FPR}(t_j) > \alpha
$$

with the exact binomial lower-tail p-value

$$
p_j = \Pr\{\operatorname{Binomial}(n_0, \alpha) \leq x_j\}.
$$

The hypotheses are ordered before seeing validation outcomes. Testing stops at
the first non-rejection. This fixed-sequence Learn-then-Test procedure controls
the family-wise error rate without treating every searched threshold as an
independent discovery. The exported one-sided bound is the exact
Clopper-Pearson upper bound for the selected count; LureScope recomputes both the
p-value and bound when loading the policy.

The implementation is dependency-free and uses stable binomial-tail recurrence.
The public JSON Schema is
[`spec/decision-policy-v2.schema.json`](../spec/decision-policy-v2.schema.json).

## Validation size is part of the result

With zero false positives, the minimum number of validation negatives is:

| FPR target | 95% confidence | 99% confidence |
|---:|---:|---:|
| 10% | 29 | 44 |
| 5% | 59 | 90 |
| 1% | 299 | 459 |
| 0.1% | 2,995 | 4,603 |

Any observed false positives require more data. LureBench reports the required
minimum and exits without a policy when the sample is insufficient. This is a
feature: an unsubstantiated low-FPR promise should not become deployment
configuration merely because a command was run.

## What policy v2 commits to

The artifact includes:

- detector, task, selected threshold, target FPR, confidence, and grid size;
- validation negatives, false positives, empirical FPR, exact p-value, and
  one-sided upper confidence bound;
- validation true positives and empirical recall as a utility point estimate
  (not a risk-controlled recall guarantee);
- SHA-256 over ordered validation IDs; and
- SHA-256 over canonical `(record ID, label, detector score)` rows.

The second digest makes changes to labels or scores visible during reproduction.
Neither digest authenticates who issued the policy. Sign or attest the artifact
through your organization's release system if issuer authenticity matters.

## Assumptions and non-guarantees

The guarantee applies only when all of these conditions hold:

1. Validation negatives are independent, representative draws from the benign
   deployment population, or satisfy an equivalent exchangeability assumption.
2. Detector weights, prompt, provider model, preprocessing, score semantics,
   target, confidence, and threshold grid were fixed before this validation run.
3. Labels are sufficiently accurate for the stated false-positive population.
4. The validation set was not repeatedly reused to select the model or redesign
   the grid. If it was, use a fresh holdout.

It does **not** guarantee recall, precision, subgroup performance, adversarial
robustness, or future FPR after population shift. Monitor deployed score and
label distributions, maintain a newly adjudicated holdout, and issue a new
policy after material model, pipeline, provider, language, channel, or population
changes. A single global guarantee can also conceal poor regional or language
slices; control those as separately predeclared risks when they matter.

## Research and governance basis

- Angelopoulos et al., [*Learn then Test: Calibrating Predictive Algorithms to
  Achieve Risk Control*](https://arxiv.org/abs/2110.01052), supplies the
  finite-sample multiple-testing framework and fixed-sequence construction.
- The [NIST AI RMF Measure function](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/)
  calls for pre-deployment testing, uncertainty measures, benchmarks, and
  formalized reporting. This policy is one narrow technical control toward that
  outcome, not AI RMF compliance by itself.
