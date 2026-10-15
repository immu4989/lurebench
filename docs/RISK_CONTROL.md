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
minimum through `minimum_zero_event_sample(target_fpr, confidence)` and exits
without a policy when the sample is insufficient. The CLI rejects an impossible
sample before detector construction rather than waiting for scores. This is a
feature: an unsubstantiated low-FPR promise should not become deployment
configuration merely because a command was run.

### Calibration preflight

On this source branch, `calibrate` validates the objective, target, confidence,
threshold-grid size, and diagnostic bin count before reading validation data.
It then checks bounded unique IDs, labels, and risk-control sample feasibility
before constructing a detector. Risk control requires both classes and enough
negatives to pass even with zero false positives. Declared negative lineage is
checked before construction too. Invalid inputs exit with code **2** and a
redacted error; existing output files remain unchanged. Detector/task mismatch
is checked after construction but before scoring and exits with code **1**.

Valid settings that do not affect the selected objective remain accepted; invalid
supplied controls are rejected even when that objective would ignore them.
Empirical objectives retain their existing one-class conventions. Passing these
checks does not certify independence, guarantee a feasible observed threshold,
bound provider spending, or preflight the output filesystem. Abstentions still
prevent policy creation: every validation record must have a valid score.

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

Newly generated v1 and v2 policy IDs use the first 191 characters of the detector
name plus `-` and a full SHA-256 digest. The canonical identity object contains
`contract: decision-policy-evidence-v1`, the full detector name, task, objective,
`target_fpr_hex` (or null), `validation_sha256`, `evaluation_sha256`,
`threshold_hex`, and the complete `risk_control` object (or null). It is encoded
as ASCII-escaped UTF-8 JSON with sorted keys and compact separators. Thresholds,
targets, and observation scores use Python float hexadecimal strings where
specified; observation rows use the existing ordered ID/label/score digest.
Creation time is excluded, so identical runs retain the same evidence ID.

Changing a label or score changes the ID even when the selected threshold stays
the same. Existing files keep their supplied IDs on load; neither schema nor
historical evidence is rewritten. Schema v1 still omits the separate
`evaluation_sha256` field, although its new ID commits to that digest. Preserve
the underlying observations if you need independent ID reproduction.

Neither schema binds the deployed model weights, prompt, preprocessing, or
provider configuration. The detector field is a name, not verification that a
deployment matches the detector used for calibration. A stronger evidence ID or
trusted policy-file hash does not close that gap; review configuration equivalence
and revalidate after changes before relying on the statistical statement.

## Configuration-bound policies

Schema v3 adds `detector_binding` to either an empirical or risk-controlled
policy. The current profile is `lurescope-portable-tfidf-exact-v1`, restricted to
the fraud task and `tfidf-logreg`. It records SHA-256 identities for the exact
portable JSON artifact, installed portable inference source, and declared
runtime profile. It does not translate the original joblib hash into a claim
that sklearn and portable inference are interchangeable.

Use the companion `lurescope calibrate` workflow on the intended serving runtime
to collect scores with its actual bundled portable implementation. The Python
`build_policy(..., detector_binding=DetectorBinding(...))` API validates and
records a supplied binding; that low-level API does not establish how scores
were collected. Callers remain responsible for the provenance of supplied
observations. Ordinary `lurebench calibrate` continues to produce v1/v2 policies.

V3 requires an evaluation digest for all objectives. Its full-digest ID covers
the binding, detector/task/objective, selected threshold and target as float-hex
strings, validation count and both evidence digests, optional utility counts and
recall, and the risk-control object. The canonical object uses contract
`decision-policy-bound-evidence-v1`, sorted keys, compact separators, and ASCII
escaping; risk-control probabilities are also represented as float-hex strings
inside the identity object. Equivalent integer/float probability representations
therefore retain the same ID. The loader recomputes the ID and rejects
inconsistent evidence; it
also retains the existing count, grid, and bound checks. Creation time is not
part of the ID. The [v3 schema](../spec/decision-policy-v3.schema.json) is included
in the wheel for offline consumers.

A matching binding is not issuer authentication or process attestation, and a
party able to replace both evidence and its ID can construct a new consistent
artifact. Protect trusted policy bytes with an independently approved hash or
your normal signing/release controls. Sampling validity, upstream text extraction,
and deployment population shift remain outside the binding. Legacy files are
still loadable and never relabelled as configuration-verified.

## Assumptions and non-guarantees

The guarantee applies only when all of these conditions hold:

1. Validation negatives are independent, identically distributed draws from the
   target negative-class population. Exchangeability alone is insufficient for
   the exact binomial calculation when observations are dependent.
2. Detector weights, prompt, provider model, preprocessing, score semantics,
   target, confidence, and threshold grid were fixed before this validation run.
3. Labels are sufficiently accurate for the stated false-positive population.
4. The validation set was not repeatedly reused to select the model or redesign
   the grid. If it was, use a fresh holdout.

This independence requirement matches the calibration setup in
[Learn then Test, Section 1.1](https://arxiv.org/html/2110.01052v5).
For fraud, negatives are benign messages; for provenance, they are human-origin
messages, including human-written fraud.

### Rejecting known related negatives

The unreleased `calibrate --objective risk_controlled_fpr` command resolves
transitive declared family, scenario, parent, seed, and rewrite relationships
before constructing the detector. More than one negative in a component stops
the run. Connections through positive records or absent parents still count.
This is a conservative rejection guard, not a cluster-adjusted confidence bound.
It neither selects representatives nor silently drops records. Repeated positives
alone do not inflate the FPR denominator; their recall remains descriptive.

Design a fresh validation sample appropriate to the intended population, or use
an empirical objective with no population-risk guarantee. Do not delete ancestry
annotations to make a run pass. The check cannot find undeclared relationships,
training overlap, repeated users, label error, or distribution shift. One declared
negative per component therefore does not establish independence.

Python `build_policy(..., groups={record_id: component_id, ...})` applies the same
guard for the risk-controlled objective. The mapping must cover all records.
If omitted, the low-level API has no ancestry information and the caller remains
responsible for sampling assumptions. Existing policy schemas and historical
verification remain unchanged; a policy hash is not evidence of an ancestry audit.

It does **not** guarantee recall, precision, subgroup performance, adversarial
robustness, or future FPR after population shift. Monitor deployed score and
label distributions, maintain a newly adjudicated holdout, and issue a new
policy after material model, pipeline, provider, language, channel, or population
changes. A single global guarantee can also conceal poor regional or language
slices; control those as separately predeclared risks when they matter.

## Enforcing a calibrated policy in LureScope

Exporting statistical evidence does not require clients to use it. Compatible
source-branch LureScope adds `LURESCOPE_POLICY_ENFORCEMENT=risk_controlled_bound`
to require a pinned v3 policy, verified portable-model binding, and risk-control
evidence for scoring. Client threshold or detector overrides are rejected;
exploratory evaluation runs on a separate research worker. Generate v3 evidence
with `lurescope calibrate` on the serving runtime, approve its exact bytes through
your trusted release process, and check `lurescope policy --check-readiness`.
Legacy LureBench joblib policies are not silently promoted to portable bindings.
The mode does not establish validation independence or regulatory compliance.
See [LureScope's source-branch enforcement workflow](https://github.com/immu4989/lurescope/blob/feat/lurepermit-lurerange/docs/BOUND_POLICY.md).

## Numerical implementation

The dependency-free binomial calculation sums mode-scaled weights in two streaming
passes. It does not retain the entire distribution. At subnormal magnitudes it
continues in log space, avoiding a binary64 fixed point where successive products
remain equal to the smallest positive float. Tails below floating-point resolution
still round to zero or one; this is not arbitrary-precision interval arithmetic.

For zero observed errors, the one-sided upper bound uses
`-expm1(log1p(-confidence) / negatives)` and takes one outward floating-point step.
This avoids both subtractive cancellation and repeated distribution enumeration.
Nonzero counts retain binomial-CDF inversion. The statistical construction remains
the [exact binomial method described by NIST](https://itl.nist.gov/div898/software/dataplot/refman2/auxillar/exacbino.htm).
Here “exact” names the finite-sample statistical method, not exact machine arithmetic.

Tests compare small tails with 100-digit Decimal finite sums and larger cases
with [SciPy's binomial implementation](https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.binom.html).
SciPy is a test oracle, not a core runtime dependency. Tests also compare nonzero
confidence bounds with independent beta quantiles. Existing artifact bytes and
IDs are not rewritten; newly generated numerical evidence can differ in its last
floating-point digits, which can change a content-derived policy identity.

Numerical consistency tolerance is not extra risk budget. Both reported and
recomputed p-values must be at most `1 - confidence`, and both reported and
recomputed upper bounds must be at most `target_fpr`, without adding an epsilon.
The selector refuses certification if its floating-point p-value and bound
disagree about acceptance. At extreme settings or numerical boundaries this can
be conservative. Previously tolerated borderline artifacts can be rejected;
review or recalibrate them rather than editing their evidence or widening the
target after seeing results. No stored artifact is rewritten by validation.

## Research and governance basis

- Angelopoulos et al., [*Learn then Test: Calibrating Predictive Algorithms to
  Achieve Risk Control*](https://arxiv.org/abs/2110.01052), supplies the
  finite-sample multiple-testing framework and fixed-sequence construction.
- The [NIST AI RMF Measure function](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/)
  calls for pre-deployment testing, uncertainty measures, benchmarks, and
  formalized reporting. This policy is one narrow technical control toward that
  outcome, not AI RMF compliance by itself.
