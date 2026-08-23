# Operational adversarial-robustness measurement method

This method measures how a text fraud-lure detector behaves on a declared,
deployment-like cohort and how often bounded attacks evade decisions that were
correct before attack. It is model-agnostic and intended for phishing,
business-email-compromise, and related social-engineering detection systems.

The method produces decision evidence. It does **not** certify a detector,
authorize a deployment, prove compliance, or establish performance outside the
measured population and attack set.

## Measurement contract

Before examining test outcomes, record and freeze:

1. the detector artifact digest, decision threshold, policy identifier, and
   policy digest;
2. the sampling frame and one declared sampling method: complete population,
   consecutive sample, random sample, or a separately documented method;
3. the labeling protocol, adjudication procedure, uncertainty policy, and
   minimum publishable slice count;
4. the confidence level, attack transformations, maximum attack attempts, and
   recovery defenses;
5. the evaluation period and the population to which the result may be applied.

Threshold selection and final evaluation must use separate records. If a
threshold is tuned on the reporting cohort, describe the result as exploratory,
not held-out evidence.

## Procedure

1. Select records according to the frozen sampling declaration. Preserve failed
   processing counts; do not silently remove hard-to-parse messages.
2. Obtain labels without exposing detector decisions to reviewers when
   practical. Retain uncertain labels separately and exclude them from the
   confusion matrix rather than forcing a class.
3. Run the frozen detector and policy once. Record true positives (TP), false
   positives (FP), true negatives (TN), and false negatives (FN).
4. For robustness, attack only eligible positive examples that the clean system
   caught. Preserve the eligible count, the count that evade after attack, and
   the evaded count recovered by the declared defense.
5. Recompute all rates from integer counts. Publish a privacy-minimized
   [LureEval receipt](LUREEVAL.md), suppressing any slice below the predeclared
   minimum.
6. Repeat on a later cohort or materially different site before generalizing a
   result. Pool only protocol-compatible receipts and never average percentages.

## Measures

For a non-zero denominator:

- recall = TP / (TP + FN);
- false-positive rate = FP / (FP + TN);
- precision = TP / (TP + FP);
- evasion rate = successful evasions / eligible clean catches;
- defense recovery rate = recovered evasions / successful evasions.

LureEval reports an exact one-sided Clopper–Pearson lower confidence bound for
recall and an exact one-sided upper bound for false-positive rate. Each bound has
the declared coverage independently; the collection is not a simultaneous
confidence region. A zero denominator produces `null`, never zero.

The robustness denominator matters: testing every positive example would mix
ordinary clean misses with attack-induced evasions. This method asks the narrower
causal question, “of the lures this policy caught, how many did this bounded
attack cause it to miss?”

## Evidence and interpretation

A defensible report includes the frozen control, cohort counts, confusion matrix,
confidence level, exact bounds, attack eligibility rules, attack budget, defense,
failed processing count, uncertain label count, and limitations. Point estimates
without denominators or uncertainty are incomplete.

Use a representative operational cohort for deployment claims. The public
conformance fixtures are synthetic protocol tests and contain no evidence about
detector quality. A passing receipt proves internal structural and arithmetic
consistency; it does not prove that sampling, labels, or issuer statements are
truthful.

## Known failure modes and gaming risks

- **Label leakage:** reviewers or models can learn from metadata correlated with
  labels rather than message semantics.
- **Unrepresentative cohorts:** synthetic, historical, single-language, or
  single-channel data may not transfer to current operations.
- **Adaptive attackers:** a fixed attack catalog underestimates an adversary who
  probes the deployed detector or changes strategy.
- **Threshold overfitting:** selecting and reporting on the same records inflates
  performance.
- **Selective publication:** omitting failed sites, time periods, attacks, or
  uncertain records biases pooled evidence.
- **Correlated sites:** distinct receipts do not guarantee independent cohorts or
  independent errors.
- **Small slices and multiplicity:** low-count subgroup estimates are unstable,
  and many per-slice intervals do not provide simultaneous coverage.
- **Drift:** sender behavior, language, delivery infrastructure, and model
  versions change; receipts expire as evidence even when their signatures remain
  valid.

## Relationship to NIST AI RMF

This method can supply evidence for measurement activities associated with the
NIST AI Risk Management Framework’s MEASURE function, especially empirical
validity, security/resilience testing, monitoring, and documentation. This is an
informative mapping only. NIST has not evaluated or endorsed LureBench, LureScope,
LureEval, or any result produced with them.

## Reproducible protocol check

Install LureBench and run the reviewed semantic vectors without a network or API
key:

```bash
python -m pip install "lurebench==0.11.0"
lurebench conformance --out lureeval-conformance-report.json
```

The conformance result covers serialization, privacy boundaries, schema
boundaries, and metric recomputation. See [CONFORMANCE.md](CONFORMANCE.md) for the
language-neutral implementation contract.
