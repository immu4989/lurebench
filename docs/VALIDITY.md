# Benchmark validity: splits, calibration and uncertainty

LureBench treats test data as a final measurement, not a place to choose a model
or threshold. Version 0.9 introduces the missing infrastructure for that rule.

## Three-way split

`assemble-core` now writes `train.jsonl`, `validation.jsonl` and `test.jsonl`.
The published v1 test membership remains byte-for-byte stable: records with a
`meta.legacy_id` use that pre-v0.8 id for test assignment. Validation is selected
with a separate, domain-separated hash only from the former training pool.

- Train models on `train`.
- Choose models, prompts and thresholds on `validation`.
- Evaluate once on `test`.

Changing the validation objective after inspecting test results is test-set
overfitting even if the model weights do not change.

> **Current published-snapshot limitation.** The tracked v1 `data/full/core`
> snapshot predates materialization of this three-way build and still contains
> only `train.jsonl` and `test.jsonl`. The bundled TF-IDF model was trained on
> that full tracked training file. Do not carve a validation subset from it after
> the fact and claim independence. For a risk-controlled policy, either supply a
> newly collected external validation set or rebuild all three splits with
> `assemble-core` and retrain the detector on the resulting `train.jsonl`. A
> future versioned corpus release should publish the materialized validation
> shard and matching retrained artifacts together.

## Leakage audit

Exact normalized-text deduplication does not catch messages that differ only in
HTML, punctuation or a small footer. Run the dependency-free cross-split audit:

```bash
lurebench audit-splits \
  -s train=data/full/core/train.jsonl \
  -s test=data/full/core/test.jsonl \
  --threshold 0.8 \
  --out split-audit.json \
  --fail-on-leakage
```

The first audit of the published v1 core on 2026-08-05 found **321 cross-split
near-duplicate pairs** at five-word-shingle Jaccard similarity >= 0.8. Four pairs
had similarity 1.0 after tokenization. No explicit family overlap was detectable,
because the source shard predates `family_id` annotations.

This does not retroactively invalidate every result: generator-held-out,
distribution-matched and attack experiments use additional controls. It does mean
the random-split TF-IDF headline should be read as an in-distribution baseline,
not independent external validation. A future corpus major version should cluster
near duplicates and assign whole clusters to one split. Published v1 test membership
is intentionally not rewritten in a minor software release.

For new shards, set `meta.family_id` (or `scenario_id`, `parent_id`, `seed_id`) on
rewrites and variants. The core builder hashes this family key, keeping every
variant in one partition, and the audit fails if an externally assembled shard
nevertheless places a declared family across split boundaries.

## Validation-only policy export

Choose a threshold by maximum MCC:

```bash
lurebench calibrate \
  --validation validation.jsonl \
  --detector tfidf-logreg \
  --model-path models/tfidf-logreg-fraud.joblib \
  --objective max_mcc \
  --out policies/tfidf-max-mcc.json
```

Or maximize recall under a false-positive budget:

```bash
lurebench calibrate \
  -d validation.jsonl -m tfidf-logreg \
  --model-path models/tfidf-logreg-fraud.joblib \
  --objective target_fpr --target-fpr 0.01 \
  -o policies/tfidf-1pct-fpr.json
```

For a finite-sample statement about the population FPR—not only an empirical
validation constraint—use the risk-controlled objective:

```bash
lurebench calibrate \
  -d validation.jsonl -m tfidf-logreg \
  --model-path models/tfidf-logreg-fraud.joblib \
  --objective risk_controlled_fpr --target-fpr 0.01 \
  --confidence 0.95 --threshold-grid-size 1001 \
  -o policies/tfidf-1pct-fpr-95.json
```

This command uses exact binomial tests in a predeclared fixed sequence and fails
closed when the benign sample is too small. At 1% FPR and 95% confidence, even
zero false positives require at least 299 validation negatives. Read the
[method, assumptions, sample-size table, and non-guarantees](RISK_CONTROL.md)
before treating the artifact as a deployment gate.

Every policy records its objective, detector, threshold, validation row count and
a SHA-256 digest of the ordered validation IDs. Risk-controlled schema-v2
policies also commit to ordered labels and scores and carry the exact counts,
p-value, and one-sided FPR bound. LureBench also reports Brier score and expected
calibration error. A policy is not called calibrated merely because someone
placed a threshold in a configuration file.

## Confidence intervals

Point estimates hide sampling uncertainty. Add deterministic paired percentile
bootstrap intervals to an evaluation with:

```bash
lurebench eval -d test.jsonl -m heuristic-v0 --bootstrap 2000
```

Intervals are reported for MCC, recall, FPR and AUC. Equal detector scores are
treated as a single realizable threshold when computing recall at an FPR budget.
