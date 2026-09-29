# Cross-generator, unseen-lineage evaluation (unreleased)

Holding out a generator does not by itself hold out the underlying phishing
scenario. In a paired-rewrite corpus, training on generator A's rewrite of a seed
and testing generator B's rewrite of that same seed can reward memorized scenario
content. This source branch therefore defaults `cross-generator` to
`--split-mode lineage_disjoint`.

```sh
lurebench cross-generator -d data/full/paired/human.jsonl \
  -d data/full/paired/deepseek-v4-pro.jsonl -d data/full/paired/glm-4.6.jsonl \
  -d data/full/paired/mistral-large-latest.jsonl --split-mode lineage_disjoint
```

This trains the local TF-IDF detector. It makes no provider calls and generates
no new lures. The default policy is a source-branch change, not PyPI 0.11.0.

## Exact split rule

1. Require unique record IDs and generator names on every AI record. Construct
   connected components from record IDs and all declared `family_id`,
   `scenario_id`, `parent_id`, `seed_id`, and `rewrite_of` references. The
   [leakage audit](LEAKAGE_AUDIT.md) uses the same declared-lineage relationships.
2. Canonically label each component with its lexicographically first explicit
   annotation token, falling back to its first record ID. Hash UTF-8 bytes of
   `lurebench-logo-lineage-v1` + NUL + the label with SHA-256. Interpret the digest
   as a big-endian integer. A component is held out if the integer modulo `k`
   is zero (`--human-holdout-k`, default 5).
3. For each generator, train on human records plus other-generator AI records
   from non-held-out components. Evaluate human records and that generator's AI
   records only from held-out components. All other records are excluded from
   that fold, not moved across boundaries to fill an empty class.
4. Validate every fold has both classes in training and evaluation **before any
   training starts**. Sort fold records by ID for order-invariant input to the
   trainer. Invalid or missing scores fail; no missing value becomes benign.

The report gives split mode, train/test sizes, component counts, and declared
component overlap. Hash allocation is approximately 1/k, not an exact class
balance guarantee. Small or heavily connected corpora can fail. Do not search
different split controls until performance looks favorable. Add independently
collected data or preregister a changed design, then report that change.

## Historical reproduction and limits

### Local paired-corpus check, 2026-09-29

The [aggregate study report](lineage-study-2026-09-29.json) pins the four input
shards, relevant source files, parsed records, and recorded library versions.
It contains no message text. On the same 1,072-record corpus, the historical
run reproduces AUC 0.583 / 0.574 / 0.835 and exposes 245 / 260 / 294 shared
lineage components across training and test. The stricter protocol reports:

| Held-out generator | Test AI | Test human | AUC | Balanced accuracy at 0.5 | Declared lineage overlap |
|---|---:|---:|---:|---:|---:|
| DeepSeek V4 Pro | 40 | 55 | 0.787 | 0.741 | 0 |
| GLM 4.6 | 41 | 55 | 0.776 | 0.671 | 0 |
| Mistral Large Latest | 55 | 55 | 0.926 | 0.836 | 0 |

These **different training and test samples** do not measure a paired model
improvement or show that removing leakage causes higher performance. The fixed
hash rule was implemented before this run; no split search was performed.
Small shared cohorts, source confounds, and missing uncertainty analysis limit
interpretation. The run made no paid/provider calls or new generations. Reproduce
both protocols locally from the repository root using the training extra:

```sh
python scripts/eval_lineage_provenance.py --out /tmp/new-lineage-study.json
```

The destination must not exist. Numerical results may vary across dependency
versions; compare the recorded environment and exact input/source hashes. The
hashes are local observations, not authenticated loaded-code attestations.

### Legacy mode

`--split-mode legacy_index` retains the previous every-kth-human test slice,
training on all other-generator AI and testing all held-out-generator AI. It
reports declared-family overlap but does not remove it. It is only a historical
comparison, not the new default or evidence of unseen-family generalization.
Existing result tables and frozen corpus shards are not silently overwritten.

The stricter split handles **declared** ancestry only. It does not discover
unannotated paraphrases, pretraining contamination, common campaigns, or source
artifacts; use lexical audits and provenance review too. Components need not be
statistically independent, and folds reuse data. AUC has no selected decision
threshold; balanced accuracy, recall, and FPR do. Near-chance point estimates
do not establish equivalence or prove a detector cannot generalize. No population
confidence bounds or live deployment safety claims follow from these scores.
