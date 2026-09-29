# Leakage-audit correctness (unreleased)

Cross-split overlap can inflate evaluation results. The motivation is well
established: [Lee et al., ACL 2022](https://aclanthology.org/2022.acl-long.577/)
study training-data duplication and train/test overlap. This implementation is
a small dependency-free lexical and declared-family check, not that paper's
large-scale deduplication system or a test for undisclosed model training data.

```sh
lurebench audit-splits --split train=train.jsonl --split test=test.jsonl \
  --threshold 0.8 --shingle-size 5 --fail-on-leakage
```

The audit compares casefolded word-shingle sets using Jaccard similarity.
`--threshold` accepts finite numbers in [0, 1]; `--shingle-size` must be an
integer from 1 through 20. Short texts use their complete token sequence as
one shingle. Punctuation-only and empty text produce empty sets; by the metric's
existing convention, two empty sets have similarity one. They are therefore
reported conservatively, not silently missed by the inverted index.

At threshold zero **every cross-split pair qualifies**, including disjoint
texts. This intentionally requires quadratic output and can be expensive;
use a positive threshold for ordinary corpus audits. Even positive thresholds
can produce quadratic work/output when most records share shingles.

The audit requires at least two named splits. Repeated CLI split names and
empty names/paths are rejected instead of overwriting an earlier input. A
family present in three splits reports all three affected boundaries. Family
components now connect **all** populated `family_id`, `scenario_id`, `parent_id`,
`seed_id`, and `rewrite_of` fields, including references to other record IDs.
Chains and cycles merge transitively; absent-parent references can still connect
siblings. Conflicting annotations conservatively merge components. Invalid
annotation types fail rather than being string-coerced. Repeated IDs across
splits are reported as leakage; conflicting annotations on the same ID fail.
This only covers declared relationships, not undisclosed ancestry. Component
labels are deterministic under input reordering, not additions to the corpus.

The core-v2 builder uses these same lineage components and also groups
empty-shingle records together. Before exact-text deduplication removes a record,
it merges text equivalence with original ancestry. Affected retained records
receive a derived `meta.family_id` so removing a parent or duplicate cannot erase
a cross-family connection. Original in-memory inputs are not mutated; derived
output metadata can differ from source annotations, whose source commitments
remain in the build manifest. V1's frozen split assignment is unchanged.
Previously built corpora are not silently regenerated or relabeled.

## Meaning of a pass

A pass means no overlap was found by these **specific lexical and family
rules** in the supplied splits. It does not prove independence, semantic
novelty, lack of paraphrase leakage, truthful provenance, or absence from a
frontier model's training data. Empty split sizes are reported explicitly;
a vacuous pass is not evidence of adequate evaluation coverage. Review raw
record identifiers before publishing reports because audit findings include IDs.

Regression tests compare the indexed algorithm with exhaustive all-pairs
Jaccard checks across zero/positive thresholds, multiple shingle sizes,
empty sets, punctuation, case variants, short messages, and Unicode text.
