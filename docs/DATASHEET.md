# Datasheet for LureBench

Following the framework of Gebru et al., *Datasheets for Datasets* (2021). This
document describes the **intended** `lurebench-core-v1` corpus. Until the shards
ship on the Hugging Face Hub, the only data in this repository is the 16-record
defanged smoke shard under `data/samples/`, which is not a benchmark split.

## Motivation

**For what purpose was the dataset created?** To measure how well detectors flag
AI-generated fraud lures across fraud typologies and generator families, on a
common schema and harness. Existing public corpora are fragmented single-paper
artifacts — usually one typology, one or two generators, often withheld — which
makes cross-paper comparison unreliable. LureBench aggregates and normalizes what
is public, adds a documented controlled-generation component for typologies with
scarce public data, and freezes a test split for comparable reporting.

**Who created it and who funds it?** Maintained by Imran Ahamed as an open,
independent project. No external funding as of v0.1.

## Composition

**What do instances represent?** Short text messages: fraud lures and benign
controls, each with a provenance label (`ai` or `human`), a fraud typology, and
optional persuasion tags. See [`schema.py`](../lurebench/schema.py) and
[DATA.md](../DATA.md).

**How many instances / what is the intended distribution?** Target for
`lurebench-core-v1` is on the order of 20k–40k records with:

- Roughly balanced fraud vs. benign (≈50/50) at the corpus level.
- Fraud instances stratified across `phishing`, `bec`, `romance`,
  `pig_butchering`.
- Both `human` and `ai` provenance represented within each typology where public
  human data exists.
- `ai` instances spread across a matrix of modern generators (see
  [SHARD_SPEC.md](SHARD_SPEC.md)), not a single model.

**Is it a sample or a census?** A curated sample. It aggregates public corpora
(see [sources.md](sources.md)) plus controlled generation. It does not claim to
represent the full population of real-world fraud.

**What data does each instance consist of?** Processed text plus categorical
metadata. Fraud text is **defanged**: URLs → `<<link>>`, contacts → `<<contact>>`.

**Are there labels?** Yes: `label` (fraud/benign) and `source` (ai/human) are the
two task targets. Both are known by construction — human instances come from
human-written corpora, AI instances from LLM-generated corpora or controlled
generation with a recorded generator id.

**Is any information missing?** Original raw URLs, PII, and any
license-encumbered source text are intentionally excluded or referenced by
pointer rather than redistributed.

**Are there errors / redundancies?** Aggregated corpora may contain near
duplicates; the build pipeline deduplicates by normalized-text hash across
sources before assembling splits.

**Does it contain sensitive or offensive content?** It contains fraudulent and
manipulative text by design. It excludes real personal data, real institution
impersonation with working details, and any live malicious infrastructure.

## Collection process

**How was the data acquired?** By ingesting public datasets through the adapters
in [`lurebench/ingest/`](../lurebench/ingest/), each mapped to the common schema,
plus controlled generation for scarce typologies following the protocol in
[SHARD_SPEC.md](SHARD_SPEC.md).

**Provenance labeling.** `source` and `generator` are assigned from the origin of
each record (which corpus, which model), never inferred by a classifier — the
benchmark must not bake a detector's guess into its own ground truth.

## Preprocessing / cleaning / labeling

Normalization to the `Lure` schema, defanging, deduplication, language tagging,
and persuasion tagging (carried over from source corpora where provided, e.g. the
Cialdini-labeled GPT-o1 phishing set; otherwise left empty in v1). The raw
per-source intermediates are retained privately for reproducibility.

## Uses

**What can it be used for?** Training and evaluating fraud-lure detectors;
measuring generalization across typologies and generators; studying the
provenance-vs-fraud task distinction.

**What should it not be used for?** Generating, personalizing, or delivering
fraud. Producing real-world identity or targeting profiles. Any use that violates
the source corpora licenses.

## Distribution and maintenance

**How is it distributed?** As versioned shards on the Hugging Face Hub, plus this
repository for schema, harness, and build tooling. Restricted source material is
never redistributed.

**Versioning.** Semantic dataset versions (`v1`, `v1.1`, ...); the `test` split is
frozen within a major version. Changes are logged in the shard release notes.

**Who maintains it and how are errors reported?** Via GitHub issues on the
repository. Corrections ship in point releases with a changelog.
