# Changelog

## 0.2.0

Makes the benchmark reproducible and usable by others: the headline finding is now
a first-class command, the corpus loads with one call, and there is a clear path to
contribute a detector.

### Added
- **`lurebench cross-generator`** and `lurebench.cross_generator_provenance()` — the
  leave-one-generator-out provenance evaluation is now a first-class capability, not
  a one-off script. Point it at a naively-assembled corpus and AUC stays near 1.00
  (the confound); point it at a distribution-matched set and it falls toward the 0.50
  chance line. One command reproduces both sides of the finding.
- **`lurebench.load_core(split)`** — download the published `lurebench-core` corpus
  straight from the Hugging Face Hub, no manual file placement. Requires the `hub`
  extra.
- **Balanced accuracy** added to the metrics bundle (`Metrics.balanced_accuracy`),
  and surfaced in the provenance leaderboard table. It is the honest, threshold-
  independent read alongside AUC.
- **`lurebench leaderboard --task {fraud,provenance}`** — score any dataset on either
  question, overriding each detector's default task.
- **[docs/adding-a-detector.md](docs/adding-a-detector.md)** — a short guide to
  contributing a detector (the interface is one method).
- `scripts/build_paired_provenance.py --engine human` persists the human negative
  class, so the paired set is self-contained for `cross-generator`.

### Notes
- The 3-generator distribution-matched provenance result is unchanged: cross-
  generator AUC 0.58 (DeepSeek), 0.57 (GLM), 0.83 (Mistral) vs a perfect 1.00 on the
  naive corpus. See [docs/provenance_results.md](docs/provenance_results.md).

## 0.1.0

Initial public release: schema, ingestion, controlled generation (hard-mode +
paired rewrite), assembly, `heuristic-v0` and `tfidf-logreg` baselines, the
`lurebench-core` corpus, and the confound-and-fix provenance writeup.
