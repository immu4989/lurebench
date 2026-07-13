# Changelog

## 0.5.0

Extends the benchmark past English. Fraud detectors are trained almost entirely on
English; fraud is not. This release measures how the shipped baselines hold up under a
language shift.

### Added
- **`lurebench multilingual`** and `lurebench.multilingual.cross_lingual_detection()` —
  report fraud-detection **recall per language**, so the deployment gap a monolingual
  benchmark score hides becomes a number. Recall is measured on positives only, so it
  needs no per-language benign set.
- **Language-aware generation** — `lurebench generate --language es` now writes
  native-quality lures in the target language (the prompt uses the language *name*, not
  the ISO code, via `LANGUAGE_NAMES` in `lurebench/generate/base.py`).
- **A multilingual pilot set** (`scripts/build_multilingual_pilot.py`) — hard-mode AI
  lures for `phishing`/`bec` in Spanish, French, German, Portuguese, Italian, and Chinese,
  under the same defensive guardrails as the rest of the corpus.
- **Artifact-controlled evaluation** — the `multilingual` command reports recall both raw
  and with defang placeholders stripped, because the raw number is misleading: a URL
  becomes `<<link>>` (a top fraud feature) in every language, so a detector can post high
  "cross-lingual recall" without reading the lure at all.
- **`docs/multilingual.md`** — the finding, with explicit notes on what it does and does
  not claim, and on which languages were fluency-reviewed vs structure-checked.

### The finding
On the pilot (es/fr/de/zh AI lures vs the English baseline), the trained `tfidf-logreg`
shows a perfect **1.00 raw recall in every language** — which looks like flawless
cross-lingual detection and is not. Strip the defang placeholder and Chinese recall
collapses **1.00 → 0.05** (a placeholder-stripped Chinese lure has zero tokens the
English-trained model has ever seen); European recall survives only on incidental
cognate/token overlap. The keyword `heuristic-v0` collapses outright on any non-English
text. Same confound lesson as the provenance work, now in the language dimension.

## 0.4.0

Adds a **taxonomy and threat-intel interoperability layer** — the government/public-sector
piece. Detection is only half the job; the other half is communicating a detection in
terms another organization can act on.

### Added
- **A formal fraud-lure taxonomy** (`lurebench/taxonomy.py`, v1.0) over the three axes
  LureBench already tags — typology, channel, persuasion technique — with **curated
  crosswalks** to MITRE ATT&CK (precise, stable IDs), the FBI/IC3 crime categories, and
  FinCEN advisories. The crosswalks are clearly marked as LureBench editorial pointers,
  not official designations.
- **`lurebench stix`** and `lurebench.stix` — export the taxonomy and/or any dataset as a
  **STIX 2.1 bundle** for ingestion by fusion centers, ISACs, and threat-intel platforms.
  The taxonomy becomes `attack-pattern` objects (crosswalks as `external_references`);
  each lure becomes an `indicator` (SHA-256 `artifact` pattern) linked by `relationship`
  objects. IDs are deterministic (name-based UUIDv5) and timestamps fixed, so output is
  reproducible and diffable. Both bundle types **pass the official OASIS `stix2-validator`**
  (added to the `dev` extra and exercised in the test suite).
- **`docs/taxonomy.md`** — the standard, the crosswalk tables (generated from code so they
  cannot drift), STIX usage, and the honesty notes on what the crosswalks are and are not.
- `taxonomy.validate()` enforces that the taxonomy and the dataset schema never drift apart.

## 0.3.0

Adds an **adversarial robustness** axis. Clean-data accuracy is the wrong number to
trust in deployment — a real fraudster perturbs the lure until it evades. This release
measures that directly.

### Added
- **`lurebench robustness`** and `lurebench.robustness.run_robustness()` — take the
  lures a detector catches on clean text, apply an attack, and report the **attack
  success rate** (fraction that now evade), alongside clean vs attacked recall. ASR is
  conditioned on clean catches, so a detector that already misses everything cannot
  masquerade as robust.
- **`lurebench.attacks`** — a pluggable attack registry. Four dependency-free,
  deterministic character-level attacks (`homoglyph`, `leet`, `zero-width`,
  `whitespace`) and two LLM-driven attacks (`llm-paraphrase`, `llm-keyword-evasion`)
  that reuse the OpenAI-compatible provider plumbing (your key, never api.openai.com
  or api.anthropic.com). The `Attack` ABC lets you add your own.
- **`llm-keyword-evasion`** is a *targeted* attack: for linear detectors it pulls the
  model's own most-predictive words (via `TfidfLogisticDetector.top_positive_features`)
  and rewrites the lure to avoid them.
- **`recall@FPR`** operating-point metrics (`Metrics.recall_at_1pct_fpr`,
  `recall_at_01pct_fpr`) and `metrics.recall_at_fpr()` — how much fraud you catch at a
  tolerable false-alarm budget, the number a deployment actually tunes to.
- **`docs/adversarial-robustness.md`** documents the suite, the metric, and the
  baseline results (keyword rules collapse under any character attack; the trained
  TF-IDF model degrades gracefully).

### Notes
- Robustness is a *different axis* from clean accuracy and ranks detectors
  differently: `heuristic-v0` looks cheap and interpretable until `vеrifу` defeats it
  (ASR 0.99), while `tfidf-logreg` degrades gracefully (homoglyph ASR 0.38). Homoglyph
  substitution is the most effective free attack against both baselines.

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
