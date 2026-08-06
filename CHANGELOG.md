# Changelog

## 0.9.0

### Added
- A new research-console visual identity, accessible SVG repository hero, and a
  clearer README path from headline finding to benchmark and live lab.
- A deterministic validation split carved exclusively from the former training
  pool. Frozen test membership is preserved across the v0.8 id migration by
  hashing `meta.legacy_id` where present.
- `audit-splits`: dependency-free cross-split family and near-duplicate detection.
  The first v1 core audit found 321 train/test pairs at five-word-shingle Jaccard
  similarity >= 0.8; this limitation is documented rather than hidden.
- `calibrate`: validation-only selection of maximum-MCC or target-FPR thresholds,
  exporting a versioned policy with validation provenance.
- Brier score, expected calibration error, reliability bins and deterministic
  paired-bootstrap confidence intervals for MCC, recall, FPR and AUC.

### Fixed
- Recall-at-FPR no longer processes equal scores one record at a time. Tied scores
  now move together, so every reported operating point can be realized by a
  threshold.
- The `train`/`all` extras now constrain scikit-learn to the 1.6 series used to
  serialize the bundled LureScope model, avoiding unsupported cross-version
  unpickling in unconstrained future environments.

## 0.8.1

### Fixed
- **Provider configuration errors were reported as detector abstentions.** A 401,
  403 or 404 from the provider returned `None`, which the harness counts as the
  detector declining that record. Because such a failure is a property of the
  configuration rather than of the record, it fails identically every time: a
  mistyped model id, an expired key, or a model the account cannot route to
  produced a plausible-looking row of 100% abstentions after burning one request
  per record.

  These now raise `ProviderConfigurationError`, are not retried (there is nothing
  to retry), and carry the model id, the status code and a hint. Genuine
  per-record abstentions, transient network failures, and 429/5xx retries are all
  unchanged.

  A model rejection carried on a 400 is escalated the same way, but only when the
  provider's message names the model we sent. 400 is ambiguous where 401/403/404
  are not: it also covers per-record problems such as an over-long message, where
  abstaining is the right response, and escalating every 400 would end a sweep
  over one oversized record.

  Found while testing `deepseek/deepseek-v4-flash-0731`, released 2026-07-31.
  OpenRouter answers it with 404 for accounts that have not opted into the
  provider's data policy; DeepSeek's official API answers it with 400 and "The
  supported API model names are deepseek-v4-pro or deepseek-v4-flash". Both
  scored clean columns of "abstentions" before this fix.


## 0.8.0

**Breaking data change.** Record ids in the shipped shards have changed. Anything
that pinned a specific id needs updating; the previous value is preserved on each
record as `meta.legacy_id`.

### Fixed
- **Generated records had colliding ids.** `generate_records` minted
  `gen-{typology}-{seq}` with no generator in the id, so every model restarted the
  same counter and running one typology across three models produced three
  different records all called `gen-bec-000006`. `rewrite_records`, two functions
  below, already did this correctly, which is why the `paired/` shards were clean.

  Scope: 170 colliding ids in `core/train`, 30 in `core/test`, 13 in
  `multilingual/eval`, and the same in the `core/hub/` copy published to the Hub.
  Every AI-generated record was affected (87/87 in `core/test`).

  This is not cosmetic. The train/test split hashes the record id, so colliding
  records were forced into the same split instead of being assigned
  independently, and anything building a dict keyed by id silently kept only the
  last record. That is exactly what happened downstream in LureScope's
  cross-model scorecard, where a stated 120-lure sample was really 73 distinct
  records.

  Ids are now `gen-{typology}-{generator}-{seq}`, matching the `rw-` convention.
  `scripts/fix_duplicate_ids.py` migrates existing shards; it asserts that row
  counts, text, labels and every non-id field are unchanged, and is idempotent.

- **CI was not linting, then linted with an unpinned ruff.** The lint step added
  in 0.7.0 installed whatever ruff was latest, so CI picked up 0.16's changed
  default rule set and went red on a commit that passed locally on 0.15. The rule
  set is now declared explicitly and ruff is pinned to a range. `E501` is
  documented as a known gap rather than silently enabled: 59 lines exceed the
  configured limit and fixing them belongs in its own pass.

- The STIX validator test failed CI on correct output. `stix2-validator` loads its
  schemas from a git submodule that is not in the published wheel, so a
  pip-installed copy reports every bundle invalid, including the example copied
  from the STIX 2.1 specification. The test now checks the validator against
  known-good input and skips if it disagrees, rather than asserting against a tool
  that cannot work. (This was masked until now: the lint step runs first, so the
  test step never executed while lint was red.)

- Two tests asserted that `openai-moderation` raises without its extra, which is
  only true when no key is present. They passed in CI and failed for anyone with
  `OPENAI_API_KEY` exported. Now hermetic.

### Added
- `duplicate_ids()` plus `n_unique_ids` / `n_duplicate_ids` in the manifest, and a
  `check_balance` warning, so a shard with colliding ids says so.
- `tests/test_record_ids.py`, including a guard asserting every shipped shard has
  unique ids. It fails against the pre-migration data, which is the check that was
  missing when the collisions were introduced.


## 0.7.0

Makes LLM-backed detectors measurable, then measures them. Six models scored
across the fraud, multilingual and provenance tasks, plus an adaptive attack.
Two of the changes below are corrections to results this project previously
published.

### Added
- **Score caching** (`lurebench/detectors/cache.py`, `lurebench/diskcache.py`).
  `CachedDetector` memoises to disk; `prewarm()` fills the cache concurrently so
  the sequential harness then runs at cache speed. Re-running an evaluation to
  regenerate a table is free, and an interrupted sweep resumes.
- **Completion caching** (`lurebench/generate/completion_cache.py`) for attack
  rewrites, cutting a re-run of the adaptive experiment from 292 new calls to 13.
- **Detector specs.** `evaluate_detectors` accepts `name@engine/model`, so one
  leaderboard carries a row per model. Exposed as `--detector/--cache-dir/--workers`.
- **`llm-judge-provenance`** detector: asks whether an AI wrote the text, ruling
  out scamminess and the uniform defang placeholders as proxies.
- **`AdaptiveParaphraseAttack`**: rewrites until the detector stops flagging,
  reporting attempts-to-evade rather than a single yes/no.
- **`openrouter` provider preset**, reaching many models through one key.
- **`extra_params`** on `OpenAICompatibleGenerator`, so callers can send
  `reasoning.effort` and stop reasoning models returning empty answers.
- New result docs: `docs/leaderboard.md` (now eight rows), `docs/multilingual_llm.md`,
  `docs/provenance_llm.md`, `docs/adaptive_robustness.md`.
- Community infrastructure: `CODE_OF_CONDUCT.md`, `SECURITY.md`, issue and PR
  templates, Dependabot, pre-commit, and a JOSS `paper.md`.

### Fixed
- **Silent abstentions inflated every metric.** A detector that declined a record
  returned `None`, and the harness excluded those from the metrics, so a model
  answering half the corpus scored a flawless 1.000 MCC/TPR/AUC. The only symptom
  was a per-typology recall that disagreed with the headline TPR. `n_skipped` is
  now carried into results and rendered as a `scored` column, and slice recall
  excludes abstentions so it agrees with TPR. On a 60-record probe, `gpt-5-nano`
  went from 31/60 abstained and a fake-perfect 1.000 to 0 abstained and an honest
  0.614 MCC at a 29% false-positive rate.
- **Truncated responses killed whole sweeps.** `http.client.IncompleteRead` and
  `RemoteDisconnected` subclass `HTTPException`, not `OSError`, so they escaped
  the retry loop. Now retried.
- **A cache flush race** dropped detectors from a leaderboard: every writer staged
  to one shared temp filename, so concurrent flushes collided in `os.replace`.
  Temp files are now per-thread.
- Attack generation is pinned to `temperature=0` (generation still samples at 1.0),
  so an attack is a measurement rather than a draw.

### Changed
- **Adaptive robustness now reports replicates, not point estimates.** Hosted
  providers are not deterministic even at temperature 0: re-running the identical
  setup moved one model's evasion rate by 17 points. Rates are the mean of three
  runs with the observed range. The finding survives (`tfidf-logreg` 9% [9-10]
  against judges at 35% [29-46] and 40% [37-42]) but the two judges cannot be
  told apart, which the earlier point estimates hid.


## 0.6.0

Adds **`llm-judge`** — the first strong fraud detector in LureBench that a user can
actually run without a GPU or OpenAI credits — and stress-tests it against the same checks
that broke the baselines.

### Added
- **`llm-judge` detector** (`lurebench/detectors/llm.py`) — asks an LLM for a 0–100
  fraud-likelihood over the OpenAI-compatible provider plumbing that powers generation
  (DeepSeek / GLM / Mistral / …, your own key, never api.openai.com or api.anthropic.com).
  Any provider by name; Mistral is the fast default, reasoning models (DeepSeek/GLM) need
  the higher `max_tokens` the detector sets by default. Plugs into every existing harness.
- **`docs/llm-detector.md`** — the detector and the two experiments below, with the honest
  limits (pilot scale, one provider, cost/latency, the paraphrase weakness).
- **Reproducible score caches** (`data/full/multilingual/llm_scores_deepseek.json`,
  `llm_robust_deepseek.json`) and the concurrent scorers `scripts/score_llm_multilingual.py`
  and `scripts/score_llm_robustness.py`.

### The findings (DeepSeek, pilot scale)
- **It closes the cross-lingual gap.** Where `tfidf-logreg`'s recall collapsed on non-Latin
  scripts under artifact control (Chinese 0.09, Russian 0.06, Arabic 0.04 — the recall was
  the `<<link>>` placeholder), `llm-judge` holds: **Chinese 0.91, Russian 0.97, Arabic
  0.95**. It reads the fraud, not the redacted URL. (Honestly: its raw recall is lower than
  tfidf's inflated ~1.00, and it uses the placeholder as a minor signal on Latin scripts.)
- **It survives the character attacks.** The homoglyph/leet/etc. attacks that drove
  `heuristic-v0` to ASR ~1.00 barely touch it (ASR 0.04–0.08). Its one real weakness is a
  semantic **LLM paraphrase** (ASR 0.17) — you beat a content detector by rewriting the
  lure, not by mangling characters.

## 0.5.1

Hardens the two things most likely to be questioned when the work is cited: the taxonomy
crosswalks and the scale of the multilingual pilot.

### Changed
- **Taxonomy crosswalks verified against primary sources** (taxonomy v1.1). Every
  FinCEN/IC3 reference now carries its exact published identifier, title, date, and URL,
  checked against the issuing agency (see `SOURCES_VERIFIED`). This **corrected a factual
  error**: the pig-butchering typology cited FinCEN `FIN-2023-Alert006`, which is actually
  a terrorist-financing alert — the correct pig-butchering alert is `FIN-2023-Alert005`
  (Sep 8 2023). BEC now cites `FIN-2019-A005` (Jul 16 2019); the GenAI-fraud dimension
  cites FBI/IC3 `I-120324-PSA` (Dec 3 2024) and FinCEN `FIN-2024-Alert004` (Nov 13 2024).
  The mapping remains editorial (not an official designation), but every target is now an
  auditable, dated document rather than a vague pointer.
- **Multilingual pilot scaled.** The two thinnest cells were generated up — Arabic 9 → 56,
  Portuguese 3 → 28 — so no language is reported on a trivial sample (all now 22–56, 255
  non-English lures total). The finding is unchanged and now better powered: Arabic
  collapses 0.98 → 0.04 under artifact control on 56 lures. The script gained a
  `--languages` filter for targeted top-ups.

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
On the pilot (AI lures in eight languages vs the English baseline), the trained
`tfidf-logreg` shows a perfect **~1.00 raw recall in every language** — which looks like
flawless cross-lingual detection and is not. Strip the defang placeholder and the result
splits cleanly along script lines: Latin-script recall survives (es/fr/de/it 0.91–1.00, on
incidental cognate overlap), while **every non-Latin script collapses** — Chinese 1.00 →
0.09, Russian 0.94 → 0.06, Arabic 1.00 → 0.00. In those scripts a placeholder-stripped lure
has almost no tokens the English-trained model has seen, so the recall was entirely the
`<<link>>` artifact. The keyword `heuristic-v0` collapses outright on any non-English text.
Same confound lesson as the provenance work, now in the language dimension, confirmed
across three independent scripts.

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
