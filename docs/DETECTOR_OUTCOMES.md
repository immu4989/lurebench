# Detector outcomes and missing evidence (unreleased)

A detector returns a finite real score in `[0, 1]`, or `None` to abstain.
This bounded interface does not establish probability calibration for a heuristic
or safety/provenance proxy.
Booleans, numeric strings, non-finite numbers, and out-of-range values violate
the contract. Scoring, collection, cached scores, and hard predictions now reject
these values instead of coercing them into benchmark observations. An invalid
cached value fails without silently spending money to query the provider again.

LLM fraud and provenance judges now accept only a complete canonical ASCII
integer `0` through `100`, with optional surrounding ASCII spaces/tabs/newlines.
Explanations, percentages, JSON, word labels, multiple numbers, signed/decimal
numbers, out-of-range values, and Unicode digits cause abstention. The parser
does not extract the first number, clamp an invalid score, or guess from keywords.

This changes the judge measurement contract. Its score cache identity now binds
the parser version, prompt, task, provider endpoint, resolved model, generation
settings, and optional caller `cache_context`. Legacy or mismatched contexts for
the same detector name stop before paid work. Preserve old results; explicitly
choose a new cache path and budget a new experiment rather than presenting old
cached scores as measurements under the new parser. Injected completion
functions require a caller-provided `cache_context` for persistent score caching.
These identities describe configuration, not publisher authentication or proof
that a provider has kept its backend unchanged.

`Detector.predict()` still returns an integer for a valid score, but now raises
`DetectorAbstainedError` when the detector abstains. Previously it returned zero.
Callers must explicitly decide how to handle an unavailable prediction.

## Moderation category contract

The moderation adapter consumes one standalone text result using the 13-category
profile documented for `omni-moderation-latest`: harassment and threatening
harassment, hate and threatening hate, illicit and violent illicit content,
self-harm, self-harm intent and instructions, sexual content and sexual content
involving minors, violence, and graphic violence. The result must contain a
boolean `flagged` field and every category score as a finite non-boolean real
value in `[0, 1]`. Wire category names and SDK attribute aliases are accepted;
duplicate aliases, unknown categories, missing values, and multiple results fail.
This fixed profile is deliberate: older or different taxonomies need a reviewed
adapter change, not silent omission of unsupported categories.

The numeric result remains the maximum category score. The adapter never
substitutes `flagged` for absent numeric evidence, ignores malformed values, or
converts them into zero. Invalid responses raise `ModerationResponseError`
without caching a score. Transport/SDK exceptions still propagate. Benchmark
callers should record a detector error, not interpret failure as benign or as a
successful abstention. Complete valid zero scores remain valid.

Moderation detects content-safety categories, not fraud, and its maximum is not
a calibrated fraud probability. The provider can update the underlying model;
policies based on category scores can therefore need recalibration. See the
[official response guidance](https://developers.openai.com/api/docs/guides/moderation#understand-moderation-results).
The adapter validates the values exposed by the SDK or injected client, not raw
HTTP bytes; it cannot undo transformations already performed by that client.

Persistent caches bind the parser/profile, requested model, configured endpoint,
SDK version, task, and optional reviewed `cache_context`. A model alias does not
pin remote weights. Preserve legacy name-only caches and use a new path for a
new experiment; use the recorded old identity only for historical replay.
An injected `client=` must supply `moderations.create` and needs a lowercase
SHA-256 `cache_context=` for persistent caching. That context is the caller's
assertion about custom client behavior/configuration, not authentication.
Do not mutate a configured client after creating its cache.

## Trained binary classifier semantics

`TfidfLogisticDetector(model_path=...)` now uses the artifact's saved `task`:
`fraud` means class 1 is fraud, while `provenance` means class 1 is AI authorship.
Passing an explicit `task=` asserts that it matches the stored metadata; it does
not relabel a trained model. Missing or unknown task metadata fails closed.
`from_pipeline(pipeline, task=...)` still requires an explicit known task, whose
meaning is the caller's responsibility. Valid fraud artifacts retain their scores.

Pipelines must have exactly the two integer class labels 0 and 1, in either
order, and a callable `predict_proba`. Boolean, string, floating-point, duplicate,
single-class, and multiclass labels are rejected before inference. The adapter
selects the column labelled 1; it never substitutes the last column when that
label is absent. This follows [scikit-learn's probability-column contract](https://scikit-learn.org/stable/modules/generated/sklearn.linear_model.LogisticRegression.html#sklearn.linear_model.LogisticRegression.predict_proba).
Both output columns are checked: one row, two finite non-boolean real values in
`[0, 1]`, summing to one within absolute tolerance `1e-6`. The tolerance permits
float32 rounding; values are not renormalized. Changed class mappings before or
during inference raise rather than silently reversing the score's meaning.

For binary linear models, positive coefficients point toward `classes_[1]`.
Feature rankings reverse that direction when label 1 is in the first column.
Unsupported or inconsistent feature metadata yields no feature explanation;
these rankings remain model coefficients, not causal explanations or proof of
calibration.

**Only load trusted joblib files.** These checks happen after deserialization and
do not authenticate metadata, inspect arbitrary Python behavior, or sandbox a
model. [Joblib persistence can execute arbitrary code](https://scikit-learn.org/stable/model_persistence.html#security-maintainability-limitations).
Review trusted legacy models in their original environment before re-exporting
missing metadata; do not guess a task from a filename or assign labels to make a
rejected model pass. Preserve historical results. LureScope's pinned data-only
serving profile does not use this joblib loader and is unchanged by this contract.

## Llama Guard safety verdicts

The optional Llama Guard 3 adapter follows the
[documented verdict format](https://dev.meta.ai/llama/docs/model-cards-and-prompt-formats/llama-guard-3):
`safe`, or `unsafe` followed by a newline and distinct comma-separated categories
`S1` through `S14`. Surrounding ASCII whitespace is allowed; partial verdicts,
explanations, contradictory output, unknown categories, and empty output abstain.
The old prefix parser treated every non-`unsafe` response as benign. Historical
results and caches are not retroactively corrected by changing the parser.

Input over 100,000 characters or the configured token budget abstains without
silently dropping part of the message. Default token budget is 8,192. Generation
uses a 128-token cap; reaching that cap abstains even if the prefix looks valid.
Runtime/loading failures still raise rather than becoming a benign result.

The Python constructor accepts `revision=` as an immutable 40-character lowercase
Hub commit and `local_files_only=True` to request offline loading. Persistent
score caching requires that revision or an external `cache_context=` SHA-256
identity for reviewed local/unpinned artifacts. The namespace also binds parser,
model identifier, device, input/output limits, and tokenizer chat template.
Use a new cache path; older prefix-parser scores are not compatible. Pins identify
configuration and do not prove safety, immutable local files, or publisher trust.

The hard 0/1 output is a **safety-taxonomy proxy**, not a calibrated fraud
probability. An accepted `safe` answer does not establish that a message is not
fraud. See [dependency security](DEPENDENCY_SECURITY.md) for the still-unresolved
optional Accelerate advisory and the limits of explicit loader flags.

## Binoculars provenance baseline

Default `BinocularsDetector()` construction is disabled before importing the
optional upstream package. The [upstream source inspected on 12 October 2026](https://github.com/ahans30/Binoculars/blob/main/binoculars/detector.py)
loads two models with `trust_remote_code=True` and tokenizes with truncation.
An application must not trigger those side effects merely by enumerating or
selecting a baseline. A reviewed backend can instead be supplied explicitly:

```python
from lurebench.detectors.binoculars import BinocularsDetector
from lurebench.harness import run

# These objects come from your separately reviewed artifact-loading process.
detector = BinocularsDetector(
    backend=reviewed_backend,
    cache_context=reviewed_backend_manifest_sha256,
)
report = run(detector, held_out_records, task="provenance")
```

The backend must expose `compute_score(text)`, a callable `tokenizer`, and an
integer `max_token_observed` between 1 and 128,000. Tokenization must honor
`truncation=False` and return `input_ids` as a flat list of nonnegative integers.
Input over 100,000 characters, fewer than two tokens, or above the backend's token
budget abstains before inference. Malformed tokenizer output and changes to the
captured tokenizer or token limit fail before the scoring call. Backends must be
trusted, stable, and separately reviewed for thread safety; this is not a Python
sandbox, a tokenizer memory bound, or an atomic concurrent-artifact guarantee.

Operators who deliberately accept the upstream loading behavior may use
`BinocularsDetector(allow_unsafe_upstream=True)` after reviewing and installing
a pinned upstream implementation in an isolated environment. This opt-in does
not disable remote code, pin its model revisions, force Safetensors, prevent
downloads, or repair vulnerable dependencies. It is not exposed by LureScope's
HTTP request models. No real upstream model was loaded in the adapter tests.

Raw outputs must be finite positive real scalars. NaN, infinities, booleans,
strings, lists, zero, and negative values raise without becoming a cached score.
Previously, NaN could become `1.0` through clipping. Valid historical values keep
the transform `clip((0.95 - raw) / 0.30 + 0.5, 0, 1)`. This is an **uncalibrated
provenance ranking proxy**, not `P(ai)`, a fraud probability, or the upstream
`predict()` operating point. Clipping can introduce ranking ties; do not claim
this wrapper reproduces the upstream paper's operating characteristics.

Persistent caching requires a lowercase SHA-256 `cache_context` supplied by the
operator to identify reviewed backend code, both models, tokenizers, and numerical
configuration. The namespace additionally binds the score-contract version and
input limits. It does not authenticate those artifacts or automatically verify
the supplied manifest. Legacy or different-context caches fail rather than being
silently reused. Preserve old results and use an explicit new cache path.

## Ordinary evaluation

`run` and `collect_scores` prepare the entire input before detector callbacks:
each record is copied and revalidated as a `Lure`, and its ID and task target are
captured separately. A callback that changes its supplied record cannot change
the ground truth used for its score or abstention, or mutate caller-owned nested
metadata through that record. Invalid later records fail before any score call.
An explicit task must be `fraud` or `provenance`; only `None` selects the detector's
declared task (or `fraud` when it has no task attribute).

Preparation uses extra memory proportional to the dataset and nested metadata.
Callbacks receive ordinary mutable Lure copies, not subclasses or shared caller
objects. Store intentional annotations separately instead of relying on mutations
to propagate back. Repeated IDs/references retain their observation slots; copying
does not prove independence, authenticate labels, or remove leakage. Cache warming
also validates and copies all records before scheduling. Leaderboards validate
thresholds, task overrides, workers, and records before detector construction,
then retain a private snapshot for slices. Direct detector calls and constructors
remain separate boundaries. Concurrent caller mutations during preparation are not an atomic
snapshot, and arbitrary in-process detector code is not sandboxed or prevented
from accessing labels. Use the separate container protocol for withholding labels
from a detector's request payload.

Leaderboard detector specifications are parsed as a complete plan before any
constructor runs. Malformed later names, model/engine syntax, or keyword mappings
reject the plan without scoring earlier detectors. Names/model/engine text must
be nonempty, at most 1,024 characters, and free of controls and surrounding
whitespace; pair forms require exactly `(name, mapping)` (or `None` for no
keywords). A bare string is not a sequence of detector specifications. This
validates syntax, not installed extras, credentials, or arbitrary constructor
arguments; runtime detector failures still produce per-detector error rows.

Headline metrics remain conditional on answered records. `n_skipped` reports
abstentions; the human-readable summary now displays it too. A metric over zero
answered records is not evidence of good performance. Do not compare conditional
recall without also comparing answer coverage and the evaluation populations.

`Report.coverage_summary()`, ordinary evaluation JSON, and new leaderboard rows
also expose positive/negative-class answer coverage and logical full-population
accuracy, recall, and FPR bounds. These enumerate the best/worst possible binary
resolutions of unanswered records, without assuming that missingness is random.
For example, one caught positive and two abstained positives yield conditional
recall 1.0 but positive coverage 1/3 and full-population recall bounds `[1/3, 1]`.
An absent class has undefined (`null`) bounds, not a zero rate. Exhaustive tests
compare these formulas against all binary completions of 1,296 four-record
label/outcome configurations.

Leaderboard slices now reuse the exact ordered score snapshot from the headline
evaluation, including abstentions. They no longer call the detector again to
recompute each slice, avoiding extra provider requests and inconsistent slices
from a stochastic or stateful detector. The snapshot is local in-memory data;
the summary JSON does not include raw message text or per-record scores.

## Robustness evaluation

`run_robustness` validates and copies the entire dataset before scoring, including
negative records. Clean and attacked scoring receive separate nested copies;
mutating a clean scoring record cannot change the text later given to the attack.
This does not verify that the attack preserves intent or sandbox callback code.

Adaptive attacks also enforce this contract. A missing clean/rewritten score
raises `DetectorAbstainedError`; invalid scores, non-string/empty generations,
or invalid budgets stop explicitly. A failed run is not reported as resistance.
The adaptive experiment script persists completed score/generation cache entries
across such failures. Already-running concurrent requests may still finish; this
does not cancel provider billing or establish an exactly-once execution guarantee.

Generated adaptive reports now describe score drops **pending intent review**.
Prompting a rewriter to preserve fraudulent intent does not verify that it did so.
Replicate ranges are descriptive, not confidence intervals, and separate cache
namespaces do not prove independence. Historical published tables are unchanged;
the corrected measurement contract requires a separately budgeted rerun.

Only positive records detected on clean text are eligible for attack evaluation.
An attacked score below the threshold is an observed evasion; an abstention is
unknown, not evasion and not successful defense.

The report now exposes:

- `n_abstained_clean`: positives whose clean result was unavailable.
- `n_abstained_after`: eligible attacks whose result was unavailable.
- `n_evaded`: eligible attacks with a valid below-threshold score.
- `attack_success_rate`: `null` if any eligible attacked outcome is missing,
  or if no clean detections were eligible; otherwise observed evasions / eligible.
- `attack_success_rate_lower` and `attack_success_rate_upper`: respectively
  evasions / eligible and (evasions + unknown attacked outcomes) / eligible.
  Both are `null` with no eligible records.

These are logical bounds on missing outcomes, **not statistical confidence
intervals**. With two evasions, one detection, and one abstention among four
eligible attacks, the result is inconclusive with bounds `[0.50, 0.75]`.

The legacy recall columns are observed detection fractions over all positives;
the attacked column evaluates only the clean-detected subset and is not a full
post-attack evaluation of every positive. Clean abstentions remain disclosed
separately. Lower clean coverage can change the eligible population, so ASR alone
is not a fair cross-detector comparison.

The cached LLM robustness script uses the same missing-outcome distinction.
Historical published results have not been silently rewritten or rerun. These
source-branch changes require clients to handle nullable ASR and explicit
prediction errors; they are not part of the existing PyPI 0.11.0 release.

## Public statistical entry points

Bootstrap JSON includes requested/defined/undefined resample counts and a
`conditional_on_defined` flag. Console output shows defined/requested counts.
For example, an AUC resample containing only one class is undefined and excluded;
the resulting quantiles are conditional on defined resamples. A nominal 95%
percentile interval is not a distribution-free coverage guarantee, especially
with tiny classes, clustered records, or prior selection on answered scores.

Ranking metrics accept arbitrary finite real margins (not only probabilities),
but reject NaN, infinity, booleans, and nonnumeric inputs before sorting or tie
sweeps. Labels/predictions must be binary integers. Calibration requires finite
probabilities in `[0, 1]`; missing scores must be handled explicitly before calling
it. It does not infer that answered observations represent missing ones.

Empirical threshold selection uses a tie-aware `O(n log n)` sweep, retaining MCC,
recall, and higher-threshold tie-breaking. Candidate thresholds remain in `[0, 1]`.
If a negative has score exactly one, a zero-FPR target may be unattainable and now
raises an error rather than exporting a threshold that serving cannot accept.
This does not create a statistical guarantee for empirical threshold selection.

The `calibrate` CLI requires answered scores for **every** input record: it refuses
to export a policy after abstentions rather than silently calibrating a selected
subset. Policy construction also rejects duplicate/ambiguous record IDs. Unique IDs
do not prove independent observations; near-duplicates, common senders/campaigns,
selection bias, and dataset reuse still require study design and audit.
