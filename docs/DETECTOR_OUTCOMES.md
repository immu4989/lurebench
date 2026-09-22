# Detector outcomes and missing evidence (unreleased)

A detector returns a finite real probability in `[0, 1]`, or `None` to abstain.
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

## Ordinary evaluation

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
