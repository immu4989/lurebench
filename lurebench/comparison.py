"""Paired binary-decision comparisons with explicit missing-score accounting.

No detector calls, model loading, imputation, or automatic winner selection.
The exact conditional McNemar test concerns co-answered correctness only.
"""

from __future__ import annotations

from collections.abc import Mapping

from .calibration import binomial_cdf
from .metrics import validate_binary_labels
from .probability import validate_score, validate_threshold


def _blocked_sign_flip(differences: list[int]) -> dict:
    """Exact integer convolution; never silently substitute a random approximation."""
    nonzero = [abs(value) for value in differences if value]
    common = {
        "method": "exact_two_sided_block_sign_flip",
        "target": "joint_exchangeability_of_model_labels_within_declared_blocks",
        "blocks_with_coanswered_records": len(differences),
        "nonzero_blocks": len(nonzero),
        "statistic": "absolute_sum_of_record_correctness_differences",
        "observed_absolute_sum": abs(sum(differences)),
        "multiplicity_adjusted": False,
    }
    if not differences:
        return {**common, "p_value": None, "status": "no_coanswered_records"}
    # Bound both bigint growth and the convolution work before allocating states.
    if len(nonzero) > 1000 or len(nonzero) * (2 * sum(nonzero) + 1) > 2_000_000:
        return {**common, "p_value": None, "status": "exact_computation_limit"}
    distribution = {0: 1}
    for weight in sorted(nonzero):
        updated: dict[int, int] = {}
        for total, count in distribution.items():
            for signed in (total - weight, total + weight):
                updated[signed] = updated.get(signed, 0) + count
        distribution = updated
    numerator = sum(count for total, count in distribution.items()
                    if abs(total) >= common["observed_absolute_sum"])
    denominator = 1 << len(nonzero)
    return {**common, "p_value": numerator / denominator, "status": "exact",
            "tail_assignments": str(numerator), "effective_assignments": str(denominator)}


def compare_paired(
    truths: Mapping[str, int],
    baseline: Mapping[str, float | None],
    candidate: Mapping[str, float | None],
    *, baseline_threshold: float = .5, candidate_threshold: float = .5,
    groups: Mapping[str, str] | None = None,
) -> dict:
    """Compare exact matching record IDs; None is an abstention, not a miss.

    Scores must already be aligned to one reviewed task and labeled dataset.
    Distinct IDs do not prove independent samples or honest model provenance.
    """
    if not all(isinstance(item, Mapping) for item in (truths, baseline, candidate)):
        raise ValueError("paired inputs must be mappings keyed by record ID")
    if not truths or set(truths) != set(baseline) or set(truths) != set(candidate):
        raise ValueError("paired inputs require identical nonempty record ID sets")
    if any(not isinstance(key, str) or not 1 <= len(key) <= 512
           or any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in key) for key in truths):
        raise ValueError("record IDs must be bounded strings without controls")
    validate_binary_labels(list(truths.values()))
    if groups is not None:
        if not isinstance(groups, Mapping) or set(groups) != set(truths):
            raise ValueError("groups must cover exactly the compared record IDs")
        if any(not isinstance(group, str) or not 1 <= len(group) <= 1024 or any(
            ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in group
        ) for group in groups.values()):
            raise ValueError("group identifiers must be bounded strings without controls")
    baseline_threshold = validate_threshold(baseline_threshold)
    candidate_threshold = validate_threshold(candidate_threshold)
    rows = []
    for key, truth in truths.items():
        truth = int(truth)
        left, right = validate_score(baseline[key]), validate_score(candidate[key])
        rows.append((int(truth),
                     None if left is None else int(left >= baseline_threshold) == truth,
                     None if right is None else int(right >= candidate_threshold) == truth))

    def summarize(cohort):
        both_correct = baseline_only = candidate_only = both_wrong = 0
        left_missing = right_missing = both_missing = 0
        lower = upper = 0
        for _, left, right in cohort:
            left_missing += left is None
            right_missing += right is None
            both_missing += left is None and right is None
            # Pointwise feasible extremes of candidate correctness - baseline
            # correctness, retaining knowledge on singly answered records.
            lower += (0 if right is None else int(right)) - (1 if left is None else int(left))
            upper += (1 if right is None else int(right)) - (0 if left is None else int(left))
            if left is None or right is None:
                continue
            both_correct += left and right
            baseline_only += left and not right
            candidate_only += right and not left
            both_wrong += not left and not right
        n = len(cohort)
        paired = both_correct + baseline_only + candidate_only + both_wrong
        return {
            "records": n, "coanswered": paired,
            "baseline_abstained": left_missing, "candidate_abstained": right_missing,
            "both_abstained": both_missing,
            "coanswered_coverage": paired / n if n else None,
            "correctness_table": {"both_correct": both_correct, "baseline_only": baseline_only,
                                  "candidate_only": candidate_only, "both_wrong": both_wrong},
            "coanswered_baseline_accuracy": (both_correct + baseline_only) / paired if paired else None,
            "coanswered_candidate_accuracy": (both_correct + candidate_only) / paired if paired else None,
            "coanswered_accuracy_delta": (candidate_only - baseline_only) / paired if paired else None,
            "all_record_binary_completion_delta_bounds": (
                {"lower": lower / n, "upper": upper / n} if n else None
            ),
        }

    overall = summarize(rows)
    table = overall["correctness_table"]
    discordant = table["baseline_only"] + table["candidate_only"]
    p_value = None
    if overall["coanswered"] and groups is None:
        p_value = min(1.0, 2 * binomial_cdf(
            min(table["baseline_only"], table["candidate_only"]), discordant, .5,
        ))
    paired_test = {
        "method": "exact_conditional_two_sided_mcnemar",
        "target": "equal_coanswered_correctness_marginals",
        "discordant_pairs": discordant, "p_value": p_value,
        "multiplicity_adjusted": False,
    }
    if groups is not None:
        blocks: dict[str, int] = {}
        for key, (_, left, right) in zip(truths, rows, strict=True):
            if left is not None and right is not None:
                group = groups[key]
                blocks[group] = blocks.get(group, 0) + int(right) - int(left)
        paired_test = _blocked_sign_flip(list(blocks.values()))
        paired_test["declared_blocks"] = len(set(groups.values()))
    paired_test["conditional_on_coanswered"] = overall["coanswered"] != len(rows)
    return {
        "schema_version": 1,
        "direction": "candidate_minus_baseline",
        "baseline_threshold": baseline_threshold, "candidate_threshold": candidate_threshold,
        "overall": overall,
        "by_class": {"positive": summarize([r for r in rows if r[0] == 1]),
                     "negative": summarize([r for r in rows if r[0] == 0])},
        "paired_test": paired_test,
        "limitations": [
            "coanswered_results_do_not_estimate_performance_on_abstained_records",
            "binary_completion_bounds_are_not_confidence_intervals",
            ("block_test_requires_joint_sign_flip_exchangeability_not_just_equal_mean_accuracy"
             if groups is not None else "paired_inference_assumes_independent_representative_record_pairs"),
            "declared_lineage_does_not_prove_independence_or_complete_relatedness",
            "record_weighted_effect_is_not_an_equal_family_weighted_effect",
            "record_ids_do_not_prove_independence_or_producer_authenticity",
            "cached_scores_are_not_new_independent_model_observations",
            "thresholds_models_and_comparisons_must_be_predeclared_for_confirmatory_inference",
            "no_automatic_winner_equivalence_or_deployment_safety_claim",
        ],
    }
