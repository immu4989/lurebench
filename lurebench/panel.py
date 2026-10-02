"""Planned baseline comparisons with conservative family-wide p-value adjustment.

No ranking, provider calls, imputation, or claim that a plan was preregistered.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from pathlib import Path

from .comparison import compare_paired
from .probability import validate_score, validate_threshold

MAX_CANDIDATES = 32


def verify_cached_panel(dataset: Path, plan_path: Path, report_path: Path) -> dict:
    """Recompute and compare every report field; never authenticate the inputs."""
    from .local_io import read_regular_file
    from .receipts import canonical_json, loads_strict_json

    raw = read_regular_file(report_path, maximum=1024 * 1024, label="panel report")
    supplied = loads_strict_json(raw)
    if (not isinstance(supplied, dict) or type(supplied.get("schema_version")) is not int
            or supplied["schema_version"] != 1
            or supplied.get("analysis") != "planned_baseline_detector_comparisons"):
        raise ValueError("expected a version 1 cached panel report")
    expected = run_cached_panel(dataset, plan_path)
    # Compare canonical bytes, not Python equality (True == 1 == 1.0). No report
    # fields, including unexpected metadata or limitations, are silently dropped.
    matches = canonical_json(supplied) == canonical_json(expected)
    return {
        "schema_version": 1, "verification": "local_cached_panel_reproduction",
        "matches_replay": matches,
        "supplied_report_sha256": hashlib.sha256(raw).hexdigest(),
        "replayed_report_canonical_sha256": hashlib.sha256(canonical_json(expected)).hexdigest(),
        "input_fingerprint": expected["input_fingerprint"],
        "limitations": [
            "same_implementation_reproduction_not_an_independent_statistical_audit",
            "does_not_authenticate_datasets_caches_plans_or_report_authors",
            "does_not_prove_preregistration_representativeness_or_deployment_safety",
            "fingerprints_are_not_anonymization",
        ],
    }


def _effective_input_fingerprint(records, entries, snapshots, truths, groups, *, task, pairing_unit):
    """Bind already-loaded analysis inputs, not a second read of mutable files."""
    from .receipts import canonical_json

    value = {
        "profile": "lurebench-panel-effective-inputs-v1",
        "task": task, "pairing_unit": pairing_unit, "baseline_id": entries[0]["id"],
        "detectors": sorted(
            ({key: item for key, item in entry.items() if key != "cache"} for entry in entries),
            key=lambda entry: entry["id"],
        ),
        "records": [{
            "id": record.id,
            "text_sha256": hashlib.sha256(record.text.encode("utf-8")).hexdigest(),
            "target": truths[record.id],
            "group": groups[record.id] if groups is not None else record.id,
            "scores": {name: validate_score(scores[record.id])
                       for name, scores in snapshots.items()},
        } for record in sorted(records, key=lambda record: record.id)],
    }
    return {"profile": value["profile"], "sha256": hashlib.sha256(canonical_json(value)).hexdigest()}


def _descriptor(value: object) -> dict:
    required = {"id", "name", "cache", "threshold"}
    if not isinstance(value, dict) or not required <= set(value) <= required | {"namespace"}:
        raise ValueError("panel detector fields do not match the supported contract")
    if not isinstance(value["id"], str):
        raise ValueError("panel detector identifier must be a string")
    holm_adjust({value["id"]: None})
    for key, maximum in (("name", 256), ("cache", 4096)):
        text = value[key]
        if not isinstance(text, str) or not 1 <= len(text) <= maximum or any(
            ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in text
        ):
            raise ValueError("panel detector name and cache path must be bounded strings")
    if "namespace" in value and (not isinstance(value["namespace"], str) or
            re.fullmatch(r"[0-9a-f]{64}", value["namespace"]) is None):
        raise ValueError("panel cache namespace must be a lowercase SHA-256 identity")
    return {**value, "threshold": validate_threshold(value["threshold"])}


def run_cached_panel(dataset: Path, plan_path: Path) -> dict:
    """Read a strict local plan and existing caches; never construct live detectors."""
    from .detectors.cache import ReplayDetector
    from .harness import TASK_TARGET
    from .lineage import lineage_components
    from .local_io import read_regular_file
    from .receipts import loads_strict_json
    from .schema import load_jsonl

    payload = read_regular_file(plan_path, maximum=64 * 1024, label="comparison plan")
    plan = loads_strict_json(payload)
    if not isinstance(plan, dict) or set(plan) != {
        "schema_version", "task", "pairing_unit", "baseline", "candidates",
    }:
        raise ValueError("comparison plan fields do not match version 1")
    if type(plan["schema_version"]) is not int or plan["schema_version"] != 1:
        raise ValueError("unsupported comparison plan version")
    if plan["task"] not in ("fraud", "provenance") or plan["pairing_unit"] not in ("lineage", "record"):
        raise ValueError("unsupported comparison task or pairing unit")
    if not isinstance(plan["candidates"], list) or not 1 <= len(plan["candidates"]) <= MAX_CANDIDATES:
        raise ValueError("plan needs one through 32 candidates")
    baseline = _descriptor(plan["baseline"])
    candidates = [_descriptor(value) for value in plan["candidates"]]
    entries = [baseline, *candidates]
    if len({entry["id"] for entry in entries}) != len(entries):
        raise ValueError("baseline and candidate identifiers must be unique")
    records = load_jsonl(str(dataset))
    if not 1 <= len(records) <= 50_000:
        raise ValueError("cached panel requires one through 50000 records")
    if len({record.id for record in records}) != len(records):
        raise ValueError("panel records must have unique IDs")
    components = lineage_components(records) if plan["pairing_unit"] == "lineage" else None
    truths = {record.id: TASK_TARGET[plan["task"]](record) for record in records}
    snapshots, coverage = {}, {}
    for entry in entries:
        cache = Path(entry["cache"])
        if not cache.is_absolute():
            cache = plan_path.parent / cache
        replay = ReplayDetector(str(cache), name=entry["name"], task=plan["task"],
                                cache_namespace=entry.get("namespace"))
        coverage[entry["id"]] = replay.plan(records)
        if not coverage[entry["id"]]["replay_complete"]:
            raise ValueError("panel cache incomplete; no comparison omitted and no live fallback")
        snapshots[entry["id"]] = {record.id: replay.score(record) for record in records}
    report = compare_panel(truths, snapshots[baseline["id"]],
                           {entry["id"]: snapshots[entry["id"]] for entry in candidates},
                           baseline_threshold=baseline["threshold"],
                           candidate_thresholds={entry["id"]: entry["threshold"] for entry in candidates},
                           groups=components)
    report.update(task=plan["task"], pairing_unit=plan["pairing_unit"],
                  plan_sha256=hashlib.sha256(payload).hexdigest(), cache_coverage=coverage,
                  input_fingerprint=_effective_input_fingerprint(
                      records, entries, snapshots, truths, components,
                      task=plan["task"], pairing_unit=plan["pairing_unit"],
                  ),
                  detector_identities=[{key: value for key, value in entry.items() if key != "cache"}
                                       for entry in entries], baseline_id=baseline["id"])
    report["limitations"].append("plan_hash_is_not_preregistration_or_producer_authentication")
    report["limitations"].append("input_fingerprint_is_not_authentication_or_anonymization")
    return report


def holm_adjust(p_values: Mapping[str, float | None]) -> dict[str, float | None]:
    """Adjust a declared family; unavailable tests retain their multiplicity slot.

    Replacing an unavailable test by one is conservative for the available tests.
    Its returned adjusted value remains None, not a claim of a null result.
    """
    if not isinstance(p_values, Mapping) or not 1 <= len(p_values) <= MAX_CANDIDATES:
        raise ValueError("supply one through 32 planned comparisons")
    if any(not isinstance(name, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", name) is None
           for name in p_values):
        raise ValueError("comparison identifiers must be bounded portable names")
    checked = {name: validate_score(value) for name, value in p_values.items()}
    ordered = sorted(checked, key=lambda name: (1. if checked[name] is None else checked[name], name))
    adjusted = {}
    previous = 0.
    for index, name in enumerate(ordered):
        value = checked[name]
        previous = max(previous, min(1., (len(ordered) - index) * (1. if value is None else value)))
        adjusted[name] = None if value is None else previous
    return {name: adjusted[name] for name in sorted(adjusted)}


def compare_panel(
    truths: Mapping[str, int], baseline: Mapping[str, float | None],
    candidates: Mapping[str, Mapping[str, float | None]], *,
    baseline_threshold: float = .5,
    candidate_thresholds: Mapping[str, float], groups: Mapping[str, str] | None = None,
) -> dict:
    """Compare every candidate to one fixed baseline, retaining all planned tests."""
    if not isinstance(candidates, Mapping) or not 1 <= len(candidates) <= MAX_CANDIDATES:
        raise ValueError("supply one through 32 candidates")
    # Validate names before any comparisons; no silent threshold defaults per model.
    holm_adjust(dict.fromkeys(candidates, None))
    if not isinstance(candidate_thresholds, Mapping) or set(candidate_thresholds) != set(candidates):
        raise ValueError("candidate thresholds must cover exactly the planned candidates")
    comparisons = {
        name: compare_paired(truths, baseline, candidates[name], baseline_threshold=baseline_threshold,
                             candidate_threshold=candidate_thresholds[name], groups=groups)
        for name in sorted(candidates)
    }
    adjusted = holm_adjust({name: report["paired_test"]["p_value"]
                            for name, report in comparisons.items()})
    # Descriptive common support prevents comparing accuracies from different
    # answered subsets as though they were measured on the same messages. Do not
    # add another family of significance tests selected after seeing abstentions.
    common_ids = [key for key in truths if baseline[key] is not None
                  and all(scores[key] is not None for scores in candidates.values())]
    common = {
        "records": len(common_ids),
        "excluded_records": len(truths) - len(common_ids),
        "coverage": len(common_ids) / len(truths),
        "positive_records": sum(int(truths[key]) for key in common_ids),
        "negative_records": sum(1 - int(truths[key]) for key in common_ids),
        "baseline_accuracy": (
            sum((baseline[key] >= baseline_threshold) == truths[key] for key in common_ids)
            / len(common_ids) if common_ids else None
        ),
        "candidate_accuracies": {
            name: (sum((scores[key] >= candidate_thresholds[name]) == truths[key]
                       for key in common_ids) / len(common_ids) if common_ids else None)
            for name, scores in sorted(candidates.items())
        },
        "inference": "descriptive_only_no_additional_hypothesis_tests",
    }
    return {
        "schema_version": 1, "analysis": "planned_baseline_detector_comparisons",
        "comparisons": comparisons,
        "all_models_coanswered": common,
        "family_adjustment": {
            "method": "holm_step_down_bonferroni",
            "planned_comparisons": len(candidates),
            "available_tests": sum(value is not None for value in adjusted.values()),
            "adjusted_p_values": adjusted,
            "unavailable_test_handling": "retain_family_slot_as_one_but_return_null",
        },
        "limitations": [
            "family_models_thresholds_and_sampling_blocks_must_be_declared_before_outcomes",
            "software_does_not_prove_preregistration_or_detect_omitted_comparisons",
            "familywise_error_control_requires_valid_marginal_tests_for_the_stated_nulls",
            "correction_does_not_repair_invalid_exchangeability_or_sampling",
            "paired_coanswered_cohorts_can_differ_between_candidates",
            "common_cohort_is_selected_by_all_models_answering_not_representative_by_construction",
            "common_cohort_changes_when_models_are_added_or_removed",
            "missing_tests_are_unavailable_not_evidence_of_no_difference",
            "no_correction_across_separate_runs_or_repeated_peeking",
            "no_automatic_ranking_superiority_equivalence_or_deployment_decision",
        ],
    }
