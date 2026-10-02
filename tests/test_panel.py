"""Independent closed-testing reference and network-free panel integration."""

import hashlib
import itertools
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from lurebench.cli import main
from lurebench.detectors.cache import CachedDetector
from lurebench.panel import compare_panel, holm_adjust, run_cached_panel
from lurebench.schema import Lure, save_jsonl


def test_holm_matches_closed_bonferroni_intersection_tests():
    # Independent oracle: every intersection containing the tested hypothesis.
    names = "abc"
    subsets = [subset for n in range(1, 4) for subset in itertools.combinations(range(3), n)]
    for values in itertools.product((0., .01, .03, .1, .5, 1., None), repeat=3):
        numeric = [1. if p is None else p for p in values]
        reference = {names[i]: None if values[i] is None else
                     max(min(1., len(subset) * min(numeric[j] for j in subset))
                         for subset in subsets if i in subset) for i in range(3)}
        assert holm_adjust(dict(zip(names, values, strict=True))) == reference


def test_missing_test_retains_its_declared_family_slot():
    assert holm_adjust({"first": .01, "unavailable": None}) == {"first": .02, "unavailable": None}
    assert holm_adjust({"first": None}) == {"first": None}
    assert holm_adjust({"first": .01}) == {"first": .01}


@pytest.mark.parametrize("values", [{}, [], {"": .1}, {"a\n": .1}, {"a": True},
    {"a": -.1}, {"a": float("nan")}, {"a": "0.1"}, {str(i): .1 for i in range(33)}])
def test_invalid_family_fails(values):
    with pytest.raises(ValueError):
        holm_adjust(values)


def test_panel_preserves_unavailable_tests_and_cohorts():
    truths = dict.fromkeys(map(str, range(8)), 1)
    baseline = dict.fromkeys(truths, .1)
    candidates = {"improved": dict.fromkeys(truths, .9), "abstained": dict.fromkeys(truths, None)}
    report = compare_panel(truths, baseline, candidates,
                           candidate_thresholds=dict.fromkeys(candidates, .5), groups={k: k for k in truths})
    assert report["family_adjustment"]["planned_comparisons"] == 2
    assert report["family_adjustment"]["available_tests"] == 1
    assert report["family_adjustment"]["adjusted_p_values"] == {"abstained": None, "improved": .015625}
    assert report["comparisons"]["abstained"]["overall"]["coanswered"] == 0
    assert report["comparisons"]["improved"]["overall"]["coanswered"] == 8
    with pytest.raises(ValueError, match="thresholds"):
        compare_panel(truths, baseline, candidates, candidate_thresholds={"improved": .5})


def test_common_cohort_exposes_selective_answering_without_extra_tests():
    truths = {"a": 0, "b": 1, "c": 1, "d": 0}
    baseline = {"a": .1, "b": .2, "c": .9, "d": None}
    candidates = {"first": {"a": .9, "b": .8, "c": None, "d": .1},
                  "second": {"a": .1, "b": None, "c": .9, "d": .1}}
    report = compare_panel(truths, baseline, candidates,
                           candidate_thresholds={"first": .5, "second": .5})
    common = report["all_models_coanswered"]
    assert common == {
        "records": 1, "excluded_records": 3, "coverage": .25,
        "positive_records": 0, "negative_records": 1, "baseline_accuracy": 1.,
        "candidate_accuracies": {"first": 0., "second": 1.},
        "inference": "descriptive_only_no_additional_hypothesis_tests",
    }
    assert report["family_adjustment"]["planned_comparisons"] == 2
    assert all(r["overall"]["coanswered"] == 2 for r in report["comparisons"].values())
    candidates["second"]["a"] = None
    empty = compare_panel(truths, baseline, candidates,
                          candidate_thresholds={"first": .5, "second": .5})["all_models_coanswered"]
    assert empty["records"] == 0
    assert empty["baseline_accuracy"] is None
    assert empty["candidate_accuracies"] == {"first": None, "second": None}


def fixture_plan(tmp_path):
    records = [Lure(id=str(i), text=f"synthetic {i}", label=1, source="human", typology="phishing")
               for i in range(8)]
    dataset = tmp_path / "messages.jsonl"
    save_jsonl(records, dataset)
    descriptors = []
    for name, score in (("baseline", .1), ("improved", .9), ("abstained", None)):
        cache = tmp_path / f"{name}.json"
        detector = CachedDetector(SimpleNamespace(name=name, task="fraud", score=lambda r, v=score: v),
                                  str(cache), flush_every=1)
        for record in records:
            detector.score(record)
        descriptors.append({"id": name, "name": name, "cache": cache.name, "threshold": .5})
    plan = {"schema_version": 1, "task": "fraud", "pairing_unit": "lineage",
            "baseline": descriptors[0], "candidates": descriptors[1:]}
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan))
    return dataset, plan_path, plan


def test_cached_cli_is_read_only_and_never_constructs_a_detector(tmp_path, monkeypatch, capsys):
    import lurebench.cli as cli
    import lurebench.detectors as detectors

    dataset, plan_path, _ = fixture_plan(tmp_path)
    before = {p: p.read_bytes() for p in tmp_path.iterdir()}

    def forbidden(*args, **kwargs):
        pytest.fail("model construction attempted")

    monkeypatch.setattr(cli, "get_detector", forbidden)
    monkeypatch.setattr(detectors, "get_detector", forbidden)
    assert main(["compare-panel", "-d", str(dataset), "--plan", str(plan_path)]) == 0
    output = capsys.readouterr().out
    report = json.loads(output)
    assert report["plan_sha256"] == hashlib.sha256(before[plan_path]).hexdigest()
    assert report["family_adjustment"]["planned_comparisons"] == 2
    assert str(tmp_path) not in output
    assert "synthetic 0" not in output
    assert {p: p.read_bytes() for p in tmp_path.iterdir()} == before
    (tmp_path / "improved.json").write_text("{}")
    assert main(["compare-panel", "-d", str(dataset), "--plan", str(plan_path)]) == 2
    assert "no live fallback" in capsys.readouterr().err


def test_input_fingerprint_binds_effective_data_not_formatting_or_unused_cache_entries(tmp_path):
    dataset, plan_path, plan = fixture_plan(tmp_path)
    original = run_cached_panel(dataset, plan_path)
    fingerprint = original["input_fingerprint"]
    assert fingerprint["profile"] == "lurebench-panel-effective-inputs-v1"
    assert len(fingerprint["sha256"]) == 64
    records = [json.loads(line) for line in dataset.read_text().splitlines()]
    dataset.write_text("\n".join(json.dumps(r) for r in reversed(records)))
    plan["candidates"].reverse()
    plan_path.write_text(json.dumps(plan, indent=2))
    cache_path = tmp_path / "improved.json"
    cache = json.loads(cache_path.read_text())
    cache["unused"] = .42
    cache_path.write_text(json.dumps(cache, indent=2))
    reformatted = run_cached_panel(dataset, plan_path)
    assert reformatted["input_fingerprint"] == fingerprint
    assert reformatted["plan_sha256"] != original["plan_sha256"]
    # Changed probability remains detectable when its classification stays equal.
    key = next(key for key in cache if key != "unused")
    cache[key] = .91
    cache_path.write_text(json.dumps(cache))
    changed = run_cached_panel(dataset, plan_path)
    assert changed["input_fingerprint"] != fingerprint
    assert changed["comparisons"] == reformatted["comparisons"]


@pytest.mark.parametrize("field", ["target", "group", "threshold", "name", "text", "task", "baseline"])
def test_effective_input_fingerprint_changes_for_analysis_inputs(field):
    import copy

    from lurebench.panel import _effective_input_fingerprint

    records = [Lure("record", "private text", 1, "human", "phishing")]
    entries = [{"id": "b", "name": "base", "threshold": .5, "cache": "not-bound"},
               {"id": "c", "name": "candidate", "threshold": .5, "cache": "not-bound"}]
    arguments = dict(records=records, entries=entries, snapshots={"b": {"record": .1},
                     "c": {"record": .9}}, truths={"record": 1}, groups={"record": "family"},
                     task="fraud", pairing_unit="lineage")
    original = _effective_input_fingerprint(**arguments)
    modified = copy.deepcopy(arguments)
    if field == "target":
        modified["truths"]["record"] = 0
    elif field == "group":
        modified["groups"]["record"] = "different-family"
    elif field in ("threshold", "name"):
        modified["entries"][0][field] = .6 if field == "threshold" else "different-model"
    elif field == "text":
        modified["records"][0].text = "different private text"
    elif field == "task":
        modified["task"] = "provenance"
    else:
        modified["entries"].reverse()
    assert _effective_input_fingerprint(**modified) != original
    assert "private" not in json.dumps(original)
    assert "record" not in json.dumps(original)


@pytest.mark.parametrize("change", [
    lambda p: p.update(schema_version=True),
    lambda p: p.update(unrecognized="field"),
    lambda p: p.update(pairing_unit="automatic"),
    lambda p: p.update(candidates=[]),
    lambda p: p["candidates"][0].update(id="baseline"),
    lambda p: p["candidates"][0].update(id=[]),
    lambda p: p["candidates"][0].update(namespace=""),
    lambda p: p["candidates"][0].update(threshold=".5"),
    lambda p: p["candidates"][0].update(cache="bad\x00path"),
])
def test_invalid_plan_fails_before_cache_reads(tmp_path, monkeypatch, change):
    from lurebench.detectors import cache

    dataset, plan_path, plan = fixture_plan(tmp_path)
    change(plan)
    plan_path.write_text(json.dumps(plan))
    monkeypatch.setattr(cache, "ReplayDetector", lambda *a, **k: pytest.fail("invalid plan reached cache"))
    with pytest.raises(ValueError):
        run_cached_panel(dataset, plan_path)


def test_duplicate_json_keys_and_symlinked_plans_are_rejected(tmp_path):
    dataset, plan_path, _ = fixture_plan(tmp_path)
    plan_path.write_text('{"schema_version":1,"schema_version":1}')
    with pytest.raises(ValueError):
        run_cached_panel(dataset, plan_path)
    link = tmp_path / "alias.json"
    link.symlink_to(plan_path)
    with pytest.raises(ValueError):
        run_cached_panel(dataset, link)


def test_published_plan_schema_accepts_valid_input_and_rejects_control_ids(tmp_path):
    jsonschema = pytest.importorskip("jsonschema")
    _, _, plan = fixture_plan(tmp_path)
    schema = json.loads((Path(__file__).resolve().parents[1] /
                         "spec/comparison-panel-plan-v1.schema.json").read_text())
    validator = jsonschema.Draft202012Validator(schema)
    validator.check_schema(schema)
    validator.validate(plan)
    plan["baseline"]["id"] = "baseline\n"
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(plan)
