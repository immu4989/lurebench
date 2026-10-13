"""Independent expanded-sample oracle for the bounded weighted implementation."""

import hashlib
import itertools
import json
import math
import random
from pathlib import Path
from types import SimpleNamespace

import pytest

from lurebench import uncertainty as module
from lurebench.cli import main
from lurebench.detectors.cache import CachedDetector
from lurebench.schema import Lure, save_jsonl
from lurebench.uncertainty import (
    METRICS,
    bootstrap_uncertainty,
    run_cached_uncertainty,
    verify_cached_uncertainty,
)


def oracle(rows, threshold=.5):
    answered = [(truth, score) for truth, score in rows if score is not None]
    positives = [score for truth, score in answered if truth]
    negatives = [score for truth, score in answered if not truth]
    tp = sum(score >= threshold for score in positives)
    fn = len(positives) - tp
    fp = sum(score >= threshold for score in negatives)
    tn = len(negatives) - fp
    denominator = (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)
    all_positive = sum(truth for truth, _ in rows)
    all_negative = len(rows) - all_positive
    pairs = [(p, n) for p in positives for n in negatives]
    return {
        "accuracy": (tp + tn) / len(answered) if answered else None,
        "mcc": (tp * tn - fp * fn) / math.sqrt(denominator) if denominator else None,
        "recall": tp / len(positives) if positives else None,
        "fpr": fp / len(negatives) if negatives else None,
        "auc": sum((p > n) + .5 * (p == n) for p, n in pairs) / len(pairs) if pairs else None,
        "answer_coverage": len(answered) / len(rows) if rows else None,
        "positive_answer_coverage": len(positives) / all_positive if all_positive else None,
        "negative_answer_coverage": len(negatives) / all_negative if all_negative else None,
    }


@pytest.mark.parametrize("threshold", [0., .5, 1.])
def test_weighted_statistics_match_all_expanded_three_cluster_resamples(threshold):
    clusters = [[(1, .5), (0, .5), (1, None)], [(1, 0.), (0, 1.)], [(0, None)]]
    rows = sorted([(t, s, g) for g, block in enumerate(clusters) for t, s in block],
                  key=lambda row: (row[1] is None, row[1] if row[1] is not None else 0))
    for assignment in itertools.product(range(3), repeat=3):
        weights = [assignment.count(g) for g in range(3)]
        expanded = [row for g in assignment for row in clusters[g]]
        result, counts = module._statistics(rows, weights, threshold)
        assert result == pytest.approx(oracle(expanded, threshold))
        assert sum(counts.values()) == len(expanded)


def fixture():
    truths = {"a": 1, "b": 0, "c": 1, "d": 0, "e": 1, "f": 0}
    scores = {"a": .5, "b": .5, "c": None, "d": .1, "e": .2, "f": None}
    groups = {"a": "first", "b": "first", "c": "first", "d": "second",
              "e": "third", "f": "third"}
    return truths, scores, groups


def test_all_intervals_match_separate_expanded_bootstrap_and_are_reorder_stable():
    truths, scores, groups = fixture()
    result = bootstrap_uncertainty(truths, scores, groups=groups, replicates=97, seed=41)
    rng = random.Random(41)
    labels = sorted(set(groups.values()))
    draws = {name: [] for name in METRICS}
    sizes = []
    for _ in range(97):
        selected = [labels[rng.randrange(3)] for _ in labels]
        sample = [(truths[k], scores[k]) for group in selected for k in truths if groups[k] == group]
        sizes.append(len(sample))
        for name, value in oracle(sample).items():
            if value is not None:
                draws[name].append(value)
    for name, values in draws.items():
        values.sort()
        interval = result["metrics"][name]
        assert interval["estimate"] == oracle([(truths[k], scores[k]) for k in truths])[name]
        assert interval["defined_replicates"] == len(values)
        assert interval["undefined_replicates"] == 97 - len(values)
        assert interval["lower"] == values[int(.025 * len(values))]
        assert interval["upper"] == values[math.ceil(.975 * len(values)) - 1]
    assert result["replicate_records"] == {"minimum": min(sizes), "maximum": max(sizes)}
    reordered = bootstrap_uncertainty(dict(reversed(list(truths.items()))),
                                     dict(reversed(list(scores.items()))),
                                     groups=dict(reversed(list(groups.items()))), replicates=97, seed=41)
    assert reordered == result
    assert json.loads(json.dumps(result, allow_nan=False)) == result


def test_one_lineage_is_not_many_independent_observations():
    truths = {str(i): i % 2 for i in range(100)}
    scores = {key: float(truth) for key, truth in truths.items()}
    report = bootstrap_uncertainty(truths, scores, groups=dict.fromkeys(truths, "one"), replicates=100)
    assert report["sample"]["resampling_units"] == 1
    assert report["executed_replicates"] == 0
    for interval in report["metrics"].values():
        assert interval["status"] == "insufficient_resampling_units"
        assert interval["lower"] is interval["upper"] is None
        assert interval["undefined_replicates"] == 0  # no draws executed


@pytest.mark.parametrize("scores", [{"p": None, "n": None}, {"p": None, "n": .1},
                                  {"p": .9, "n": None}, {"p": .1, "n": .1}])
def test_missing_and_degenerate_metrics_are_not_zero_imputed(scores):
    truths = {"p": 1, "n": 0}
    result = bootstrap_uncertainty(truths, scores, replicates=100)
    expected = oracle([(truths[k], scores[k]) for k in truths])
    for name, estimate in expected.items():
        interval = result["metrics"][name]
        assert interval["estimate"] == estimate
        if estimate is None:
            assert interval["status"] == "undefined_estimate"
            assert interval["lower"] is interval["upper"] is None
    assert result["executed_replicates"] == 100


def test_single_class_keeps_useful_metrics_instead_of_aborting_auc():
    report = bootstrap_uncertainty({"a": 1, "b": 1}, {"a": .9, "b": .1}, replicates=100)
    assert report["metrics"]["recall"]["estimate"] == .5
    assert report["metrics"]["recall"]["status"] == "available"
    for name in ("fpr", "auc", "mcc", "negative_answer_coverage"):
        assert report["metrics"][name]["status"] == "undefined_estimate"


def test_no_defined_replicates_is_explicit(monkeypatch):
    monkeypatch.setattr(module.random, "Random", lambda seed: SimpleNamespace(randrange=lambda n: 0))
    report = bootstrap_uncertainty({"a": 1, "b": 0}, {"a": .9, "b": .1}, replicates=3)
    assert report["metrics"]["auc"]["status"] == "no_defined_replicates"
    assert report["metrics"]["auc"]["undefined_replicates"] == 3
    assert report["metrics"]["auc"]["conditional_on_defined"] is True


def test_wholly_abstaining_group_is_in_the_sampling_population():
    result = bootstrap_uncertainty({"a": 1, "b": 0}, {"a": None, "b": .1},
                                   groups={"a": "missing", "b": "answered"}, replicates=100)
    assert result["sample"]["resampling_units"] == 2
    assert result["sample"]["units_with_answered_records"] == 1
    assert result["metrics"]["answer_coverage"]["lower"] == 0
    assert result["metrics"]["answer_coverage"]["upper"] == 1
    assert result["metrics"]["accuracy"]["undefined_replicates"] > 0


@pytest.mark.parametrize("keyword,value", [
    ("replicates", True), ("replicates", 0), ("replicates", 1.5), ("replicates", 10001),
    ("confidence", True), ("confidence", 0), ("confidence", 1), ("confidence", math.nan),
    ("seed", True), ("seed", -1), ("seed", 2**64), ("seed", .5),
    ("threshold", None), ("threshold", True), ("threshold", math.inf),
])
def test_invalid_configuration_fails_before_randomness(monkeypatch, keyword, value):
    monkeypatch.setattr(module.random, "Random", lambda *a: pytest.fail("invalid input consumed RNG"))
    with pytest.raises(ValueError):
        bootstrap_uncertainty({"a": 1, "b": 0}, {"a": .9, "b": .1}, **{keyword: value})


@pytest.mark.parametrize("truths,scores,groups", [
    ({}, {}, None), ({"a": 1}, {}, None), ({"a": True}, {"a": .9}, None),
    ({"a": .5}, {"a": .9}, None), ({"a": 1}, {"a": True}, None),
    ({"a": 1}, {"a": math.nan}, None), ({"a": 1}, {"a": -.1}, None),
    ({"a": 1}, {"a": .9}, {}), ({"a": 1}, {"a": .9}, {"a": False}),
    ({"a": 1}, {"a": .9}, {"a": ""}), ({"a": 1}, {"a": .9}, {"a": "x\ny"}),
    ({"": 1}, {"": .9}, None), ({"a\ud800": 1}, {"a\ud800": .9}, None),
    ([1], [.9], None), ({"a": 1}, {"a": ".9"}, None),
])
def test_invalid_inputs_fail(truths, scores, groups):
    with pytest.raises(ValueError):
        bootstrap_uncertainty(truths, scores, groups=groups)


def test_work_limit_and_max_records(monkeypatch):
    monkeypatch.setattr(module, "MAX_WORK", 3)
    with pytest.raises(ValueError, match="work limit"):
        bootstrap_uncertainty({"a": 1, "b": 0}, {"a": .9, "b": .1}, replicates=2)
    monkeypatch.setattr(module, "MAX_RECORDS", 1)
    with pytest.raises(ValueError, match="record"):
        bootstrap_uncertainty({"a": 1, "b": 0}, {"a": .9, "b": .1}, replicates=1)


def test_fingerprint_binds_effective_inputs_without_disclosing_identifiers():
    truths, scores, groups = fixture()
    report = bootstrap_uncertainty(truths, scores, groups=groups, replicates=10)
    changed = bootstrap_uncertainty(truths, {**scores, "a": .51}, groups=groups, replicates=10)
    assert report["input_fingerprint"] != changed["input_fingerprint"]
    assert report["metrics"]["accuracy"] == changed["metrics"]["accuracy"]
    singletons = bootstrap_uncertainty(truths, scores, replicates=10)
    assert report["input_fingerprint"] != singletons["input_fingerprint"]
    assert '"first"' not in json.dumps(report)


def cached_fixture(tmp_path):
    records = [Lure(str(i), f"PRIVATE SYNTHETIC MESSAGE {i}", i % 2, "ai" if i % 2 else "human",
                    "phishing" if i % 2 else "benign", meta={"family_id": f"family-{i // 2}"})
               for i in range(6)]
    dataset, path = tmp_path / "records.jsonl", tmp_path / "cache.json"
    save_jsonl(records, dataset)
    cache = CachedDetector(SimpleNamespace(name="synthetic", task="fraud", score=lambda r: .8),
                           str(path), flush_every=0)
    for record in records:
        cache.score(record)
    cache.flush()
    return dataset, path


@pytest.mark.parametrize("task", ["fraud", "provenance"])
def test_cli_readonly_default_lineage_no_live_detector(tmp_path, monkeypatch, capsys, task):
    dataset, cache = cached_fixture(tmp_path)
    before = dataset.read_bytes(), cache.read_bytes()
    monkeypatch.setattr("lurebench.cli.get_detector", lambda *a: pytest.fail("live detector"))
    args = ["uncertainty-cached", "--dataset", str(dataset), "--cache", str(cache),
            "--detector-name", "synthetic", "--task", task, "--replicates", "30"]
    assert main(args) == 0
    output = capsys.readouterr()
    report = json.loads(output.out)
    assert report["source"]["task"] == task
    assert report["sample"]["resampling_units"] == 3
    assert report["source"]["dataset_sha256"] == hashlib.sha256(before[0]).hexdigest()
    assert "PRIVATE SYNTHETIC MESSAGE" not in output.out
    assert str(tmp_path) not in output.out
    assert (dataset.read_bytes(), cache.read_bytes()) == before
    assert main([*args, "--resampling-unit", "record"]) == 0
    assert json.loads(capsys.readouterr().out)["sample"]["resampling_units"] == 6


def test_cli_incomplete_cache_is_redacted_and_not_created(tmp_path, capsys):
    dataset, _ = cached_fixture(tmp_path)
    cache = tmp_path / "MISSING-PRIVATE-CACHE.json"
    assert main(["uncertainty-cached", "--dataset", str(dataset), "--cache", str(cache),
                 "--detector-name", "synthetic", "--task", "fraud"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "PRIVATE" not in captured.err
    assert "no live fallback" in captured.err
    assert not cache.exists()


def test_cached_duplicate_ids_rejected_before_cache_read(tmp_path):
    dataset, _ = cached_fixture(tmp_path)
    with dataset.open("ab") as handle:
        handle.write(dataset.read_bytes().splitlines(keepends=True)[0])
    with pytest.raises(ValueError, match="unique"):
        run_cached_uncertainty(dataset, tmp_path / "missing", detector_name="synthetic", task="fraud")


def test_duplicating_all_records_within_their_groups_does_not_manufacture_precision():
    truths, scores, groups = fixture()
    report = bootstrap_uncertainty(truths, scores, groups=groups, replicates=300)
    copies = {f"{k}-copy-{j}": k for k in truths for j in range(10)}
    repeated = bootstrap_uncertainty({key: truths[k] for key, k in copies.items()},
                                    {key: scores[k] for key, k in copies.items()},
                                    groups={key: groups[k] for key, k in copies.items()}, replicates=300)
    for name in METRICS:
        # sqrt on scaled integer MCC denominators can differ by one floating-point ULP.
        assert repeated["metrics"][name] == pytest.approx(report["metrics"][name], abs=1e-15)
    assert repeated["sample"]["records"] == 10 * report["sample"]["records"]


def test_singletons_match_record_resampling_and_do_not_touch_global_rng():
    truths, scores, _ = fixture()
    before = random.getstate()
    record = bootstrap_uncertainty(truths, scores, replicates=100)
    grouped = bootstrap_uncertainty(truths, scores, groups={key: key for key in truths}, replicates=100)
    assert record["metrics"] == grouped["metrics"]
    assert random.getstate() == before


@pytest.mark.parametrize("mutation", [
    lambda r: r["metrics"]["accuracy"].update(lower=0.),
    lambda r: r.update(extra="not silently ignored"),
    lambda r: r.update(executed_replicates=30.),
    lambda r: r.update(limitations=[]),
    lambda r: r["source"].update(task="provenance"),
    lambda r: r.update(seed=0),
])
def test_verifier_detects_every_changed_field(tmp_path, mutation):
    dataset, cache = cached_fixture(tmp_path)
    controls = dict(detector_name="synthetic", task="fraud", replicates=30)
    report = run_cached_uncertainty(dataset, cache, **controls)
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report))
    before = {p: p.read_bytes() for p in tmp_path.iterdir()}
    assert verify_cached_uncertainty(dataset, cache, path, **controls)["matches_replay"]
    assert before == {p: p.read_bytes() for p in tmp_path.iterdir()}
    mutation(report)
    path.write_text(json.dumps(report))
    assert not verify_cached_uncertainty(dataset, cache, path, **controls)["matches_replay"]


@pytest.mark.parametrize("content", ["{}", "[]", '{"schema_version":1,"schema_version":1}',
                                     '{"schema_version":true}', " " * (64 * 1024 + 1)])
def test_verifier_invalid_reports_reject_before_replay(tmp_path, monkeypatch, content):
    path = tmp_path / "report.json"
    path.write_text(content)
    monkeypatch.setattr(module, "run_cached_uncertainty", lambda *a, **kw: pytest.fail("replay reached"))
    with pytest.raises(ValueError):
        verify_cached_uncertainty(tmp_path / "unused", tmp_path / "unused-cache", path)


def test_verify_cli_distinct_match_mismatch_and_error_status(tmp_path, capsys):
    dataset, cache = cached_fixture(tmp_path)
    controls = dict(detector_name="synthetic", task="fraud", replicates=30)
    report = run_cached_uncertainty(dataset, cache, **controls)
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report))
    arguments = ["verify-uncertainty", "--dataset", str(dataset), "--cache", str(cache),
                 "--detector-name", "synthetic", "--task", "fraud", "--replicates", "30",
                 "--report", str(path)]
    assert main(arguments) == 0
    assert json.loads(capsys.readouterr().out)["matches_replay"]
    assert main([*arguments, "--seed", "99"]) == 1
    assert not json.loads(capsys.readouterr().out)["matches_replay"]
    path.write_text("[]")
    assert main(arguments) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "no live fallback" in captured.err


def test_exported_schema_covers_cached_bare_and_unavailable_reports(tmp_path):
    from jsonschema import Draft202012Validator

    schema = json.loads((Path(__file__).parents[1] / "spec/detector-uncertainty-v1.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    dataset, cache = cached_fixture(tmp_path)
    report = run_cached_uncertainty(dataset, cache, detector_name="synthetic", task="fraud", replicates=10)
    validator.validate(report)
    validator.validate(bootstrap_uncertainty({"a": 1}, {"a": None}, replicates=1))
    validator.validate(bootstrap_uncertainty({"a": 1, "b": 0}, {"a": .9, "b": .1}, replicates=10))
    report["metrics"]["accuracy"]["lower"] = None
    assert list(validator.iter_errors(report))
    report["metrics"]["accuracy"]["lower"] = -.1
    assert list(validator.iter_errors(report))
