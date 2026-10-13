"""No provider work for invalid plans; retain measurements when intervals are unavailable."""

import json
import math
import random
from types import SimpleNamespace

import pytest

from lurebench import calibration, cli, leaderboard
from lurebench.harness import run
from lurebench.schema import Lure, save_jsonl


def records(labels=(0, 1)):
    return [Lure(str(i), f"synthetic {i}", label, "human",
                 "phishing" if label else "benign") for i, label in enumerate(labels)]


@pytest.mark.parametrize("options", [
    ["--threshold", "nan"], ["--threshold", "2"],
    ["--bootstrap", "-1"], ["--bootstrap", "10001"],
    ["--bootstrap", "5", "--confidence", "0"],
    ["--bootstrap", "5", "--confidence", "nan"],
])
def test_eval_preflight_before_construction(tmp_path, monkeypatch, capsys, options):
    path = tmp_path / "input.jsonl"
    save_jsonl(records(), path)
    calls = []
    monkeypatch.setattr(cli, "get_detector", lambda *a, **kw: calls.append("constructed"))
    assert cli.main(["eval", "-d", str(path), "--json", *options]) == 2
    assert calls == []
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("labels,score", [((1, 1), .9), ((0, 0), .1), ((0, 1), None), ((1,), .9)])
@pytest.mark.parametrize("as_json", [True, False])
def test_eval_keeps_report_when_interval_unavailable(tmp_path, monkeypatch, capsys, labels, score, as_json):
    path = tmp_path / "input.jsonl"
    save_jsonl(records(labels), path)
    calls = []

    def scoring(record):
        calls.append(record.id)
        return score

    monkeypatch.setattr(cli, "get_detector", lambda *a, **kw:
                        SimpleNamespace(name="synthetic", task="fraud", score=scoring))
    assert cli.main(["eval", "-d", str(path), "--bootstrap", "20", *(["--json"] if as_json else [])]) == 0
    output = capsys.readouterr().out
    assert len(calls) == len(labels)
    if as_json:
        result = json.loads(output)[0]
        assert result["metrics"]["n"] == (len(labels) if score is not None else 0)
        assert result["confidence_intervals"]["auc"] is None
        status = result["confidence_interval_status"]["auc"]
        assert status["status"] in {"undefined_estimate", "no_scored_observations", "insufficient_observations"}
        assert status["requested_replicates"] == 20
        assert status["executed_replicates"] == 0
    else:
        assert "AUC unavailable" in output


@pytest.mark.parametrize("bad", [[], ["name"], ["name", {}, "extra"], 1, None,
                               "", "name@", "name@engine/", ("name", []), ("name", {1: "x"})])
def test_late_bad_spec_stops_before_any_detector(monkeypatch, bad):
    calls = []
    monkeypatch.setattr(leaderboard, "get_detector", lambda *a, **kw: calls.append("constructed"))
    with pytest.raises(ValueError):
        leaderboard.evaluate_detectors(records(), ["synthetic", bad])
    assert calls == []


def test_report_interval_results_preserve_defined_legacy_intervals():
    report = run(SimpleNamespace(name="synthetic", score=lambda r: .9 if r.label else .1), records())
    strict = report.confidence_intervals(replicates=40, seed=7)
    partial = report.confidence_interval_results(replicates=40, seed=7)
    for name, expected in strict.items():
        assert partial[name].interval == expected
        assert partial[name].status == "available"


@pytest.mark.parametrize("bad", [True, None, -1, 2**64, 1., "1"])
def test_invalid_seed_precedes_statistic_callback(bad):
    with pytest.raises(ValueError):
        calibration.bootstrap_ci([(0, .1), (1, .9)], lambda *a: pytest.fail("called"), seed=bad)


@pytest.mark.parametrize("option,value", [("replicates", True), ("replicates", 0),
    ("replicates", 10001), ("confidence", None), ("confidence", True), ("confidence", 1)])
def test_report_configuration_rejected_even_without_answers(option, value):
    report = run(SimpleNamespace(score=lambda r: None), records())
    with pytest.raises(ValueError):
        report.confidence_interval_results(**{option: value})


@pytest.mark.parametrize("observations", [[(True, .5)], [(1, None)], [(1, math.nan)], [(1, True)], [(2, .5)]])
def test_malformed_singleton_is_not_an_unavailable_interval(observations):
    report = run(SimpleNamespace(score=lambda r: .5), records())
    report.observations = observations
    with pytest.raises(ValueError):
        report.confidence_interval_results(replicates=2)


def test_limits_reject_before_callbacks_without_executing_large_work(monkeypatch):
    monkeypatch.setattr(calibration, "MAX_BOOTSTRAP_DRAWS", 5)
    with pytest.raises(ValueError, match="bounded work"):
        calibration.bootstrap_ci([(0, .1), (1, .9)], lambda *a: pytest.fail("called"), replicates=3)
    monkeypatch.setattr(calibration, "MAX_BOOTSTRAP_RECORDS", 1)
    with pytest.raises(ValueError, match="bounded work"):
        calibration.bootstrap_ci([(0, .1), (1, .9)], lambda *a: pytest.fail("called"), replicates=1)


def test_dataset_size_limit_precedes_eval_constructor(tmp_path, monkeypatch, capsys):
    path = tmp_path / "input.jsonl"
    save_jsonl(records(), path)
    monkeypatch.setattr(calibration, "MAX_BOOTSTRAP_DRAWS", 5)
    monkeypatch.setattr(cli, "get_detector", lambda *a, **kw: pytest.fail("constructed"))
    assert cli.main(["eval", "-d", str(path), "--bootstrap", "3"]) == 2
    assert capsys.readouterr().out == ""


def test_disabled_bootstrap_does_not_limit_dataset_size(monkeypatch):
    monkeypatch.setattr(calibration, "MAX_BOOTSTRAP_RECORDS", 1)
    assert calibration.validate_bootstrap_configuration(0, .95, 4989, 1_000_000, allow_zero=True) == .95


def test_no_defined_auc_draw_does_not_discard_other_metrics():
    report = run(SimpleNamespace(score=lambda r: .9 if r.label else .1), records())
    # Seed zero draws the second observation twice in its first resample.
    result = report.confidence_interval_results(replicates=1, seed=0)
    assert result["auc"].status == "no_defined_replicates"
    assert result["auc"].interval is None
    assert result["auc"].executed_replicates == 1
    assert result["recall"].status == "available"
    with pytest.raises(calibration.UndefinedBootstrapStatistic):
        report.confidence_intervals(replicates=1, seed=0)


def test_unexpected_statistic_failure_is_not_unavailability(monkeypatch):
    report = run(SimpleNamespace(score=lambda r: .5), records())

    def fail(*args):
        raise ValueError("unexpected bug")

    monkeypatch.setattr(report, "_bootstrap_statistics", lambda: {"unexpected": fail})
    with pytest.raises(ValueError, match="unexpected bug"):
        report.confidence_interval_results(replicates=2)


def test_partial_results_match_independent_auc_resampling_oracle():
    data = records((0, 1, 0, 1, 1))
    scores = [.1, .5, .5, .2, .9]
    report = run(SimpleNamespace(score=lambda r: scores[int(r.id)]), data)
    before = random.getstate()
    result = report.confidence_interval_results(replicates=97, confidence=.9, seed=41)["auc"]
    rng = random.Random(41)
    defined = []
    for _ in range(97):
        sample = [rng.randrange(len(data)) for _ in data]
        positives = [scores[i] for i in sample if data[i].label]
        negatives = [scores[i] for i in sample if not data[i].label]
        if positives and negatives:
            defined.append(sum((p > n) + .5 * (p == n) for p in positives for n in negatives)
                           / (len(positives) * len(negatives)))
    defined.sort()
    alpha = (1 - .9) / 2
    assert result.interval.lower == pytest.approx(defined[int(alpha * len(defined))])
    assert result.interval.upper == pytest.approx(defined[math.ceil((1 - alpha) * len(defined)) - 1])
    assert result.interval.undefined_replicates == 97 - len(defined)
    assert result.interval.conditional_on_defined == (len(defined) < 97)
    assert random.getstate() == before


@pytest.mark.parametrize("spec", ["@engine", "name@@engine", "name\n", " " * 2,
                                ("name", {"model": 3}), ("name", {"engine": ""})])
def test_spec_parser_rejects_ambiguous_forms(spec):
    with pytest.raises(ValueError):
        leaderboard.parse_detector_spec(spec)


@pytest.mark.parametrize("specs", ["synthetic", b"synthetic", None, {"synthetic": {}}])
def test_single_string_is_not_a_sequence_of_detector_names(monkeypatch, specs):
    monkeypatch.setattr(leaderboard, "get_detector", lambda *a, **kw: pytest.fail("constructed"))
    with pytest.raises(ValueError):
        leaderboard.evaluate_detectors(records(), specs)


@pytest.mark.parametrize("threshold", [0., .5, 1.])
def test_count_statistics_preserve_full_evaluation_interval_results(threshold):
    from lurebench.metrics import evaluate

    data = records((0, 1, 0, 1, 1, 0))
    scores = [0., .5, .5, .2, 1., .9]
    report = run(SimpleNamespace(score=lambda r: scores[int(r.id)]), data, threshold=threshold)
    result = report.confidence_intervals(replicates=53, confidence=.9, seed=41)
    for name in ("mcc", "recall", "fpr"):
        def reference(truths, values, metric=name):
            return getattr(evaluate(truths, [int(s >= threshold) for s in values], values), metric)
        assert result[name] == calibration.bootstrap_ci(report.observations, reference, 53, .9, 41)


def test_count_statistics_do_not_compute_unrelated_ranking_metrics(monkeypatch):
    from lurebench import harness

    report = run(SimpleNamespace(score=lambda r: .9 if r.label else .1), records())
    monkeypatch.setattr(harness, "evaluate", lambda *a, **kw: pytest.fail("full metric sweep"))
    assert report.confidence_interval_results(replicates=20)["mcc"].status == "available"


@pytest.mark.parametrize("seed", [0, 2**64 - 1])
def test_cli_bootstrap_seed_is_reproducible(tmp_path, capsys, seed):
    path = tmp_path / "input.jsonl"
    save_jsonl(records((0, 1, 0, 1)), path)
    args = ["eval", "-d", str(path), "--bootstrap", "20", "--seed", str(seed), "--json"]
    assert cli.main(args) == 0
    first = capsys.readouterr().out
    assert cli.main(args) == 0
    assert capsys.readouterr().out == first
    assert json.loads(first)[0]["bootstrap"]["seed"] == seed
