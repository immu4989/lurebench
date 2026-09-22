from itertools import product

import pytest

from lurebench.harness import run
from lurebench.schema import Lure


def records(labels):
    return [Lure(id=f"row-{i}", text="synthetic", label=label, source="ai",
                 typology="phishing" if label else "benign") for i, label in enumerate(labels)]


class Outcomes:
    def __init__(self, values):
        self.values = iter(values)

    def score(self, lure):
        return next(self.values)


def test_completion_bounds_match_every_binary_resolution_of_four_record_populations():
    populations = 0
    for labels in product((0, 1), repeat=4):
        for outcomes in product((0.0, 1.0, None), repeat=4):
            report = run(Outcomes(outcomes), records(labels))
            coverage = report.coverage_summary()
            assert coverage["records"] == 4
            assert coverage["answered"] + coverage["abstained"] == 4
            missing = [i for i, value in enumerate(outcomes) if value is None]
            possibilities = {"accuracy": [], "recall": [], "fpr": []}
            for resolutions in product((0, 1), repeat=len(missing)):
                decisions = list(outcomes)
                for index, resolution in zip(missing, resolutions, strict=True):
                    decisions[index] = resolution
                positives = sum(labels)
                negatives = 4 - positives
                possibilities["accuracy"].append(
                    sum(label == decision
                        for label, decision in zip(labels, decisions, strict=True)) / 4
                )
                if positives:
                    possibilities["recall"].append(
                        sum(label == 1 and decision == 1
                            for label, decision in zip(labels, decisions, strict=True)) / positives
                    )
                if negatives:
                    possibilities["fpr"].append(
                        sum(label == 0 and decision == 1
                            for label, decision in zip(labels, decisions, strict=True)) / negatives
                    )
            for metric, values in possibilities.items():
                bounds = coverage["binary_completion_bounds"][metric]
                if not values:
                    assert bounds is None
                else:
                    assert bounds["lower"] == pytest.approx(min(values))
                    assert bounds["upper"] == pytest.approx(max(values))
            populations += 1
    assert populations == 1296


def test_selective_positive_abstention_is_visible_despite_perfect_conditional_recall():
    report = run(Outcomes([1.0, None, None, 0.0]), records([1, 1, 1, 0]))
    assert report.metrics.recall == 1.0
    coverage = report.coverage_summary()
    assert coverage["by_class"]["positive"]["answer_coverage"] == pytest.approx(1 / 3)
    assert coverage["by_class"]["negative"]["answer_coverage"] == 1.0
    assert coverage["binary_completion_bounds"]["recall"] == {"lower": 1 / 3, "upper": 1.0}


def test_empty_population_has_no_coverage_or_completion_bounds():
    coverage = run(Outcomes([]), []).coverage_summary()
    assert coverage["answer_coverage"] is None
    assert all(value is None for value in coverage["binary_completion_bounds"].values())
    assert coverage["by_class"]["positive"]["answer_coverage"] is None


def test_inconsistent_accounting_cannot_produce_coverage_claim():
    report = run(Outcomes([None]), records([1]))
    report.n_skipped = 0
    with pytest.raises(ValueError, match="accounting"):
        report.coverage_summary()


def test_per_record_snapshot_preserves_abstentions_and_input_order():
    report = run(Outcomes([None, 0.1, 0.9]), records([1, 0, 1]))
    assert report.record_scores == [None, 0.1, 0.9]
    assert report.observations == [(0, 0.1), (1, 0.9)]


def test_eval_json_includes_class_coverage(tmp_path, monkeypatch, capsys):
    import json

    from lurebench import cli
    from lurebench.schema import save_jsonl

    source = tmp_path / "synthetic.jsonl"
    save_jsonl(records([1, 0]), source)
    monkeypatch.setattr(cli, "get_detector", lambda name: Outcomes([None, 0.0]))
    assert cli.main(["eval", "-d", str(source), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)[0]
    assert report["coverage"]["by_class"]["positive"]["abstained"] == 1
    assert report["coverage"]["binary_completion_bounds"]["recall"] == {"lower": 0, "upper": 1}
