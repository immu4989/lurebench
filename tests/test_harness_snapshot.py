"""Detector callbacks cannot redefine the harness's captured ground truth."""

from types import SimpleNamespace

import pytest

from lurebench.harness import collect_scores, run
from lurebench.schema import Lure


@pytest.mark.parametrize("operation", [run, collect_scores])
def test_mutating_callback_cannot_relabel_or_change_caller_record(operation):
    record = Lure("original", "Synthetic notes", 1, "human", "phishing",
                  meta={"nested": {"note": "original"}})
    original = record.to_dict()

    def score(value):
        value.label = 0
        value.id = "changed-id"
        value.meta["nested"]["note"] = "changed"
        return 0.

    result = operation(SimpleNamespace(task="fraud", score=score), [record])
    if operation is run:
        assert result.metrics.fn == 1 and result.metrics.tn == 0
        assert result.observations == [(1, 0.)]
    else:
        assert result == (["original"], [1], [0.])
    assert record.to_dict() == original


@pytest.mark.parametrize("operation", [run, collect_scores])
@pytest.mark.parametrize("task", ["fraud", "provenance"])
@pytest.mark.parametrize("answer", [None, 0., 1.])
def test_targets_and_abstention_classes_captured_before_callback(operation, task, answer):
    record = Lure("positive", "Notes", 1, "ai", "phishing")

    def score(value):
        value.label = 0
        value.source = "human"
        return answer

    result = operation(SimpleNamespace(task=task, score=score), [record])
    if operation is collect_scores:
        assert result == (([], [], []) if answer is None else (["positive"], [1], [answer]))
    elif answer is None:
        assert result.n_abstained_positive == 1 and result.n_abstained_negative == 0
        assert result.coverage_summary()["by_class"]["positive"]["records"] == 1
    else:
        assert result.observations == [(1, answer)]
        assert result.metrics.tp == int(answer == 1.)
        assert result.metrics.fn == int(answer == 0.)
    assert record.label == 1 and record.source == "ai"


@pytest.mark.parametrize("operation", [run, collect_scores])
@pytest.mark.parametrize("field,value", [
    ("label", 2), ("label", True), ("source", "unknown"), ("text", 123),
    ("id", ""), ("typology", "benign"), ("persuasion", "invalid"), ("meta", []),
])
def test_late_mutated_input_rejected_before_any_callback(operation, field, value):
    first = Lure("first", "Notes", 1, "human", "phishing")
    invalid = Lure("second", "private input", 1, "human", "phishing")
    setattr(invalid, field, value)
    detector = SimpleNamespace(task="fraud", score=lambda _: pytest.fail("callback started"))
    with pytest.raises(ValueError, match="record 2") as error:
        operation(detector, [first, invalid])
    assert "private input" not in str(error.value) and error.value.__suppress_context__


@pytest.mark.parametrize("operation", [run, collect_scores])
@pytest.mark.parametrize("task", [False, 0, "", [], {}, "other"])
def test_invalid_explicit_task_never_silently_falls_back(operation, task):
    detector = SimpleNamespace(task="fraud", score=lambda _: pytest.fail("callback started"))
    with pytest.raises(ValueError, match="task must"):
        operation(detector, [], task=task)


@pytest.mark.parametrize("operation", [run, collect_scores])
def test_explicit_valid_task_overrides_detector_task(operation):
    record = Lure("example", "Notes", 0, "ai", "benign")
    detector = SimpleNamespace(task="fraud", score=lambda _: .8)
    result = operation(detector, [record], task="provenance")
    if operation is run:
        assert result.task == "provenance" and result.metrics.tp == 1
    else:
        assert result == (["example"], [1], [.8])


@pytest.mark.parametrize("operation", [run, collect_scores])
def test_repeated_input_references_are_isolated_per_observation(operation):
    record = Lure("repeated", "original", 1, "human", "phishing",
                  persuasion=["urgency"], meta={"list": [1]})
    original = record.to_dict()
    seen = []

    def score(value):
        seen.append(value.to_dict())
        value.text = "changed"
        value.persuasion.clear()
        value.meta["list"].append(2)
        return .7

    operation(SimpleNamespace(score=score), [record, record])
    assert seen == [original, original] and record.to_dict() == original


@pytest.mark.parametrize("operation", [run, collect_scores])
@pytest.mark.parametrize("failure", ["raise", "invalid-score"])
def test_callback_failure_does_not_modify_caller_dataset(operation, failure):
    record = Lure("original", "original", 1, "human", "phishing")
    original = record.to_dict()

    def score(value):
        value.text = "changed"
        if failure == "raise":
            raise RuntimeError("synthetic failure")
        return float("nan")

    with pytest.raises(RuntimeError if failure == "raise" else ValueError):
        operation(SimpleNamespace(score=score), [record])
    assert record.to_dict() == original


def test_all_records_prepared_before_first_callback():
    records = [Lure(str(i), "original", 1, "human", "phishing") for i in range(2)]
    seen = []

    def score(value):
        # A reference held outside the callback API remains outside its isolation
        # boundary, but it must not alter the already captured run inputs.
        records[1].label = 0
        records[1].text = "external change"
        seen.append(value.text)
        return 0.

    report = run(SimpleNamespace(score=score), records)
    assert seen == ["original", "original"]
    assert report.metrics.fn == 2 and report.metrics.tn == 0


@pytest.mark.parametrize("operation", [run, collect_scores])
def test_non_lure_input_rejected_before_callbacks(operation):
    with pytest.raises(ValueError, match="record 1"):
        operation(SimpleNamespace(score=lambda _: pytest.fail("callback started")), [{}])
