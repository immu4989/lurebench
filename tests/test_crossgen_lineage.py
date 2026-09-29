"""Training/evaluation boundary tests with a deterministic instrumented detector."""

import random

import pytest

from lurebench.crossgen import cross_generator_provenance, render_markdown
from lurebench.schema import Lure


def corpus():
    result = []
    for i in range(100):
        result.append(Lure(id=f"h{i}", text=f"human {i}", source="human", label=1,
                           typology="phishing"))
        for g in ("A", "B"):
            result.append(Lure(id=f"{g}{i}", text=f"synthetic {g} {i}", source="ai", label=1,
                               typology="phishing", generator=g, meta={"rewrite_of": f"h{i}"}))
    return result


class Recorder:
    trained = []

    @classmethod
    def train(cls, records, task):
        assert task == "provenance"
        instance = cls()
        instance.train_records = list(records)
        instance.test_records = []
        cls.trained.append(instance)
        return instance

    def score(self, record):
        self.test_records.append(record)
        return .9 if record.source == "ai" else .1


@pytest.fixture(autouse=True)
def reset_calls():
    Recorder.trained = []


def test_default_holds_out_both_generator_and_original_seed():
    result = cross_generator_provenance(corpus(), detector_cls=Recorder)
    for row, detector in zip(result, Recorder.trained, strict=True):
        train_seeds = {r.meta.get("rewrite_of", r.id) for r in detector.train_records}
        test_seeds = {r.meta.get("rewrite_of", r.id) for r in detector.test_records}
        assert not train_seeds & test_seeds
        assert all(r.generator != row.held_out for r in detector.train_records)
        assert row.overlapping_lineage_components == 0
        assert row.split_mode == "lineage_disjoint"
        assert row.n_test_ai == row.n_test_human
        assert row.n_train_ai == row.n_train_human
        assert row.n_train_ai + row.n_test_ai == 100
        assert row.auc == 1
        assert row.balanced_accuracy == 1


def test_reordered_input_has_identical_folds_and_report():
    data = corpus()
    first = cross_generator_provenance(data, detector_cls=Recorder)
    first_ids = [([r.id for r in d.train_records], [r.id for r in d.test_records])
                 for d in Recorder.trained]
    Recorder.trained = []
    random.Random(987).shuffle(data)
    assert cross_generator_provenance(data, detector_cls=Recorder) == first
    assert [([r.id for r in d.train_records], [r.id for r in d.test_records])
            for d in Recorder.trained] == first_ids


def test_legacy_mode_exposes_sibling_leakage_and_original_test_size():
    rows = cross_generator_provenance(corpus(), detector_cls=Recorder, split_mode="legacy_index")
    assert all(row.n_test_ai == 100 for row in rows)
    assert all(row.overlapping_lineage_components == 100 for row in rows)
    report = render_markdown(rows, "synthetic only")
    assert "legacy_index" in report
    assert "threshold-independent" not in report
    assert "Balanced accuracy" in report
    assert "depend on the supplied threshold" in report


@pytest.mark.parametrize("change", [{"threshold": True}, {"threshold": float("nan")},
                                    {"human_holdout_k": 0}, {"human_holdout_k": 1},
                                    {"human_holdout_k": True}, {"human_holdout_k": 2.5},
                                    {"human_holdout_k": 101}, {"split_mode": "other"}])
def test_invalid_controls_fail_before_training(change):
    with pytest.raises(ValueError):
        cross_generator_provenance(corpus(), detector_cls=Recorder, **change)
    assert Recorder.trained == []


def test_single_component_and_missing_generator_fail_before_training():
    records = corpus()
    for record in records:
        record.meta["family_id"] = "one-component"
    with pytest.raises(ValueError, match="no training started"):
        cross_generator_provenance(records, detector_cls=Recorder)
    assert Recorder.trained == []
    records = corpus()
    records[1].generator = None
    with pytest.raises(ValueError, match="generator identity"):
        cross_generator_provenance(records, detector_cls=Recorder)
    assert Recorder.trained == []


@pytest.mark.parametrize("bad", [None, True, "0.9", float("nan"), float("inf"), -1, 1.1])
def test_missing_or_invalid_scores_cannot_be_valid_metrics(bad):
    class BadScore(Recorder):
        def score(self, record):
            return bad

    with pytest.raises(ValueError):
        cross_generator_provenance(corpus(), detector_cls=BadScore)
