"""Class polarity and stored task are part of a trained model's meaning."""

import math
from types import SimpleNamespace

import pytest

from lurebench.detectors.tfidf import TfidfLogisticDetector
from lurebench.schema import Lure

PROBE = Lure(id="synthetic", text="Synthetic message", label=0,
             source="human", typology="benign")


class PipelineStub:
    def __init__(self, classes=(0, 1), output=None):
        self.classes_ = list(classes)
        self.output = [[.25, .75]] if output is None else output
        self.calls = 0

    def predict_proba(self, texts):
        self.calls += 1
        return self.output


@pytest.mark.parametrize("classes", [[], [0], [1], [0, 2], [-1, 1], [0, 0],
                                     [1, 1], [0, 1, 2], [False, True],
                                     [0., 1.], ["0", "1"], [[0], [1]]])
def test_invalid_class_mappings_are_rejected_before_inference(classes):
    pipe = PipelineStub(classes)
    with pytest.raises(ValueError):
        TfidfLogisticDetector.from_pipeline(pipe, "fraud")
    assert pipe.calls == 0


@pytest.mark.parametrize("classes,expected", [([0, 1], .75), ([1, 0], .25)])
def test_positive_class_is_selected_by_label(classes, expected):
    detector = TfidfLogisticDetector.from_pipeline(PipelineStub(classes), "fraud")
    assert detector.score(PROBE) == expected


@pytest.mark.parametrize("output", [[], [.25, .75], [[.25]], [[.1, .2, .7]],
                                    [[.25, .75], [.25, .75]], [[True, False]],
                                    [["0.25", "0.75"]], [[None, .75]],
                                    [[math.nan, .75]], [[math.inf, .75]],
                                    [[-.25, .75]], [[1.25, .75]], [[.5, .75]],
                                    [[.25, 10**400]], [[.25, None]],
                                    [[[.25], [.75]]]])
def test_invalid_full_probability_row_is_rejected(output):
    detector = TfidfLogisticDetector.from_pipeline(PipelineStub(output=output), "fraud")
    with pytest.raises(ValueError):
        detector.score(PROBE)


@pytest.mark.parametrize("task", ["", "other", None, True, [], "FRAUD"])
def test_injected_pipeline_requires_explicit_known_task(task):
    with pytest.raises(ValueError):
        TfidfLogisticDetector.from_pipeline(PipelineStub(), task)


def test_classes_cannot_change_after_attachment():
    pipe = PipelineStub()
    detector = TfidfLogisticDetector.from_pipeline(pipe, "fraud")
    pipe.classes_ = [1, 0]
    with pytest.raises(ValueError):
        detector.score(PROBE)
    assert pipe.calls == 0


def test_class_change_during_inference_is_rejected():
    pipe = PipelineStub()
    detector = TfidfLogisticDetector.from_pipeline(pipe, "fraud")

    def mutate(texts):
        pipe.classes_ = [1, 0]
        return [[.25, .75]]

    pipe.predict_proba = mutate
    with pytest.raises(ValueError):
        detector.score(PROBE)


@pytest.mark.parametrize("task", ["fraud", "provenance"])
def test_load_preserves_task_and_explicit_match(monkeypatch, task):
    joblib = pytest.importorskip("joblib")

    monkeypatch.setattr(joblib, "load", lambda path: {"pipeline": PipelineStub(), "task": task})
    detector = TfidfLogisticDetector(model_path=__file__)
    assert detector.task == task
    assert detector.score(PROBE) == .75
    assert TfidfLogisticDetector(model_path=__file__, task=task).task == task
    opposite = "provenance" if task == "fraud" else "fraud"
    with pytest.raises(ValueError, match="task"):
        TfidfLogisticDetector(model_path=__file__, task=opposite)


@pytest.mark.parametrize("blob", [None, [], {}, {"pipeline": PipelineStub()},
                                  {"pipeline": PipelineStub(), "task": "other"},
                                  {"task": "fraud"}, {"pipeline": None, "task": "fraud"}])
def test_malformed_artifact_metadata_is_rejected(monkeypatch, blob):
    joblib = pytest.importorskip("joblib")

    monkeypatch.setattr(joblib, "load", lambda path: blob)
    with pytest.raises(ValueError):
        TfidfLogisticDetector(model_path=__file__)


def test_invalid_explicit_task_rejected_before_deserialization(monkeypatch):
    joblib = pytest.importorskip("joblib")

    called = []
    monkeypatch.setattr(joblib, "load", lambda path: called.append(True))
    with pytest.raises(ValueError):
        TfidfLogisticDetector(model_path=__file__, task="other")
    assert called == []


@pytest.mark.parametrize("classes,expected", [([0, 1], ["positive", "negative"]),
                                            ([1, 0], ["negative", "positive"])])
def test_feature_ranking_uses_positive_label_polarity(classes, expected):
    pipe = PipelineStub(classes)
    pipe.named_steps = {
        "tfidf": SimpleNamespace(get_feature_names_out=lambda: ["positive", "negative"]),
        "clf": SimpleNamespace(classes_=classes, coef_=[[2., -3.]]),
    }
    detector = TfidfLogisticDetector.from_pipeline(pipe, "fraud")
    assert detector.top_positive_features(2) == expected


def test_numpy_integer_classes_and_float_probabilities_are_supported():
    np = pytest.importorskip("numpy")
    pipe = PipelineStub()
    pipe.classes_ = np.array([0, 1], dtype=np.int64)
    pipe.output = np.array([[.25, .75]], dtype=np.float32)
    assert TfidfLogisticDetector.from_pipeline(pipe, "fraud").score(PROBE) == .75


def test_probability_sum_tolerates_float32_rounding_without_renormalizing():
    output = [[.1, .90000002]]
    detector = TfidfLogisticDetector.from_pipeline(PipelineStub(output=output), "fraud")
    assert detector.score(PROBE) == .90000002


def test_real_benign_only_estimator_is_not_relabelled_as_fraud():
    sklearn_dummy = pytest.importorskip("sklearn.dummy")
    estimator = sklearn_dummy.DummyClassifier(strategy="most_frequent")
    estimator.fit(["ordinary notes", "meeting notes"], [0, 0])
    assert estimator.predict_proba([PROBE.text]).tolist() == [[1.]]
    with pytest.raises(ValueError, match="classes"):
        TfidfLogisticDetector.from_pipeline(estimator, "fraud")


@pytest.mark.parametrize("pipe", [None, object(), SimpleNamespace(classes_=[0, 1]),
                                 SimpleNamespace(classes_=[0, 1], predict_proba=42)])
def test_unfitted_or_nonpredicting_pipeline_rejected(pipe):
    with pytest.raises(ValueError):
        TfidfLogisticDetector.from_pipeline(pipe, "fraud")


def test_numpy_boolean_classes_are_not_integer_targets():
    np = pytest.importorskip("numpy")
    pipe = PipelineStub()
    pipe.classes_ = np.array([False, True])
    with pytest.raises(ValueError):
        TfidfLogisticDetector.from_pipeline(pipe, "fraud")


def test_changed_classes_cannot_be_saved(tmp_path):
    pipe = PipelineStub()
    detector = TfidfLogisticDetector.from_pipeline(pipe, "fraud")
    pipe.classes_ = [0]
    output = tmp_path / "new-directory" / "model.joblib"
    with pytest.raises(ValueError):
        detector.save(str(output))
    assert not output.parent.exists()


@pytest.mark.parametrize("classes,coef", [([1, 0], [[1., 2.]]),
                                        ([0, 1], [[math.nan, 2.]]),
                                        ([0, 1], [[1.]]),
                                        ([0, 1], [[1., 2.], [3., 4.]])])
def test_unsupported_feature_explanations_are_not_emitted(classes, coef):
    pipe = PipelineStub()
    pipe.named_steps = {
        "tfidf": SimpleNamespace(get_feature_names_out=lambda: ["one", "two"]),
        "clf": SimpleNamespace(classes_=classes, coef_=coef),
    }
    detector = TfidfLogisticDetector.from_pipeline(pipe, "fraud")
    assert detector.top_positive_features() == []
