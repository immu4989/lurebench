import math

import pytest

from lurebench.detectors.base import Detector
from lurebench.detectors.cache import CachedDetector, _key
from lurebench.harness import collect_scores, run
from lurebench.probability import DetectorAbstainedError, validate_score
from lurebench.schema import Lure

RECORD = Lure(id="synthetic", text="synthetic message", label=1, source="ai", typology="phishing")


class Fixed(Detector):
    def __init__(self, value):
        self.value = value

    def score(self, lure):
        return self.value


@pytest.mark.parametrize("value", [True, False, "0.5", [], {}, math.nan, math.inf,
                                  -math.inf, -0.01, 1.01, 10**400])
def test_invalid_probability_rejected_by_harness_collection_prediction_and_cache(value):
    detector = Fixed(value)
    for operation in (
        lambda: run(detector, [RECORD]), lambda: collect_scores(detector, [RECORD]),
        lambda: detector.predict(RECORD), lambda: CachedDetector(detector).score(RECORD),
    ):
        with pytest.raises(ValueError):
            operation()


@pytest.mark.parametrize("value", [0, 0.0, 0.5, 1, 1.0])
def test_valid_probability_boundaries(value):
    assert validate_score(value) == float(value)


def test_abstention_is_counted_but_never_hard_predicted_as_negative():
    detector = Fixed(None)
    report = run(detector, [RECORD])
    assert report.metrics.n == 0
    assert report.n_skipped == 1
    assert "abstained=1" in report.summary_line()
    assert collect_scores(detector, [RECORD]) == ([], [], [])
    with pytest.raises(DetectorAbstainedError):
        detector.predict(RECORD)
    cached = CachedDetector(detector)
    assert cached.score(RECORD) is None
    assert cached.score(RECORD) is None
    assert cached.hits == 1


def test_invalid_cached_probability_fails_without_new_provider_call():
    class NoCall(Fixed):
        def score(self, lure):
            raise AssertionError("invalid cached values must not trigger paid retries")

    cached = CachedDetector(NoCall(None))
    cached.store.set(_key(cached.name, RECORD.text), "private-invalid-output")
    with pytest.raises(ValueError) as error:
        cached.score(RECORD)
    assert "private-invalid-output" not in str(error.value)


@pytest.mark.parametrize("threshold", [None, True, "0.5", math.nan, math.inf, -1, 2])
def test_invalid_threshold_rejected_before_detector_call(threshold):
    class NoCall(Fixed):
        def score(self, lure):
            raise AssertionError("threshold validation must precede provider calls")

    detector = NoCall(None)
    with pytest.raises(ValueError):
        run(detector, [RECORD], threshold=threshold)
    with pytest.raises(ValueError):
        detector.predict(RECORD, threshold=threshold)
