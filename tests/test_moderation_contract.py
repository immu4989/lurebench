"""Synthetic moderation responses must not turn missing evidence into scores."""

import math
import sys
from types import SimpleNamespace

import pytest

from lurebench.detectors import moderation
from lurebench.detectors.cache import CachedDetector
from lurebench.diskcache import CacheReadError
from lurebench.schema import Lure

CATEGORIES = (
    "harassment", "harassment/threatening", "hate", "hate/threatening", "illicit",
    "illicit/violent", "self-harm", "self-harm/intent", "self-harm/instructions",
    "sexual", "sexual/minors", "violence", "violence/graphic",
)
PROBE = Lure("synthetic", "Synthetic neutral notes", 0, "human", "benign")


def response(scores=None, flagged=False):
    if scores is None:
        scores = {name: .1 for name in CATEGORIES}
    return SimpleNamespace(results=[SimpleNamespace(category_scores=SimpleNamespace(**scores),
                                                   flagged=flagged)])


def client(payload):
    return SimpleNamespace(moderations=SimpleNamespace(create=lambda **kw: payload))


def raw_detector(payload):
    # Reproduce the existing score method independently of optional SDK setup.
    detector = moderation.OpenAIModerationDetector.__new__(moderation.OpenAIModerationDetector)
    detector._client = client(payload)
    detector._model = "omni-moderation-latest"
    return detector


@pytest.mark.parametrize("flagged", [False, True])
@pytest.mark.parametrize("scores", [None, SimpleNamespace(), SimpleNamespace(violence=.1)])
def test_missing_or_partial_scores_never_fall_back_to_flagged(flagged, scores):
    payload = response()
    payload.results[0].category_scores = scores
    with pytest.raises(RuntimeError):
        raw_detector(payload).score(PROBE)


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf, True, False,
                                  "0.9", None, [], {}, -.1, 1.1, 10**400])
@pytest.mark.parametrize("location", ["harassment", "violence/graphic"])
def test_every_category_is_validated_before_maximum(value, location):
    scores = {name: .3 for name in CATEGORIES}
    scores[location] = value
    with pytest.raises(RuntimeError):
        raw_detector(response(scores)).score(PROBE)


@pytest.mark.parametrize("results", [None, [], (), {}, [None], [response().results[0]] * 2])
def test_exactly_one_result_is_required(results):
    with pytest.raises(RuntimeError):
        raw_detector(SimpleNamespace(results=results)).score(PROBE)


@pytest.mark.parametrize("flagged", [None, 0, 1, "false", [], {}])
def test_flagged_field_is_boolean_not_a_score_fallback(flagged):
    with pytest.raises(RuntimeError):
        raw_detector(response(flagged=flagged)).score(PROBE)


def test_unknown_or_duplicate_category_aliases_fail_closed():
    for extra in ({"new_category": .9}, {"self_harm": .9}):
        scores = {name: .1 for name in CATEGORIES}
        with pytest.raises(RuntimeError):
            raw_detector(response({**scores, **extra})).score(PROBE)


@pytest.mark.parametrize("value", [0., .27, 1.])
@pytest.mark.parametrize("flagged", [False, True])
def test_complete_valid_scores_keep_historical_maximum(value, flagged):
    scores = {name: 0. for name in CATEGORIES}
    scores["violence"] = value
    assert raw_detector(response(scores, flagged)).score(PROBE) == value


def test_plain_mapping_and_sdk_attribute_aliases_are_supported():
    mapping = {"results": [{"flagged": False, "category_scores": {
        name: .4 for name in CATEGORIES
    }}]}
    assert raw_detector(mapping).score(PROBE) == .4
    scores = {name.replace("-", "_").replace("/", "_"): .4 for name in CATEGORIES}
    assert raw_detector(response(scores)).score(PROBE) == .4


def test_sdk_model_dump_uses_wire_aliases():
    class Scores:
        def model_dump(self, *, by_alias):
            assert by_alias is True
            return {name: .4 for name in CATEGORIES}

    payload = response()
    payload.results[0].category_scores = Scores()
    assert raw_detector(payload).score(PROBE) == .4


def test_injected_client_needs_context_for_persistent_caching(tmp_path):
    detector = moderation.OpenAIModerationDetector(client=client(response()))
    assert detector.score(PROBE) == .1
    with pytest.raises(ValueError, match="cache_context"):
        CachedDetector(detector, str(tmp_path / "cache.json"))


def test_invalid_response_is_not_cached_and_error_is_redacted(tmp_path):
    payload = response({**{name: .1 for name in CATEGORIES}, "private sentinel": .5})
    detector = moderation.OpenAIModerationDetector(client=client(payload), cache_context="a" * 64)
    cache = CachedDetector(detector, str(tmp_path / "cache.json"))
    with pytest.raises(RuntimeError) as error:
        cache.score(PROBE)
    assert "private sentinel" not in str(error.value)
    assert cache._cache == {}


def test_cache_context_and_model_changes_reject_existing_cache(tmp_path):
    path = str(tmp_path / "cache.json")
    first = moderation.OpenAIModerationDetector(client=client(response()), cache_context="a" * 64)
    cache = CachedDetector(first, path)
    cache.score(PROBE)
    cache.flush()
    for kwargs in ({"cache_context": "b" * 64},
                   {"cache_context": "a" * 64, "model": "reviewed-other-model"}):
        detector = moderation.OpenAIModerationDetector(client=client(response()), **kwargs)
        with pytest.raises(CacheReadError):
            CachedDetector(detector, path)


@pytest.mark.parametrize("kwargs", [{"model": ""}, {"model": "x" * 257},
                                    {"model": True}, {"model": "bad\nmodel"},
                                    {"cache_context": "bad"}, {"cache_context": True}])
def test_invalid_constructor_controls_fail_before_sdk_import(monkeypatch, kwargs):
    monkeypatch.setitem(sys.modules, "openai", None)
    with pytest.raises(ValueError):
        moderation.OpenAIModerationDetector(**kwargs)


def test_transport_failures_propagate_without_a_score():
    detector = raw_detector(response())

    def fail(**kwargs):
        raise OSError("synthetic network failure")

    detector._client.moderations.create = fail
    with pytest.raises(OSError):
        detector.score(PROBE)


def test_legacy_score_cache_is_preserved_and_rejected(tmp_path):
    path = tmp_path / "legacy.json"
    old = CachedDetector(SimpleNamespace(name="openai-moderation", task="fraud",
                                         score=lambda record: 0.), str(path))
    old.score(PROBE)
    old.flush()
    before = path.read_bytes()
    detector = moderation.OpenAIModerationDetector(client=client(response()), cache_context="a" * 64)
    with pytest.raises(CacheReadError):
        CachedDetector(detector, str(path))
    assert path.read_bytes() == before


def test_sdk_constructor_identity_tracks_endpoint_and_model_not_credentials(monkeypatch):
    calls = []
    endpoint = ["https://provider.example.test/v1/"]

    def sdk_client():
        calls.append(True)
        supplied = client(response())
        supplied.base_url = endpoint[0]
        return supplied

    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=sdk_client))
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-first")
    first = moderation.OpenAIModerationDetector()
    assert first.cache_namespace is not None
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-rotated")
    assert moderation.OpenAIModerationDetector().cache_namespace == first.cache_namespace
    endpoint[0] = "https://another-provider.example.test/v1/"
    assert moderation.OpenAIModerationDetector().cache_namespace != first.cache_namespace
    assert moderation.OpenAIModerationDetector(model="other").cache_namespace != first.cache_namespace
    assert len(calls) == 4


def test_request_preserves_text_and_selected_model():
    calls = []

    def create(**kwargs):
        calls.append(kwargs)
        return response()

    supplied = SimpleNamespace(moderations=SimpleNamespace(create=create))
    detector = moderation.OpenAIModerationDetector(model="reviewed-model", client=supplied)
    detector.score(PROBE)
    assert calls == [{"model": "reviewed-model", "input": PROBE.text}]


@pytest.mark.parametrize("supplied", [object(), {}, SimpleNamespace(moderations=None),
                                     SimpleNamespace(moderations=SimpleNamespace(create=1))])
def test_incompatible_injected_client_rejected(supplied):
    with pytest.raises(ValueError, match="moderations.create"):
        moderation.OpenAIModerationDetector(client=supplied)


def test_pydantic_category_alias_serialization():
    pydantic = pytest.importorskip("pydantic")
    fields = {
        name.replace("-", "_").replace("/", "_"):
        (float, pydantic.Field(alias=name)) for name in CATEGORIES
    }
    category_model = pydantic.create_model("SyntheticCategoryScores", **fields)
    payload = response()
    payload.results[0].category_scores = category_model(**{name: .4 for name in CATEGORIES})
    assert raw_detector(payload).score(PROBE) == .4
