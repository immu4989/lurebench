import json
from pathlib import Path

import pytest

from lurebench import mandate, mandate_conformance

VECTOR = Path(__file__).parents[1] / "conformance/luremandate-v1"
NOW = "2026-09-22T00:00:00Z"


def load(name):
    return json.loads((VECTOR / name).read_bytes())


def create(kind, value):
    if kind == "evaluation":
        return mandate.evaluate_mandate(load("plan.json"), load("run.json"), evaluated_at=value)
    if kind == "challenge":
        return mandate_conformance.compile_mandate_challenge(
            load("conformance-plan.json"), load("conformance-run.json"),
            challenge_id="test-challenge", generated_at=value,
        )
    if kind == "submission":
        return mandate_conformance.reference_mandate_submission(
            load("challenge.json"), submission_id="test-submission", submitted_at=value,
        )
    return mandate_conformance.evaluate_mandate_conformance(
        load("challenge.json"), load("submission.json"), evaluated_at=value,
    )


@pytest.mark.parametrize("kind", ["evaluation", "challenge", "submission", "score"])
@pytest.mark.parametrize("value", ["", False, 0, [], {}])
def test_explicit_falsy_timestamp_is_rejected_not_replaced(monkeypatch, kind, value):
    def forbidden_clock():
        raise AssertionError("explicit timestamps must not request a default clock")

    monkeypatch.setattr(mandate, "_now", forbidden_clock)
    monkeypatch.setattr(mandate_conformance, "_now", forbidden_clock)
    with pytest.raises(ValueError):
        create(kind, value)


@pytest.mark.parametrize("kind,field", [
    ("evaluation", "evaluated_at"), ("challenge", "generated_at"),
    ("submission", "submitted_at"), ("score", "evaluated_at"),
])
def test_none_uses_clock_and_explicit_timestamp_is_preserved(monkeypatch, kind, field):
    monkeypatch.setattr(mandate, "_now", lambda: NOW)
    monkeypatch.setattr(mandate_conformance, "_now", lambda: NOW)
    assert create(kind, None)[field] == NOW
    explicit = "2026-09-23T00:00:00Z"
    assert create(kind, explicit)[field] == explicit
