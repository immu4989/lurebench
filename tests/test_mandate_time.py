"""Authority time inputs must not be rounded or normalized permissively."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from lurebench.mandate import validate_mandate_plan
from lurebench.mandate_time import (
    TIMESTAMP_PATTERN,
    parse_mandate_timestamp,
    validate_mandate_timestamp,
)

INVALID = [
    "2026-09-05 15:00:00Z",
    "2026-09-05X15:00:00Z",
    "20260905T150000Z",
    "2026-W36-6T15:00:00Z",
    "2026-09-05T15:00:00.1234567Z",
    "2026-09-05T15:00:00+05:60",
    "2026-09-05T15:00:00+24:00",
    "2026-09-05T15:00:00+05:30:30",
    "2026-09-05T15:00:00",
    "2026-02-30T15:00:00Z",
    "2026-09-05T23:59:60Z",
    "2026-09-05T15:00:00Z\n",
    "0001-01-01T00:00:00+01:00",
    "9999-12-31T23:59:59-01:00",
]


@pytest.mark.parametrize("value", INVALID)
def test_unsupported_timestamps_fail_closed(value):
    with pytest.raises(ValueError):
        parse_mandate_timestamp(value, "test time")


@pytest.mark.parametrize(
    "value",
    [
        "2026-09-05T15:00:00Z",
        "2026-09-05T15:00:00.000000+00:00",
        "2026-09-05T20:30:00+05:30",
        "2026-09-05T11:00:00-04:00",
        "2026-09-05T15:00:00-00:00",
    ],
)
def test_equivalent_offsets_preserve_exact_utc_instant_and_source_string(value):
    assert parse_mandate_timestamp(value, "time") == datetime(2026, 9, 5, 15, tzinfo=timezone.utc)
    assert validate_mandate_timestamp(value, "time") == value
    Draft202012Validator(
        {"type": "string", "format": "date-time", "pattern": TIMESTAMP_PATTERN},
        format_checker=FormatChecker(),
    ).validate(value)


def test_plan_entrypoint_enforces_timestamp_profile():
    path = Path(__file__).parents[1] / "conformance/luremandate-v1/plan.json"
    plan = json.loads(path.read_text())
    plan["created_at"] = "2026-09-05T14:59:00.0000001Z"
    with pytest.raises(ValueError, match="microsecond"):
        validate_mandate_plan(plan)


def test_every_published_mandate_datetime_has_the_profile_constraint():
    root = Path(__file__).parents[1] / "spec"
    found = 0

    def walk(value):
        nonlocal found
        if isinstance(value, dict):
            if value.get("format") == "date-time":
                assert value.get("pattern") == TIMESTAMP_PATTERN
                found += 1
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    for path in root.glob("luremandate*.schema.json"):
        walk(json.loads(path.read_text()))
    assert found > 10


def test_rolling_window_does_not_underflow_at_earliest_supported_date():
    from lurebench.mandate import _sha256
    from lurebench.mandate import evaluate_mandate as evaluate
    from lurebench.permit import _canonical

    root = Path(__file__).parents[1] / "conformance/luremandate-v1"
    plan = json.loads((root / "plan.json").read_text())
    run = json.loads((root / "run.json").read_text())
    plan["created_at"] = "0001-01-01T00:00:00Z"
    run["plan_sha256"] = _sha256(_canonical(plan))
    run["started_at"] = "0001-01-01T00:00:01Z"
    run["completed_at"] = "0001-01-01T00:00:05Z"
    transaction = run["transactions"][0]
    run["transactions"] = [transaction]
    transaction["intent"]["proposed_at"] = "0001-01-01T00:00:01Z"
    transaction["intent_sha256"] = _sha256(_canonical(transaction["intent"]))
    for approval in transaction["approvals"]:
        approval["issued_at"] = "0001-01-01T00:00:02Z"
        approval["expires_at"] = "0001-01-01T00:00:04Z"
        approval["intent_sha256"] = transaction["intent_sha256"]
    transaction["decision"]["decided_at"] = "0001-01-01T00:00:03Z"
    transaction["outcome"]["observed_at"] = "0001-01-01T00:00:04Z"
    result = evaluate(plan, run, evaluated_at="0001-01-01T00:00:05Z")
    assert result["results"][0]["expected_reason_code"] == "authority_satisfied"
