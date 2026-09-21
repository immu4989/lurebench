"""Reject Python equality aliases in untrusted JSON authority evidence."""

import json
from pathlib import Path

import pytest

from lurebench.mandate import default_mandate_plan, validate_mandate_plan
from lurebench.mandate_conformance import validate_mandate_conformance_score
from lurebench.mandate_counterfactual import validate_counterfactual_mandate_conformance
from lurebench.mandate_pairwise import validate_pairwise_mandate_conformance
from lurebench.mandate_sequence import validate_sequence_mandate_conformance

ROOT = Path(__file__).parents[1] / "conformance"
CASES = [
    ("luremandate-v1/conformance-score.json", validate_mandate_conformance_score),
    ("luremandate-pairwise-v1/pairwise-assurance.json", validate_pairwise_mandate_conformance),
    (
        "luremandate-counterfactual-v1/counterfactual-assurance.json",
        validate_counterfactual_mandate_conformance,
    ),
    ("luremandate-sequence-v1/sequence-assurance.json", validate_sequence_mandate_conformance),
]


@pytest.mark.parametrize("path,validator", CASES)
@pytest.mark.parametrize("replacement", [True, 1.0])
def test_schema_version_requires_integer(path, validator, replacement):
    value = json.loads((ROOT / path).read_text())
    value["schema_version"] = replacement
    with pytest.raises(ValueError):
        validator(value)


@pytest.mark.parametrize("path,validator", CASES)
def test_recomputed_counts_require_exact_json_types(path, validator):
    value = json.loads((ROOT / path).read_text())
    field = next(key for key, item in value["summary"].items() if type(item) is int)
    value["summary"][field] = float(value["summary"][field])
    with pytest.raises(ValueError):
        validator(value)


@pytest.mark.parametrize(
    "field,replacement",
    [
        ("maximum_invalid_allow_count", False),
        ("require_complete_outcomes", 1),
    ],
)
def test_policy_acceptance_has_exact_boolean_and_integer_types(field, replacement):
    plan = default_mandate_plan()
    plan["acceptance"][field] = replacement
    with pytest.raises(ValueError):
        validate_mandate_plan(plan)
