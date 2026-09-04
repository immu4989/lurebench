from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from lurebench.identity import default_identity_plan, validate_identity_plan
from lurebench.runtime import default_runtime_profile, validate_runtime_profile
from lurebench.spiffe import parse_spiffe_id, validate_spiffe_trust_domain

ROOT = Path(__file__).parents[1]
VECTORS = json.loads(
    (ROOT / "conformance/spiffe-id-v1/vectors.json").read_text(encoding="utf-8")
)


@pytest.mark.parametrize(
    ("value", "domain"),
    [(item["value"], item["trust_domain"]) for item in VECTORS["valid_ids"]],
)
def test_spiffe_parser_accepts_normative_forms(value: str, domain: str):
    item = next(candidate for candidate in VECTORS["valid_ids"] if candidate["value"] == value)
    assert parse_spiffe_id(value, "identity", require_path=item["require_path"]) == (
        value,
        domain,
    )
    assert validate_spiffe_trust_domain(domain, "domain") == domain


@pytest.mark.parametrize(
    "item",
    VECTORS["invalid_ids"],
    ids=[item["reason"] for item in VECTORS["invalid_ids"]],
)
def test_spiffe_parser_rejects_ambiguous_or_out_of_contract_forms(item: dict):
    with pytest.raises(ValueError):
        parse_spiffe_id(item["value"], "identity", require_path=item["require_path"])


def test_root_id_is_valid_general_identity_but_not_workload_identity():
    assert parse_spiffe_id("spiffe://example.com", "identity") == (
        "spiffe://example.com",
        "example.com",
    )
    with pytest.raises(ValueError, match="non-root path"):
        parse_spiffe_id("spiffe://example.com", "workload", require_path=True)


def test_identity_and_runtime_contracts_share_exact_spiffe_rules():
    plan = default_identity_plan()
    plan["principals"][3]["spiffe_id"] = "spiffe://trust_domain.example/ns/Prod/agent_1"
    assert validate_identity_plan(plan) == plan

    profile = default_runtime_profile()
    profile["identity"]["allowed_spiffe_trust_domains"] = ["trust_domain.example"]
    assert validate_runtime_profile(profile) == profile

    for bad in ("spiffe://example.com", "spiffe://example.com/a//b", "spiffe://EXAMPLE/a"):
        changed = json.loads(json.dumps(plan))
        changed["principals"][3]["spiffe_id"] = bad
        with pytest.raises(ValueError, match="canonical SPIFFE ID"):
            validate_identity_plan(changed)

    changed_profile = json.loads(json.dumps(profile))
    changed_profile["identity"]["allowed_spiffe_trust_domains"] = ["Example.com"]
    with pytest.raises(ValueError, match="trust domains"):
        validate_runtime_profile(changed_profile)


def test_public_spiffe_vectors_and_boundaries_are_schema_valid():
    schema = json.loads(
        (ROOT / "spec/spiffe-id-conformance-v1.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(VECTORS)
    for domain in VECTORS["valid_trust_domains"]:
        assert validate_spiffe_trust_domain(domain, "domain") == domain
    for domain in VECTORS["invalid_trust_domains"]:
        with pytest.raises(ValueError):
            validate_spiffe_trust_domain(domain, "domain")
    assert parse_spiffe_id(
        f"spiffe://{'a' * 255}/service", "identity", require_path=True
    )[1] == "a" * 255
    with pytest.raises(ValueError):
        validate_spiffe_trust_domain("a" * 256, "domain")
    with pytest.raises(ValueError):
        parse_spiffe_id(f"spiffe://example.com/{'a' * 2_030}", "identity")
