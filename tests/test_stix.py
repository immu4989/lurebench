"""Tests for the STIX 2.1 exporter."""

from __future__ import annotations

import json

from lurebench import stix
from lurebench.schema import Lure


def _records():
    return [
        Lure(id="lb-1", text="Verify your account or it will be suspended.", label=1,
             source="ai", typology="phishing", generator="deepseek-v4-pro",
             channel="email", persuasion=["authority", "urgency"]),
        Lure(id="lb-2", text="Darling, help me with an investment.", label=1,
             source="ai", typology="pig_butchering", channel="chat", persuasion=["liking"]),
        Lure(id="lb-3", text="Lunch tomorrow?", label=0, source="human",
             typology="benign", channel="email"),
    ]


def test_taxonomy_export_has_identity_and_attack_patterns():
    objs = stix.taxonomy_to_stix()
    types = [o["type"] for o in objs]
    assert types.count("identity") == 1
    # 4 non-benign typologies + 9 persuasion techniques
    assert types.count("attack-pattern") == 4 + 9


def test_bundle_is_well_formed_and_json_serializable():
    bundle = stix.records_to_stix(_records())
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    json.dumps(bundle)  # must be serializable


def test_export_is_deterministic():
    a = stix.records_to_stix(_records())
    b = stix.records_to_stix(_records())
    assert json.dumps(a) == json.dumps(b)


def test_benign_excluded_by_default_included_on_request():
    default = stix.records_to_stix(_records())
    inds = [o for o in default["objects"] if o["type"] == "indicator"]
    assert len(inds) == 2  # benign lb-3 dropped
    with_benign = stix.records_to_stix(_records(), include_benign=True)
    inds2 = [o for o in with_benign["objects"] if o["type"] == "indicator"]
    assert len(inds2) == 3


def test_relationship_refs_all_resolve():
    bundle = stix.records_to_stix(_records())
    ids = {o["id"] for o in bundle["objects"]}
    rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
    assert rels
    for r in rels:
        assert r["source_ref"] in ids
        assert r["target_ref"] in ids


def test_indicators_have_required_stix21_fields():
    bundle = stix.records_to_stix(_records())
    required = {"type", "spec_version", "id", "created", "modified",
                "pattern", "pattern_type", "valid_from"}
    for ind in (o for o in bundle["objects"] if o["type"] == "indicator"):
        assert required <= set(ind)
        assert ind["pattern"].startswith("[artifact:hashes.'SHA-256' = '")


def test_attack_patterns_carry_external_references():
    bundle = stix.records_to_stix(_records())
    aps = [o for o in bundle["objects"] if o["type"] == "attack-pattern"]
    assert aps
    for ap in aps:
        assert ap["external_references"]
        assert any(r["source_name"] == "LureBench" for r in ap["external_references"])


def test_passes_official_stix_validator_if_available():
    import pytest

    pytest.importorskip("stix2validator")
    from stix2validator import ValidationOptions, validate_string

    for bundle in (stix.to_bundle(stix.taxonomy_to_stix()),
                   stix.records_to_stix(_records())):
        results = validate_string(json.dumps(bundle), ValidationOptions())
        assert results.is_valid, [str(e) for e in results.errors]
