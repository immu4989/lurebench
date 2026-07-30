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


# A bundle taken verbatim from the STIX 2.1 specification. Used to check that the
# validator itself works before its verdict on our output is trusted.
_SPEC_EXAMPLE = {
    "type": "bundle",
    "id": "bundle--44af6c39-c09b-49c5-9de2-394224b04982",
    "objects": [{
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        "created": "2016-04-06T20:03:48.000Z",
        "modified": "2016-04-06T20:03:48.000Z",
        "name": "Poison Ivy Malware",
        "pattern": ("[file:hashes.'SHA-256' = 'aec070645fe53ee3b3763059376134f058"
                    "cc337247c978add178b6ccdfb0019f']"),
        "pattern_type": "stix",
        "valid_from": "2016-01-01T00:00:00Z",
        "indicator_types": ["malicious-activity"],
    }],
}


def test_passes_official_stix_validator_if_available():
    import pytest

    pytest.importorskip("stix2validator")
    from stix2validator import ValidationOptions, validate_string

    # "Available" has to mean "usable", not merely "importable". stix2-validator
    # loads its JSON schemas from a git submodule that is not included in the
    # published wheel, so a pip-installed copy reports every bundle invalid with
    # "Cannot locate a schema for the object's type" - including the example above,
    # copied straight out of the specification. Asserting against a validator in
    # that state tests nothing and fails CI on correct output, so the tool is
    # checked against known-good input first and the test skips if it disagrees.
    probe = validate_string(json.dumps(_SPEC_EXAMPLE), ValidationOptions())
    if not probe.is_valid:
        pytest.skip(
            "stix2validator cannot validate the STIX 2.1 spec example itself "
            f"({[str(e) for e in probe.errors][:1]}); its schemas are missing"
        )

    for bundle in (stix.to_bundle(stix.taxonomy_to_stix()),
                   stix.records_to_stix(_records())):
        results = validate_string(json.dumps(bundle), ValidationOptions())
        assert results.is_valid, [str(e) for e in results.errors]
