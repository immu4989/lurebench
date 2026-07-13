"""Tests for the fraud-lure taxonomy and its schema consistency."""

from __future__ import annotations

import pytest

from lurebench import taxonomy
from lurebench.schema import CHANNELS, TYPOLOGIES


def test_validate_passes_for_shipped_taxonomy():
    taxonomy.validate()  # must not raise


def test_every_schema_typology_has_a_taxonomy_entry():
    assert set(taxonomy.TYPOLOGY_TAXONOMY) == TYPOLOGIES


def test_every_schema_channel_has_a_taxonomy_entry():
    assert CHANNELS <= set(taxonomy.CHANNEL_TAXONOMY)


def test_validate_catches_drift(monkeypatch):
    # Simulate a schema typology with no taxonomy entry.
    monkeypatch.setattr(taxonomy, "TYPOLOGIES", TYPOLOGIES | {"deepfake_kyc"})
    with pytest.raises(ValueError, match="not taxonomy"):
        taxonomy.validate()


def test_non_benign_typologies_carry_crosswalks():
    for key, entry in taxonomy.TYPOLOGY_TAXONOMY.items():
        if key == "benign":
            continue
        assert entry.crosswalks, f"{key} has no crosswalks"


def test_mitre_crosswalk_urls_are_well_formed():
    for entry in taxonomy.TYPOLOGY_TAXONOMY.values():
        for cw in entry.crosswalks:
            if cw.framework == "MITRE ATT&CK":
                assert cw.url.startswith("https://attack.mitre.org/techniques/T")
                assert cw.ref_id.startswith("T")


def test_persuasion_vocabulary_present():
    for lever in ("authority", "urgency", "liking", "fear", "secrecy"):
        assert lever in taxonomy.PERSUASION_TAXONOMY
