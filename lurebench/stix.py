"""Export LureBench records and taxonomy as STIX 2.1 — the interoperability format.

STIX 2.1 is the OASIS standard that fusion centers, ISACs, and threat-intel platforms
already speak. This module turns the LureBench taxonomy into STIX ``attack-pattern``
objects (each carrying the FinCEN/IC3/MITRE crosswalks as ``external_references``) and
turns each lure into an ``indicator`` linked to the patterns it exhibits, all wrapped in
a STIX ``bundle`` that another tool can ingest directly.

Design choices worth knowing:

- **Deterministic IDs.** STIX object IDs are UUIDv5 (name-based) over a fixed namespace,
  so the same input always produces byte-identical output — diffable, testable, no
  randomness.
- **Fixed timestamps.** ``created``/``modified`` default to a constant so exports are
  reproducible; pass ``timestamp`` to override.
- **Indicator patterns** use the STIX ``artifact:hashes`` form over the SHA-256 of the
  (defanged) lure text — a valid STIX pattern that references content without shipping it.
- Pure standard library: no ``stix2`` dependency, just ``json``, ``uuid``, ``hashlib``.
"""

from __future__ import annotations

import hashlib
import uuid
from typing import Dict, Iterable, List, Optional

from . import taxonomy
from .schema import Lure

STIX_VERSION = "2.1"
DEFAULT_TIMESTAMP = "2025-01-01T00:00:00.000Z"

# Fixed namespace so name-based UUIDs are stable across runs and machines.
_NS = uuid.UUID("6b3f7e2a-1c4d-5e6f-8a9b-0c1d2e3f4a5b")


def _id(stix_type: str, name: str) -> str:
    return f"{stix_type}--{uuid.uuid5(_NS, f'{stix_type}:{name}')}"


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _external_refs(crosswalks) -> List[dict]:
    refs = []
    for cw in crosswalks:
        ref = {"source_name": cw.framework, "description": cw.name}
        if cw.ref_id:
            ref["external_id"] = cw.ref_id
        if cw.url:
            ref["url"] = cw.url
        refs.append(ref)
    return refs


def _base(stix_type: str, name_key: str, ts: str, identity_id: str) -> dict:
    return {
        "type": stix_type,
        "spec_version": STIX_VERSION,
        "id": _id(stix_type, name_key),
        "created_by_ref": identity_id,
        "created": ts,
        "modified": ts,
    }


def _identity(ts: str) -> dict:
    return {
        "type": "identity",
        "spec_version": STIX_VERSION,
        "id": _id("identity", "LureBench"),
        "created": ts,
        "modified": ts,
        "name": "LureBench",
        "identity_class": "system",
        "description": (
            "Benchmark and taxonomy for AI-generated fraud lures. "
            + taxonomy.DISCLAIMER
        ),
    }


def _attack_pattern(entry: taxonomy.TaxonomyEntry, axis: str, ts: str, identity_id: str) -> dict:
    obj = _base("attack-pattern", f"{axis}:{entry.key}", ts, identity_id)
    obj["name"] = f"{entry.label}"
    obj["description"] = entry.description
    refs = _external_refs(entry.crosswalks)
    refs.append({"source_name": "LureBench", "external_id": f"{axis}:{entry.key}",
                 "description": f"LureBench {axis} taxonomy v{taxonomy.TAXONOMY_VERSION}"})
    obj["external_references"] = refs
    return obj


def taxonomy_to_stix(timestamp: str = DEFAULT_TIMESTAMP) -> List[dict]:
    """The taxonomy itself as STIX: an identity plus one attack-pattern per fraud
    typology and per persuasion technique, each carrying its framework crosswalks."""
    taxonomy.validate()
    identity = _identity(timestamp)
    idid = identity["id"]
    objects = [identity]
    for key, entry in taxonomy.TYPOLOGY_TAXONOMY.items():
        if key == "benign":
            continue
        objects.append(_attack_pattern(entry, "typology", timestamp, idid))
    for entry in taxonomy.PERSUASION_TAXONOMY.values():
        objects.append(_attack_pattern(entry, "persuasion", timestamp, idid))
    return objects


def _indicator(record: Lure, ts: str, identity_id: str) -> dict:
    obj = _base("indicator", f"lure:{record.id}", ts, identity_id)
    tax = taxonomy.TYPOLOGY_TAXONOMY.get(record.typology)
    label = tax.label if tax else record.typology
    obj["name"] = f"AI-fraud lure {record.id} ({label})"
    obj["description"] = (
        f"typology={record.typology}; channel={record.channel}; source={record.source}"
        + (f"; generator={record.generator}" if record.generator else "")
        + (f"; persuasion={','.join(record.persuasion)}" if record.persuasion else "")
    )
    obj["indicator_types"] = ["malicious-activity"] if record.label == 1 else ["benign"]
    obj["pattern"] = f"[artifact:hashes.'SHA-256' = '{_sha256(record.text)}']"
    obj["pattern_type"] = "stix"
    obj["valid_from"] = ts
    obj["labels"] = [f"typology:{record.typology}", f"channel:{record.channel}",
                     f"source:{record.source}"]
    return obj


def _relationship(src: str, rel: str, tgt: str, ts: str, identity_id: str) -> dict:
    obj = _base("relationship", f"{src}|{rel}|{tgt}", ts, identity_id)
    obj["relationship_type"] = rel
    obj["source_ref"] = src
    obj["target_ref"] = tgt
    return obj


def to_bundle(objects: List[dict]) -> dict:
    # Bundle id is content-addressed so identical object sets share an id.
    key = ",".join(o["id"] for o in objects)
    return {"type": "bundle", "id": _id("bundle", key), "objects": objects}


def records_to_stix(
    records: Iterable[Lure],
    timestamp: str = DEFAULT_TIMESTAMP,
    include_benign: bool = False,
) -> dict:
    """A full STIX 2.1 bundle: identity, the referenced taxonomy attack-patterns, one
    indicator per lure, and relationships linking each indicator to its patterns."""
    taxonomy.validate()
    identity = _identity(timestamp)
    idid = identity["id"]
    objects: List[dict] = [identity]

    ap_index: Dict[str, dict] = {}   # axis:key -> attack-pattern object (deduped)

    def ensure_ap(axis: str, key: str) -> Optional[str]:
        table = (taxonomy.TYPOLOGY_TAXONOMY if axis == "typology"
                 else taxonomy.PERSUASION_TAXONOMY)
        entry = table.get(key)
        if entry is None or key == "benign":
            return None
        cache_key = f"{axis}:{key}"
        if cache_key not in ap_index:
            ap = _attack_pattern(entry, axis, timestamp, idid)
            ap_index[cache_key] = ap
            objects.append(ap)
        return ap_index[cache_key]["id"]

    indicators: List[dict] = []
    relationships: List[dict] = []
    for record in records:
        if record.typology == "benign" and not include_benign:
            continue
        ind = _indicator(record, timestamp, idid)
        indicators.append(ind)
        typ_ap = ensure_ap("typology", record.typology)
        if typ_ap:
            relationships.append(_relationship(ind["id"], "indicates", typ_ap, timestamp, idid))
        for p in record.persuasion:
            p_ap = ensure_ap("persuasion", p)
            if p_ap:
                relationships.append(
                    _relationship(ind["id"], "related-to", p_ap, timestamp, idid))

    objects.extend(indicators)
    objects.extend(relationships)
    return to_bundle(objects)
