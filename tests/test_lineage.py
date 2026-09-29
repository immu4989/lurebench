"""Explicit lineage graph components and audit integration."""

import random

import pytest

from lurebench.audit import audit_splits
from lurebench.lineage import lineage_components
from lurebench.schema import Lure


def record(identifier, **meta):
    return Lure(id=identifier, text=identifier, label=1, source="human",
                typology="phishing", meta=meta)


def test_rewrite_siblings_and_transitive_parent_annotations_are_connected():
    records = [record("human", family_id="campaign"), record("a", rewrite_of="human"),
               record("b", parent_id="a"), record("other")]
    groups = lineage_components(records)
    assert groups["human"] == groups["a"] == groups["b"]
    assert groups["other"] != groups["human"]
    audit = audit_splits({"train": records[:1], "test": records[1:]})
    assert len(audit.family_overlaps) == 1


def test_cycles_and_conflicting_fields_conservatively_merge():
    records = [record("a", parent_id="b", family_id="X"),
               record("b", parent_id="a", scenario_id="Y"), record("c", seed_id="Y")]
    assert len(set(lineage_components(records).values())) == 1


@pytest.mark.parametrize("value", [False, 0, 1, [], {}, "", "x\ny", "\ud800", "x" * 1025])
def test_populated_bad_annotation_cannot_be_string_coerced(value):
    with pytest.raises(ValueError):
        lineage_components([record("a", rewrite_of=value)])


def test_null_annotation_is_absent_and_duplicate_ids_fail():
    assert lineage_components([record("a", family_id=None)]) == {"a": "a"}
    with pytest.raises(ValueError, match="unique"):
        lineage_components([record("a"), record("a")])
    assert audit_splits({"train": [record("a")], "test": [record("a")]}).family_overlaps
    with pytest.raises(ValueError, match="conflicting"):
        audit_splits({"train": [record("a", seed_id="x")], "test": [record("a", seed_id="y")]})


def test_components_match_independent_graph_traversal_and_are_order_invariant():
    rng = random.Random(4989)
    records = []
    adjacency = {}
    for i in range(100):
        key = f"r{i}"
        refs = {"parent_id": f"r{rng.randrange(150)}", "family_id": f"f{rng.randrange(100)}"}
        records.append(record(key, **refs))
        adjacency.setdefault(key, set())
        for ref in refs.values():
            adjacency.setdefault(ref, set()).add(key)
            adjacency[key].add(ref)
    groups = lineage_components(records)
    for left in records:
        reached, pending = set(), [left.id]
        while pending:
            key = pending.pop()
            if key not in reached:
                reached.add(key)
                pending.extend(adjacency[key] - reached)
        for right in records:
            assert (groups[left.id] == groups[right.id]) == (right.id in reached)
    rng.shuffle(records)
    assert lineage_components(records) == groups


def test_long_lineage_chain_is_iterative_not_recursive():
    records = [record(f"r{i}", parent_id=f"r{i + 1}") for i in range(3000)]
    assert len(set(lineage_components(records).values())) == 1
