"""Tests for multi-class corpus assembly."""

from __future__ import annotations

import json

from lurebench.corpus import assign_test, build_core, gate, write_core
from lurebench.schema import Lure


def _write(path, records):
    with open(path, "w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r.to_dict()) + "\n")


def test_gate_keeps_sourced_and_approved_drops_the_rest():
    recs = [
        Lure(id="s1", text="sourced human phishing at <<link>>", label=1, source="human", typology="phishing"),
        Lure(id="g1", text="approved ai bec, send the account", label=1, source="ai", typology="bec",
             meta={"review": "approved"}),
        Lure(id="g2", text="pending ai romance at <<contact>>", label=1, source="ai", typology="romance",
             meta={"review": "pending"}),
        Lure(id="g3", text="flagged ai lure http://x", label=1, source="ai", typology="phishing",
             meta={"review": "flagged"}),
    ]
    kept, pending, flagged = gate(recs)
    assert {r.id for r in kept} == {"s1", "g1"}
    assert pending == 1 and flagged == 1


def test_build_core_merges_gates_and_splits(tmp_path):
    sourced = [
        Lure(id=f"src-{i:04d}", text=f"human phishing number {i} confirm at <<link>>",
             label=1, source="human", typology="phishing", meta={"source_id": "phishtext"})
        for i in range(40)
    ]
    benign = [
        Lure(id=f"ben-{i:04d}", text=f"benign note number {i} see you at noon",
             label=0, source="human", typology="benign", meta={"source_id": "phishtext"})
        for i in range(40)
    ]
    generated = [
        Lure(id="gen-bec-000001", text="approved bec, wire to the account on file", label=1,
             source="ai", typology="bec", generator="deepseek-v4-pro",
             meta={"source_id": "controlled-generation", "review": "approved"}),
        Lure(id="gen-bec-000002", text="pending bec, not approved yet", label=1,
             source="ai", typology="bec", generator="deepseek-v4-pro",
             meta={"source_id": "controlled-generation", "review": "pending"}),
    ]
    p1, p2, p3 = tmp_path / "src.jsonl", tmp_path / "ben.jsonl", tmp_path / "gen.jsonl"
    _write(p1, sourced)
    _write(p2, benign)
    _write(p3, generated)

    build = build_core([str(p1), str(p2), str(p3)])
    # 80 sourced + 1 approved generated; the pending generated one is dropped.
    assert build.n == 81
    assert build.dropped_pending == 1
    assert build.per_source["controlled-generation"] == 1
    assert build.per_source["phishtext"] == 80
    # Both splits present, no overlap.
    train_ids = {r.id for r in build.train}
    test_ids = {r.id for r in build.test}
    assert train_ids and test_ids
    assert train_ids.isdisjoint(test_ids)


def test_split_is_frozen_by_id():
    # The same id always lands in the same split regardless of surrounding data.
    ids = [f"phishing-texts-mit-{i:05d}" for i in range(200)]
    first = {i: assign_test(i) for i in ids}
    second = {i: assign_test(i) for i in ids}
    assert first == second
    # Roughly 10% in test (loose bound on 200 ids).
    n_test = sum(first.values())
    assert 5 <= n_test <= 35


def test_write_core_emits_both_splits(tmp_path):
    recs = [Lure(id=f"x-{i}", text=f"lure {i} at <<link>>", label=1, source="ai",
                 typology="phishing", meta={"review": "approved"}) for i in range(20)]
    p = tmp_path / "in.jsonl"
    _write(p, recs)
    build = build_core([str(p)])
    paths = write_core(build, str(tmp_path / "core"))
    assert (tmp_path / "core" / "train.jsonl").exists()
    assert (tmp_path / "core" / "test.jsonl").exists()
    assert set(paths) == {"train", "test"}
