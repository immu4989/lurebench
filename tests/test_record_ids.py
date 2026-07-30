"""Record ids must be unique, and the generator must not mint colliding ones.

The bug this guards against: ``generate_records`` minted ``gen-{typology}-{seq}``
with no generator in the id, so running one typology across three models produced
three different records all called ``gen-bec-000006``. Roughly 500 colliding ids
reached the shipped shards and the published Hub dataset before anyone noticed,
because nothing checked.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lurebench.generate import GenerationSpec, TemplateGenerator, generate_records
from lurebench.manifest import build_manifest, check_balance, duplicate_ids
from lurebench.schema import Lure, load_jsonl

ROOT = Path(__file__).resolve().parent.parent
SHIPPED_SHARDS = [
    ROOT / "data" / "full" / "core" / "train.jsonl",
    ROOT / "data" / "full" / "core" / "test.jsonl",
    ROOT / "data" / "full" / "core" / "hub" / "train.jsonl",
    ROOT / "data" / "full" / "core" / "hub" / "test.jsonl",
    ROOT / "data" / "full" / "multilingual" / "eval.jsonl",
    ROOT / "data" / "full" / "phishtext" / "train.jsonl",
    ROOT / "data" / "full" / "phishtext" / "test.jsonl",
    ROOT / "data" / "samples" / "lures.jsonl",
]


def _lure(rid, text="a message", **kw):
    base = dict(label=1, source="ai", typology="bec")
    base.update(kw)
    return Lure(id=rid, text=text, **base)


# --- the generator itself -------------------------------------------------------

def test_generated_id_carries_the_generator():
    spec = GenerationSpec(typology="bec", generator="glm-4.6")
    records = generate_records(TemplateGenerator(), spec, 3)
    assert records, "template generator produced nothing"
    for rec in records:
        assert "glm-4.6" in rec.id, f"generator missing from id: {rec.id}"


def test_two_generators_same_typology_do_not_collide():
    # The exact shape of the original bug: same typology, same start_index,
    # different model. Previously every id matched.
    gen = TemplateGenerator()
    a = generate_records(gen, GenerationSpec(typology="bec", generator="glm-4.6"), 4)
    b = generate_records(gen, GenerationSpec(typology="bec", generator="deepseek-v4-pro"), 4)
    assert a and b
    assert not ({r.id for r in a} & {r.id for r in b})


def test_start_index_still_separates_batches_of_one_generator():
    gen = TemplateGenerator()
    spec = GenerationSpec(typology="phishing", generator="glm-4.6")
    a = generate_records(gen, spec, 2, start_index=0)
    b = generate_records(gen, spec, 2, start_index=100)
    assert not ({r.id for r in a} & {r.id for r in b})


# --- the integrity check --------------------------------------------------------

def test_duplicate_ids_reports_counts():
    recs = [_lure("x"), _lure("x", text="different"), _lure("y")]
    assert duplicate_ids(recs) == {"x": 2}
    assert duplicate_ids([_lure("a"), _lure("b")]) == {}


def test_manifest_counts_unique_ids():
    recs = [_lure("x"), _lure("x", text="two"), _lure("x", text="three"), _lure("y")]
    man = build_manifest(recs)
    assert man["n"] == 4
    assert man["n_unique_ids"] == 2
    assert man["n_duplicate_ids"] == 1


def test_check_balance_warns_about_duplicate_ids():
    man = build_manifest([_lure("x"), _lure("x", text="two")])
    warnings = check_balance(man)
    assert any("duplicate record id" in w for w in warnings)


def test_check_balance_silent_on_clean_ids():
    man = build_manifest([_lure("a"), _lure("b", text="two")])
    assert not any("duplicate record id" in w for w in check_balance(man))


# --- the regression guard on shipped data ---------------------------------------

@pytest.mark.parametrize("shard", SHIPPED_SHARDS, ids=lambda p: p.name and str(p.parent.name) + "/" + p.name)
def test_shipped_shard_has_unique_ids(shard):
    """Every shard present must have unique ids.

    Coverage is uneven and worth being explicit about. ``data/full/`` is
    gitignored - the corpus is distributed through the Hub, not through git - so
    in a fresh CI checkout only ``multilingual/eval.jsonl`` and
    ``samples/lures.jsonl`` exist and the rest of these cases skip. That is still
    a real guard: ``multilingual/eval.jsonl`` was one of the shards that carried
    collisions, so this would have gone red in CI. For the shards CI never sees,
    the protection is the generator tests above, which need no data at all."""
    if not shard.exists():
        pytest.skip(f"{shard} not present (data/full is gitignored; fetched from the Hub)")
    records = load_jsonl(shard)
    dups = duplicate_ids(records)
    assert not dups, (
        f"{shard.name}: {len(dups)} duplicate ids covering "
        f"{sum(v - 1 for v in dups.values())} extra rows, e.g. {list(dups)[:3]}"
    )


def test_split_assignment_is_unambiguous_per_id():
    """The train/test split hashes the record id, so a colliding id forces every
    copy into the same split instead of assigning them independently. Guarding the
    ids is what keeps the split meaningful."""
    from lurebench.corpus import assign_test

    train = ROOT / "data" / "full" / "core" / "train.jsonl"
    test = ROOT / "data" / "full" / "core" / "test.jsonl"
    if not (train.exists() and test.exists()):
        pytest.skip("core shards not present")
    train_ids = {json.loads(line)["id"] for line in train.open(encoding="utf-8") if line.strip()}
    test_ids = {json.loads(line)["id"] for line in test.open(encoding="utf-8") if line.strip()}
    assert not (train_ids & test_ids), "an id appears in both splits"
    # assign_test must be a pure function of the id
    sample = list(test_ids)[:50]
    assert all(assign_test(i) == assign_test(i) for i in sample)
