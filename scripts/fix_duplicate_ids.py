"""Re-key generated records whose ids collide across generators.

``generate_records`` used to mint ``gen-{typology}-{seq}`` with no generator in the
id, so running one typology across three models produced three different records
all called ``gen-bec-000006``. The generator is fixed; this migrates shards that
were built before the fix.

The new id matches the format ``rewrite_records`` already used:

    gen-bec-000006  (generator glm-4.6)  ->  gen-bec-glm-4.6-000006

Every record keeps its original id under ``meta.legacy_id``, so anything that
referenced the old value can still be resolved.

Two things this deliberately does **not** do. It does not re-split: records stay in
the file they are already in, so no published number moves. And it does not touch
text, labels, or any other field, which the verification below asserts rather than
assumes.

    python scripts/fix_duplicate_ids.py --check          # report only
    python scripts/fix_duplicate_ids.py --write          # migrate in place
"""

from __future__ import annotations

import argparse
import collections
import json
import os
from typing import List, Tuple

SHARDS = [
    "data/full/core/train.jsonl",
    "data/full/core/test.jsonl",
    "data/full/core/hub/train.jsonl",
    "data/full/core/hub/test.jsonl",
    "data/full/multilingual/eval.jsonl",
]


def load(path: str) -> List[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def new_id(rec: dict) -> str:
    """``gen-{typology}-{generator}-{seq}``, preserving the original sequence number.

    Only generated records are touched. Anything else (sourced human records, and
    the ``rw-`` rewrites that already carry a generator) is returned unchanged.
    """
    rid = rec.get("id", "")
    gen = rec.get("generator")
    if not rid.startswith("gen-") or not gen:
        return rid
    if f"-{gen}-" in rid:
        return rid  # already migrated
    prefix, _, seq = rid.rpartition("-")
    if not seq.isdigit():
        return rid
    return f"{prefix}-{gen}-{seq}"


def plan(records: List[dict]) -> List[Tuple[int, str, str]]:
    """Indices whose id changes, as (index, old, new)."""
    out = []
    for i, rec in enumerate(records):
        nid = new_id(rec)
        if nid != rec.get("id"):
            out.append((i, rec["id"], nid))
    return out


def dup_report(records: List[dict]) -> Tuple[int, int]:
    ids = collections.Counter(r.get("id") for r in records)
    dups = {k: v for k, v in ids.items() if v > 1}
    return len(dups), sum(v - 1 for v in dups.values())


def migrate(path: str, write: bool) -> dict:
    records = load(path)
    before_dups, before_extra = dup_report(records)
    changes = plan(records)

    migrated = [dict(r) for r in records]
    for i, old, nid in changes:
        migrated[i]["id"] = nid
        meta = dict(migrated[i].get("meta") or {})
        meta.setdefault("legacy_id", old)
        migrated[i]["meta"] = meta

    after_dups, after_extra = dup_report(migrated)

    # Assertions, not hopes: the migration must be conservative in every respect.
    assert len(migrated) == len(records), "row count changed"
    for before, after in zip(records, migrated, strict=True):
        assert before["text"] == after["text"], "text changed"
        assert before.get("label") == after.get("label"), "label changed"
        assert before.get("source") == after.get("source"), "source changed"
        assert before.get("generator") == after.get("generator"), "generator changed"
        changed = {k for k in set(before) | set(after) if before.get(k) != after.get(k)}
        assert changed <= {"id", "meta"}, f"unexpected field changed: {changed}"

    if write and changes:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            for rec in migrated:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        os.replace(tmp, path)

    return {
        "path": path,
        "rows": len(records),
        "changed": len(changes),
        "dups_before": before_dups,
        "extra_before": before_extra,
        "dups_after": after_dups,
        "extra_after": after_extra,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true", help="report without writing")
    g.add_argument("--write", action="store_true", help="migrate in place")
    ap.add_argument("--shards", nargs="+", default=SHARDS)
    args = ap.parse_args(argv)

    print(f"{'shard':40s} {'rows':>6} {'rekeyed':>8} {'dups→':>10} {'after':>6}")
    failures = 0
    for path in args.shards:
        if not os.path.exists(path):
            print(f"{path:40s}  (missing, skipped)")
            continue
        r = migrate(path, write=args.write)
        print(f"{r['path']:40s} {r['rows']:6d} {r['changed']:8d} "
              f"{r['dups_before']:10d} {r['dups_after']:6d}")
        if r["dups_after"]:
            failures += 1
    if failures:
        print(f"\n{failures} shard(s) still contain duplicate ids")
        return 1
    print("\nall shards have unique ids" if args.write else "\ndry run: nothing written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
