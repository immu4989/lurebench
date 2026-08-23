"""Validity tests for leakage-clustered core v2 construction."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from lurebench.corpus_v2 import build_core_v2, cluster_records, write_core_v2
from lurebench.schema import Lure


def _write(path: Path, records: list[Lure]) -> None:
    path.write_text(
        "".join(json.dumps(record.to_dict()) + "\n" for record in records),
        encoding="utf-8",
    )


def _corpus() -> list[Lure]:
    records = []
    for index in range(40):
        benign = index % 2 == 0
        records.append(
            Lure(
                id=f"record-{index:03d}",
                text=(
                    f"Token{index} quarterly project calendar confirms the ordinary "
                    "team planning session next week"
                ),
                label=0 if benign else 1,
                source="human" if index % 3 else "ai",
                typology="benign" if benign else "phishing",
                generator="synthetic-test" if index % 3 == 0 else None,
                language="en",
                channel="email",
                meta={"review": "approved"} if index % 3 == 0 else {},
            )
        )
    records.extend(
        [
            Lure(
                id="near-a",
                text="Please review and approve the attached quarterly wire payment today.",
                label=1,
                source="human",
                typology="bec",
            ),
            Lure(
                id="near-b",
                text="Please review and approve the attached quarterly wire payment today!",
                label=1,
                source="human",
                typology="bec",
            ),
            Lure(
                id="family-a",
                text="An unrelated account notice for the first controlled variant",
                label=1,
                source="ai",
                typology="phishing",
                generator="synthetic-test",
                meta={"review": "approved", "family_id": "scenario-7"},
            ),
            Lure(
                id="family-b",
                text="A substantially rewritten request used as the second controlled variant",
                label=1,
                source="ai",
                typology="phishing",
                generator="synthetic-test",
                meta={"review": "approved", "family_id": "scenario-7"},
            ),
        ]
    )
    return records


def test_cluster_records_binds_near_duplicates_and_declared_families():
    clusters, stats = cluster_records(_corpus())
    owner = {record.id: cluster.id for cluster in clusters for record in cluster.records}

    assert owner["near-a"] == owner["near-b"]
    assert owner["family-a"] == owner["family-b"]
    assert stats["near_duplicate_unions"] >= 1
    assert stats["explicit_family_unions"] >= 1


def test_v2_build_is_deterministic_and_passes_boundary_audit(tmp_path):
    source = tmp_path / "source.jsonl"
    _write(source, _corpus())

    first = build_core_v2([str(source)])
    second = build_core_v2([str(source)])

    assert first.audit.passed
    assert first.n == len(_corpus())
    assert first.cluster_count == len(_corpus()) - 2
    assert {
        split: [record.id for record in records] for split, records in first.splits().items()
    } == {split: [record.id for record in records] for split, records in second.splits().items()}
    for left, right in (("near-a", "near-b"), ("family-a", "family-b")):
        occupied = [
            name
            for name, records in first.splits().items()
            if left in {record.id for record in records}
            or right in {record.id for record in records}
        ]
        assert len(occupied) == 1


def test_contradictory_identical_text_fails_closed(tmp_path):
    source = tmp_path / "contradiction.jsonl"
    records = _corpus()
    records.extend(
        [
            Lure(
                id="same-benign",
                text="identical message",
                label=0,
                source="human",
                typology="benign",
            ),
            Lure(
                id="same-fraud",
                text="identical message",
                label=1,
                source="human",
                typology="phishing",
            ),
        ]
    )
    _write(source, records)

    with pytest.raises(ValueError, match="contradictory"):
        build_core_v2([str(source)])


def test_duplicate_record_id_with_different_content_fails_closed(tmp_path):
    source = tmp_path / "duplicate-id.jsonl"
    records = _corpus()
    records.append(
        Lure(id="record-000", text="different content", label=0, source="human", typology="benign")
    )
    _write(source, records)

    with pytest.raises(ValueError, match="conflicting records"):
        build_core_v2([str(source)])


def test_write_separates_private_heldout_and_validates_manifest(tmp_path):
    source = tmp_path / "source.jsonl"
    _write(source, _corpus())
    build = build_core_v2([str(source)])
    public = tmp_path / "public"
    private = tmp_path / "private" / "heldout.jsonl"

    paths = write_core_v2(build, str(public), str(private))

    assert set(paths) == {"train", "validation", "test", "heldout", "manifest"}
    assert stat.S_IMODE(private.stat().st_mode) == 0o600
    assert not (public / "heldout.jsonl").exists()
    manifest = json.loads((public / "manifest.json").read_text(encoding="utf-8"))
    schema = json.loads(Path("spec/core-v2-build-v1.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(manifest)
    assert manifest["boundary_audit"]["passed"] is True
    assert manifest["splits"]["heldout"]["publication"] == "private_evaluator_only"
    assert str(source) not in json.dumps(manifest)


def test_writer_rejects_heldout_inside_public_directory(tmp_path):
    source = tmp_path / "source.jsonl"
    _write(source, _corpus())
    build = build_core_v2([str(source)])

    with pytest.raises(ValueError, match="outside"):
        write_core_v2(
            build,
            str(tmp_path / "public"),
            str(tmp_path / "public" / "heldout.jsonl"),
        )
