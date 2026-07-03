#!/usr/bin/env python3
"""Build the first real LureBench shard from David-Egea/phishing-texts (MIT).

Human-written phishing vs. benign email text. This shard covers the ``fraud``
task and the **human** side of the ``provenance`` task. AI-generated positives
are added later through LureBench's own controlled-generation protocol, because
cleanly-licensed public AI-generated phishing data is scarce (see
docs/sources.md and docs/SHARD_SPEC.md).

Reproducible: run from the repo root with the package installed (``pip install -e .``).

    python scripts/build_phishtext_shard.py

Outputs to data/full/phishtext/ (gitignored): train.jsonl, test.jsonl, manifest.json.
"""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path

import pandas as pd

from lurebench.corpus import assign_test
from lurebench.ingest import GenericAdapter, dedupe
from lurebench.manifest import build_manifest, check_balance
from lurebench.schema import save_jsonl

DATASET = "David-Egea/phishing-texts"
OUT = Path("data/full/phishtext")
MIN_TOKENS = 5


def parquet_urls() -> list[str]:
    url = f"https://huggingface.co/api/datasets/{DATASET}/parquet/default/train"
    with urllib.request.urlopen(url) as resp:  # noqa: S310 - trusted HF host
        return json.load(resp)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)

    print(f"Downloading {DATASET} (MIT) ...")
    frames = [pd.read_parquet(u) for u in parquet_urls()]
    df = pd.concat(frames, ignore_index=True)
    print(f"  {len(df)} raw rows, columns={list(df.columns)}")

    # Stage a raw JSONL and normalize through the adapter framework so the same
    # defang + schema-validation path is exercised as any other source.
    raw_path = OUT / "_raw.jsonl"
    with open(raw_path, "w", encoding="utf-8") as fh:
        for _, row in df.iterrows():
            fh.write(json.dumps({"text": str(row["text"]), "phishing": int(row["phishing"])}) + "\n")

    adapter = GenericAdapter(
        source_id="phishing-texts-mit",
        text_col="text",
        label_col="phishing",
        label_true={"1"},
        typology_fraud="phishing",
        typology_benign="benign",
        source="human",
        channel="email",
        homepage=f"https://huggingface.co/datasets/{DATASET}",
        license="MIT",
        citation="David-Egea/phishing-texts (Hugging Face Hub), MIT license",
    )

    records = [r for r in adapter.parse(str(raw_path)) if len(r.text.split()) >= MIN_TOKENS]
    before = len(records)
    records = dedupe(records)
    print(f"  {before} valid rows -> {len(records)} after dedup")

    train = [r for r in records if not assign_test(r.id)]
    test = [r for r in records if assign_test(r.id)]
    save_jsonl(train, OUT / "train.jsonl")
    save_jsonl(test, OUT / "test.jsonl")

    manifest = build_manifest(records)
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    raw_path.unlink(missing_ok=True)

    print(f"\nWrote {len(train)} train / {len(test)} test records to {OUT}")
    print(
        f"  fraud={manifest['n_fraud']} benign={manifest['n_benign']} "
        f"fraud_ratio={manifest['fraud_ratio']}"
    )
    for warning in check_balance(manifest):
        print(f"  ! balance: {warning}")


if __name__ == "__main__":
    main()
