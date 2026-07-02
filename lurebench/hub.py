"""Hugging Face Hub publishing.

Assembles a Hub-ready dataset directory (shards + dataset card + manifest) and,
optionally, pushes it. The ``huggingface_hub`` dependency is lazy so the core
package stays dependency-free.

    pip install "lurebench[hub]"
    huggingface-cli login          # or set HF_TOKEN
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Optional, Sequence

from .manifest import build_manifest, check_balance
from .schema import Lure, load_jsonl


def build_dataset_card(repo_id: str, manifest: dict, version: str) -> str:
    typ = manifest.get("by_typology", {})
    gen = manifest.get("by_generator", {})
    return f"""---
license: apache-2.0
task_categories:
  - text-classification
tags:
  - fraud-detection
  - phishing
  - ai-generated-text
  - ai-security
pretty_name: LureBench Core
---

# {repo_id}

Benchmark shards for **LureBench** — detecting AI-generated fraud lures
(phishing, BEC, romance / pig-butchering). Version `{version}`.

Each record follows the LureBench schema (see the
[code repository](https://github.com/immu4989/lurebench)): `text`, `label`
(fraud vs. benign), `source` (ai vs. human), `typology`, `generator`,
`language`, `channel`, `persuasion`.

## Composition

- Records: **{manifest.get('n', 0)}**  ·  fraud ratio: **{manifest.get('fraud_ratio', 0)}**  ·  AI ratio: **{manifest.get('ai_ratio', 0)}**
- Typologies: {', '.join(f'{k}={v}' for k, v in typ.items()) or 'n/a'}
- Generators: {', '.join(f'{k}={v}' for k, v in gen.items()) or 'n/a'}

See the full manifest in `manifest.json`, and the datasheet and source licenses
in the code repository (`docs/DATASHEET.md`, `docs/sources.md`).

## Responsible use

Defensive research only. Fraud text is defanged. Do not use to generate,
personalize, or deliver fraud. See `DATA.md` in the code repository.
"""


def assemble(
    shards: dict[str, str],
    out_dir: str,
    repo_id: str,
    version: str = "v1",
) -> dict:
    """Build a Hub-ready directory from ``{split: jsonl_path}`` without pushing.

    Returns the combined manifest.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    all_records: list[Lure] = []
    for split, path in shards.items():
        records = load_jsonl(path)
        all_records.extend(records)
        shutil.copyfile(path, out / f"{split}.jsonl")

    manifest = build_manifest(all_records)
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (out / "README.md").write_text(build_dataset_card(repo_id, manifest, version), encoding="utf-8")

    warnings = check_balance(manifest)
    if warnings:
        (out / "BALANCE_WARNINGS.txt").write_text("\n".join(warnings), encoding="utf-8")
    return {"manifest": manifest, "warnings": warnings, "out_dir": str(out)}


def push(out_dir: str, repo_id: str, private: bool = True, token: Optional[str] = None) -> str:
    """Upload an assembled directory to the Hub as a dataset repo."""
    try:
        from huggingface_hub import HfApi  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise ImportError("push requires the 'hub' extra: pip install 'lurebench[hub]'") from exc

    token = token or os.environ.get("HF_TOKEN")
    api = HfApi(token=token)
    api.create_repo(repo_id=repo_id, repo_type="dataset", private=private, exist_ok=True)
    api.upload_folder(repo_id=repo_id, repo_type="dataset", folder_path=out_dir)
    return f"https://huggingface.co/datasets/{repo_id}"
