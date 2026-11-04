from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).parents[1]
LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")


def _documents(root):
    # Enumerate first-party inputs, not backend staging trees or local experiments.
    yield from root.glob("*.md")
    for folder in ("docs", "blog", "examples", ".github", "tests", "conformance", "space",
                   "lurebench", "lurescope", "data/samples", "scripts"):
        yield from (root / folder).rglob("*.md")


def test_documentation_discovery_excludes_build_and_scratch_trees(tmp_path):
    for name in ("README.md", "docs/guide.md", "package-0.0.0/README.md",
                 "scratch/README.md"):
        document = tmp_path / name
        document.parent.mkdir(parents=True, exist_ok=True)
        document.write_text("# synthetic\n")
    assert {p.relative_to(tmp_path).as_posix() for p in _documents(tmp_path)} == {
        "README.md", "docs/guide.md",
    }


def test_markdown_relative_links_resolve():
    broken = []
    for document in _documents(ROOT):
        relative = document.relative_to(ROOT)
        if {"build", "dist"} & set(relative.parts) or any(
            part.startswith(".") and part != ".github" for part in relative.parts
        ):
            continue
        for raw_target in LINK.findall(document.read_text(encoding="utf-8")):
            target = raw_target.strip().split()[0].strip("<>")
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            path = target.split("#", 1)[0]
            if path and not (document.parent / path).resolve().exists():
                broken.append(f"{relative}: {target}")
    assert not broken, "broken relative Markdown links:\n" + "\n".join(broken)
