from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).parents[1]
LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")


def test_markdown_relative_links_resolve():
    broken = []
    for document in ROOT.rglob("*.md"):
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
