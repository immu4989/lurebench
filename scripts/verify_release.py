"""Fail closed when a release tag and public version metadata disagree."""

from __future__ import annotations

import argparse
import ast
import re
from pathlib import Path


def _package_version(path: Path) -> str:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__version__":
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        return node.value.value
    raise ValueError(f"{path} does not define a literal __version__")


def verify(tag: str, root: Path) -> str:
    if not re.fullmatch(r"v\d+\.\d+\.\d+", tag):
        raise ValueError("release tag must use vMAJOR.MINOR.PATCH")
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
    project = pyproject.split("[project]", 1)[1].split("\n[", 1)[0]
    name_match = re.search(r'(?m)^name\s*=\s*"([^"]+)"\s*$', project)
    version_match = re.search(r'(?m)^version\s*=\s*"([^"]+)"\s*$', project)
    if name_match is None or version_match is None:
        raise ValueError("pyproject.toml project name/version must be literal strings")
    name, version = name_match.group(1), version_match.group(1)
    expected = f"v{version}"
    if tag != expected:
        raise ValueError(f"tag {tag!r} does not match project version {version!r}")
    package_version = _package_version(root / name / "__init__.py")
    if package_version != version:
        raise ValueError(f"package version {package_version!r} does not match {version!r}")
    citation = (root / "CITATION.cff").read_text(encoding="utf-8")
    if not re.search(rf"(?m)^version:\s*[\"']?{re.escape(version)}[\"']?\s*$", citation):
        raise ValueError("CITATION.cff version does not match the project")
    readme = (root / "README.md").read_text(encoding="utf-8")
    if f"version-{version}-" not in readme:
        raise ValueError("README version badge does not match the project")
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    if not re.search(rf"(?m)^## {re.escape(version)}(?:\s|$)", changelog):
        raise ValueError("CHANGELOG has no heading for the release version")
    return version


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("tag")
    parser.add_argument("--root", type=Path, default=Path(__file__).parents[1])
    args = parser.parse_args()
    version = verify(args.tag, args.root.resolve())
    print(f"verified release metadata for {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
