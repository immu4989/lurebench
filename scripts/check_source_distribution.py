"""Check reproduction inputs in a trusted local source archive, without extraction.

This compares bytes to the checkout, not publisher identity. The format and size
checks are not a sandbox for arbitrary untrusted compressed archives.
"""

from __future__ import annotations

import argparse
import tarfile
import tomllib
from pathlib import Path

MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MAX_MEMBERS = 10000
TOP_LEVEL = (
    "pyproject.toml", "uv.lock", "README.md", "LICENSE", "CHANGELOG.md",
    "CONTRIBUTING.md", "CITATION.cff", "CODE_OF_CONDUCT.md", "SECURITY.md",
)
SUFFIXES = {
    ".py", ".pyi", ".json", ".jsonl", ".md", ".cjs", ".js", ".html", ".css",
    ".txt", ".yml", ".yaml", ".pem", ".svg", ".gif", ".png", ".pdf",
    ".joblib", ".xml", ".webmanifest", ".rego", ".cedar", ".toml",
}
BASENAMES = {"Dockerfile", ".dockerignore", "CODEOWNERS"}
TRANSIENT = {".git", ".venv", "__pycache__", ".pytest_cache", ".ruff_cache", "build", "dist"}


def required_sources(root: Path, package: str) -> dict[str, Path]:
    if package not in {"lurebench", "lurescope"}:
        raise ValueError("unknown source package")
    sources = {name: root / name for name in TOP_LEVEL}
    sources.update((p.name, p) for p in root.glob("*.md"))
    for name in ("Dockerfile", "Dockerfile.space-ci", "compose.yaml", ".dockerignore"):
        if (root / name).exists():
            sources[name] = root / name
    directories = [package, "tests", "scripts", "spec", "conformance",
                   "docs", "blog", "examples", ".github"]
    if package == "lurescope":
        sources["MANIFEST.in"] = root / "MANIFEST.in"
        directories.append("space")
    else:
        directories.append("data/samples")
    for name in directories:
        directory = root / name
        if directory.is_symlink():
            raise ValueError(f"source directory is a symlink: {name}")
        for item in directory.rglob("*"):
            relative = item.relative_to(root)
            if set(relative.parts) & TRANSIENT:
                continue
            if item.is_symlink():
                raise ValueError(f"source input is a symlink: {relative}")
            if item.is_dir():
                continue
            if item.suffix in SUFFIXES or item.name in BASENAMES:
                sources[relative.as_posix()] = item
    for required in (f"{package}/", "tests/", "scripts/"):
        if not any(name.startswith(required) and name.endswith(".py") for name in sources):
            raise ValueError(f"source tree lacks reproduction inputs: {required}")
    for name, item in sources.items():
        if item.is_symlink() or not item.is_file():
            raise ValueError(f"source input is missing or nonregular: {name}")
        if item.stat().st_size > MAX_MEMBER_BYTES:
            raise ValueError(f"source input exceeds byte limit: {name}")
    return sources


def _member_name(member: tarfile.TarInfo) -> tuple[str, ...]:
    name = member.name
    if member.isdir() and name.endswith("/"):
        name = name[:-1]
    parts = tuple(name.split("/"))
    if (not name or len(name) > 1024 or "\\" in name
            or any(part in {"", ".", ".."} for part in parts) or ":" in parts[0]):
        raise ValueError("source archive has a noncanonical member path")
    if (set(parts) & TRANSIENT or parts[-1].endswith((".pyc", ".pyo"))
            or parts[-1] in {".env", ".netrc", ".pypirc"}
            or (parts[-1].startswith(".env.") and parts[-1] != ".env.example")):
        raise ValueError("source archive contains a transient or credential filename")
    return parts


def verify(path: Path, root: Path, package: str) -> int:
    sources = required_sources(root, package)
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    if project["name"] != package:
        raise ValueError("source project name does not match the requested package")
    prefix = f'{package}-{project["version"]}'
    if path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError("compressed source archive exceeds byte limit")
    seen, matched = set(), set()
    total = 0
    with tarfile.open(path, "r:gz") as archive:
        for index, member in enumerate(archive):
            if index >= MAX_MEMBERS:
                raise ValueError("source archive exceeds member limit")
            parts = _member_name(member)
            if parts[0] != prefix:
                raise ValueError("source archive has the wrong package/version root")
            if parts in seen:
                raise ValueError("duplicate source archive member")
            seen.add(parts)
            if (member.size < 0 or member.size > MAX_MEMBER_BYTES
                    or total + member.size > MAX_TOTAL_BYTES):
                raise ValueError("source archive exceeds expanded byte limits")
            total += member.size
            if member.isdir():
                if member.size:
                    raise ValueError("source archive directory carries payload")
                continue
            if member.type not in {tarfile.REGTYPE, tarfile.AREGTYPE} or member.sparse:
                raise ValueError("source archive contains a nonregular or sparse member")
            if len(parts) == 1:
                raise ValueError("source archive root must be a directory")
            relative = "/".join(parts[1:])
            if relative in sources:
                source = sources[relative]
                if member.size != source.stat().st_size:
                    raise ValueError(f"stale source archive bytes: {relative}")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError(f"unreadable source archive member: {relative}")
                with stream:
                    actual = stream.read(MAX_MEMBER_BYTES + 1)
                if actual != source.read_bytes():
                    raise ValueError(f"stale source archive bytes: {relative}")
                matched.add(relative)
    missing = set(sources) - matched
    if missing:
        raise ValueError(f"source archive missing reproduction input: {sorted(missing)[0]}")
    return len(matched)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--package", required=True, choices=("lurebench", "lurescope"))
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args(argv)
    try:
        count = verify(args.archive, args.root, args.package)
    except (OSError, ValueError, KeyError, EOFError, tarfile.TarError) as exc:
        parser.exit(1, f"source reproduction contract failed: {exc}\n")
    print(f"verified {count} exact reproduction inputs in {args.archive.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
