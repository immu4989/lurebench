"""Check that authority code, schemas, and reference evidence survive wheel packaging."""

from __future__ import annotations

import argparse
from pathlib import Path
from zipfile import BadZipFile, ZipFile


def verify(wheel: Path, root: Path, package: str) -> int:
    sources = list((root / package).glob("*.py"))
    sources.extend((root / "spec").glob("luremandate*.schema.json"))
    for directory in (root / "conformance").glob("luremandate*-v1"):
        sources.extend(
            path
            for path in directory.rglob("*")
            if path.is_file() and path.suffix in {".json", ".pem"}
        )
    if not sources:
        raise ValueError("no authority sources found")
    with ZipFile(wheel) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError("wheel has duplicate archive paths")
        for source in sources:
            relative = source.relative_to(root).as_posix()
            if relative.startswith(f"{package}/"):
                candidates = [relative] if relative in names else []
            elif package == "lurebench":
                destination = (
                    f"lurebench/{relative}"
                    if relative.startswith("spec/")
                    else relative.replace("conformance/", "lurebench/conformance_data/", 1)
                )
                candidates = [destination] if destination in names else []
            else:
                suffix = f".data/data/share/lurescope/{relative}"
                candidates = [name for name in names if name.endswith(suffix)]
            if len(candidates) != 1:
                raise ValueError(f"wheel is missing or duplicates source: {relative}")
            if archive.read(candidates[0]) != source.read_bytes():
                raise ValueError(f"wheel contains stale source bytes: {relative}")
    return len(sources)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path)
    parser.add_argument("--package", required=True, choices=("lurebench", "lurescope"))
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args(argv)
    try:
        count = verify(args.wheel, args.root, args.package)
    except (OSError, ValueError, BadZipFile) as exc:
        parser.exit(1, f"wheel authority contract failed: {exc}\n")
    print(f"verified {count} exact source files in {args.wheel.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
