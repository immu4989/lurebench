"""Exercise a locally installed wheel outside the repository, without services.

Dependencies come from the calling interpreter; the package under test must
come entirely from --installed-root. LureScope runs with producer imports
forbidden. Install a trusted local wheel with --no-deps before invoking this.
"""

from __future__ import annotations

import argparse
import contextlib
import importlib
import importlib.abc
import importlib.metadata
import io
import json
import sys
from pathlib import Path


class ForbidProducerImports(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "lurebench" or fullname.startswith("lurebench."):
            raise ImportError("producer import forbidden in installed consumer audit")
        return None


def check_installation(package: str, installed_root: Path) -> dict:
    root = installed_root.resolve(strict=True)
    checkout = Path(__file__).resolve().parents[1]
    if Path.cwd().resolve().is_relative_to(checkout):
        raise ValueError("run this check outside the source checkout")
    if not (root / package / "__init__.py").is_file():
        raise ValueError("installed package initializer is missing")
    prefixes = (package, "lurebench") if package == "lurescope" else (package,)
    if any(
        name == prefix or name.startswith(prefix + ".")
        for name in sys.modules
        for prefix in prefixes
    ):
        raise ValueError("run this check in a fresh interpreter")
    original_path = sys.path[:]
    guard = ForbidProducerImports() if package == "lurescope" else None
    sys.path.insert(0, str(root))
    if guard is not None:
        sys.meta_path.insert(0, guard)
    try:
        distribution = importlib.metadata.distribution(package)
        metadata_files = [
            item for item in distribution.files or ()
            if str(item).endswith(".dist-info/METADATA")
        ]
        if len(metadata_files) != 1 or not Path(
            distribution.locate_file(metadata_files[0])
        ).resolve().is_relative_to(root):
            raise ValueError("package metadata did not resolve inside the installation")
        cli = importlib.import_module(f"{package}.cli")
        output = io.StringIO()
        arguments = (
            ["mandate", "selftest", "--json"]
            if package == "lurescope"
            else ["mandate-selftest", "--json"]
        )
        with contextlib.redirect_stdout(output):
            status = cli.main(arguments)
        if status != 0:
            raise ValueError("installed CLI self-test failed")
        result = json.loads(output.getvalue())
        expected_profiles = 10 if package == "lurescope" else 7
        if any(
            type(result["summary"][field]) is not int for field in ("passed", "total")
        ) or result["summary"] != {
            "status": "pass", "passed": expected_profiles, "total": expected_profiles
        } or len(result["results"]) != expected_profiles:
            raise ValueError("installed reference verification is incomplete or failed")
        if (
            result.get("reference_only") is not True
            or result.get("kind") != f"{package}-mandate-reference-selftest"
            or result.get("package_version") != distribution.version
        ):
            raise ValueError("installed diagnostic identity or reference boundary is invalid")
        probes = {"boolean-version", "float-version", "unknown-field", "derived-claim"}
        for item in result["results"]:
            observed = item.get("rejection_probes", {})
            if (
                item.get("status") != "pass"
                or set(observed) != probes
                or any(value is not True for value in observed.values())
            ):
                raise ValueError("installed tamper-rejection coverage is incomplete or failed")
        for name, module in list(sys.modules.items()):
            if name == package or name.startswith(package + "."):
                location = getattr(module, "__file__", None)
                if location is None or not Path(location).resolve().is_relative_to(root):
                    raise ValueError(f"package module escaped installed root: {name}")
        if guard is not None and any(
            name == "lurebench" or name.startswith("lurebench.") for name in sys.modules
        ):
            raise ValueError("producer module was imported during consumer check")
        return result
    finally:
        sys.path[:] = original_path
        if guard is not None:
            sys.meta_path.remove(guard)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", required=True, choices=("lurebench", "lurescope"))
    parser.add_argument("--installed-root", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = check_installation(args.package, args.installed_root)
    except (OSError, ValueError, ImportError, KeyError, TypeError) as exc:
        parser.exit(1, f"installed authority check failed: {exc}\n")
    print(
        f"{args.package}: {result['summary']['passed']}/{result['summary']['total']} "
        "installed profiles passed, including rejection probes"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
