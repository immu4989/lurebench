"""Validate the local NIST AI Metrology draft against a supplied official schema."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

PLACEHOLDER = "replace-before-submission@example.invalid"
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DRAFT = (
    ROOT / "docs" / "nist" / "operational-adversarial-robustness-evaluation.yaml"
)


def _strict_json(path: Path) -> Any:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key in {path}: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-standard JSON constant in {path}: {value}")

    return json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=no_duplicates,
        parse_constant=reject_constant,
    )


def validate(draft_path: Path, schema_path: Path, *, allow_placeholder: bool) -> None:
    try:
        from jsonschema import Draft202012Validator, FormatChecker
    except ImportError as exc:
        raise RuntimeError("install the development dependencies: pip install -e '.[dev]'") from exc

    draft = _strict_json(draft_path)
    schema = _strict_json(schema_path)
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(draft)
    if draft.get("contact_email") == PLACEHOLDER and not allow_placeholder:
        raise ValueError(
            "draft is not submission-ready: replace the intentional contact placeholder"
        )
    if not allow_placeholder and str(draft.get("contact_email", "")).endswith(".invalid"):
        raise ValueError("draft is not submission-ready: contact_email uses .invalid")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--draft", type=Path, default=DEFAULT_DRAFT)
    parser.add_argument("--schema", type=Path, required=True)
    parser.add_argument(
        "--allow-placeholder",
        action="store_true",
        help="validate shape while retaining the deliberate non-submittable contact",
    )
    args = parser.parse_args()
    try:
        validate(args.draft, args.schema, allow_placeholder=args.allow_placeholder)
    except (FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        parser.exit(1, f"! {exc}\n")
    print(f"NIST AI Metrology draft validates against {args.schema}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
