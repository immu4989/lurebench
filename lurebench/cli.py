"""Command-line interface: ``lurebench eval`` / ``lurebench detectors``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List

from .detectors import available, get_detector
from .harness import Report, run
from .schema import load_jsonl


def _cmd_detectors(_: argparse.Namespace) -> int:
    print("Registered detectors:")
    for name in available():
        print(f"  - {name}")
    return 0


def _cmd_eval(args: argparse.Namespace) -> int:
    dataset = load_jsonl(args.dataset)
    names: List[str] = args.detector or ["heuristic-v0"]

    reports: List[Report] = []
    for name in names:
        try:
            detector = get_detector(name)
        except (ImportError, RuntimeError, KeyError) as exc:
            print(f"! skipping {name}: {exc}", file=sys.stderr)
            continue
        reports.append(run(detector, dataset, threshold=args.threshold, task=args.task))

    if not reports:
        print("No detector could be run.", file=sys.stderr)
        return 1

    if args.json:
        payload = [
            {
                "detector": r.detector,
                "task": r.task,
                "threshold": r.threshold,
                "n_skipped": r.n_skipped,
                "metrics": r.metrics.as_dict(),
            }
            for r in reports
        ]
        print(json.dumps(payload, indent=2))
    else:
        print(f"\nLureBench eval — {len(dataset)} records — {args.dataset}\n")
        for r in reports:
            print("  " + r.summary_line())
        print()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lurebench", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_eval = sub.add_parser("eval", help="run detectors over a dataset")
    p_eval.add_argument("--dataset", "-d", required=True, help="path to a JSONL dataset")
    p_eval.add_argument(
        "--detector",
        "-m",
        action="append",
        help="detector name (repeatable); default: heuristic-v0",
    )
    p_eval.add_argument("--task", "-t", choices=["fraud", "provenance"], default=None)
    p_eval.add_argument("--threshold", type=float, default=0.5)
    p_eval.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    p_eval.set_defaults(func=_cmd_eval)

    p_det = sub.add_parser("detectors", help="list registered detectors")
    p_det.set_defaults(func=_cmd_detectors)

    return parser


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
