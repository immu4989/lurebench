"""Command-line interface: ``lurebench eval`` / ``lurebench detectors``."""

from __future__ import annotations

import argparse
import json
import sys
from typing import List

from .detectors import available, get_detector
from .harness import Report, run
from .ingest import available as ingest_available
from .generate import GenerationSpec, generate_records, screen
from .generate import available as gen_available
from .generate import get_generator
from .corpus import build_core, write_core
from .crossgen import cross_generator_provenance
from .crossgen import render_markdown as render_crossgen
from .hub import assemble, push
from .ingest import dedupe, get_adapter
from .leaderboard import evaluate_detectors, render_markdown, write_json
from .manifest import build_manifest, check_balance
from .schema import load_jsonl, save_jsonl


def _cmd_detectors(_: argparse.Namespace) -> int:
    print("Registered detectors:")
    for name in available():
        print(f"  - {name}")
    return 0


def _cmd_ingest(args: argparse.Namespace) -> int:
    kwargs = {}
    if args.generator:
        kwargs["generator"] = args.generator
    try:
        adapter = get_adapter(args.adapter, **kwargs)
    except (KeyError, TypeError) as exc:
        print(f"! {exc}", file=sys.stderr)
        print(f"  available adapters: {ingest_available()}", file=sys.stderr)
        return 1

    records = list(adapter.parse(args.input))
    if args.dedupe:
        before = len(records)
        records = dedupe(records)
        print(f"deduped {before} -> {len(records)} records", file=sys.stderr)

    save_jsonl(records, args.out)
    print(f"wrote {len(records)} records to {args.out} (source={adapter.source_id})")
    return 0


def _cmd_train(args: argparse.Namespace) -> int:
    from .detectors.tfidf import TfidfLogisticDetector

    records = load_jsonl(args.dataset)
    try:
        detector = TfidfLogisticDetector.train(records, task=args.task)
    except ImportError as exc:
        print(f"! {exc}", file=sys.stderr)
        return 1
    detector.save(args.out)
    n_pos = sum(1 for r in records if (r.label if args.task == "fraud" else (r.source == "ai")))
    print(f"trained {detector.name} (task={args.task}) on {len(records)} records "
          f"({n_pos} positive) -> {args.out}")
    return 0


def _cmd_cross_generator(args: argparse.Namespace) -> int:
    records = []
    for path in args.dataset:
        records.extend(load_jsonl(path))
    try:
        results = cross_generator_provenance(records, threshold=args.threshold)
    except (ValueError, ImportError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 1
    label = ", ".join(args.dataset)
    md = render_crossgen(results, dataset_label=label)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(md)
        print(f"wrote {args.out}")
    else:
        print(md)
    return 0


def _cmd_leaderboard(args: argparse.Namespace) -> int:
    dataset = load_jsonl(args.dataset)
    names = args.detector or available()
    results = evaluate_detectors(dataset, names, threshold=args.threshold, task=args.task)
    markdown = render_markdown(results, dataset_label=args.dataset, n_records=len(dataset))

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(markdown)
        print(f"wrote leaderboard to {args.out}")
    else:
        print(markdown)
    if args.json:
        write_json(results, args.json)
        print(f"wrote results JSON to {args.json}")
    return 0


def _cmd_manifest(args: argparse.Namespace) -> int:
    dataset = load_jsonl(args.dataset)
    manifest = build_manifest(dataset)
    print(json.dumps(manifest, indent=2))
    for warning in check_balance(manifest):
        print(f"! balance: {warning}", file=sys.stderr)
    return 0


def _parse_splits(pairs: List[str]) -> dict:
    splits = {}
    for pair in pairs:
        if "=" not in pair:
            raise ValueError(f"--split expects name=path, got {pair!r}")
        name, path = pair.split("=", 1)
        splits[name.strip()] = path.strip()
    return splits


def _cmd_generate(args: argparse.Namespace) -> int:
    gen_kwargs = {}
    if args.engine != "template" and args.model:
        gen_kwargs["model"] = args.model
    if args.engine != "template" and args.max_tokens:
        gen_kwargs["max_tokens"] = args.max_tokens
    if args.engine == "openai-compat":
        if not args.base_url or not args.api_key_env:
            print("! engine 'openai-compat' requires --base-url and --api-key-env", file=sys.stderr)
            return 1
        gen_kwargs["base_url"] = args.base_url
        gen_kwargs["api_key_env"] = args.api_key_env
    try:
        generator = get_generator(args.engine, **gen_kwargs)
    except (ImportError, RuntimeError, KeyError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        print(f"  available engines: {gen_available()}", file=sys.stderr)
        return 1

    label = args.generator_id or getattr(generator, "model", None) or args.engine
    spec = GenerationSpec(
        typology=args.typology,
        channel=args.channel,
        language=args.language,
        persuasion=args.persuasion or [],
        persona=args.persona or "",
        generator=label,
        hard=args.hard,
    )
    records = generate_records(generator, spec, args.n)
    clean, flagged = screen(records)

    save_jsonl(clean + flagged, args.out)
    stats = getattr(generator, "stats", None)
    if stats:
        print(f"  calls: {stats['attempted']} attempted, {stats['ok']} ok, "
              f"{stats['rate_limited']} rate-limited, {stats['content_filter']} filtered, "
              f"{stats['empty']} empty, {stats['http_error']} errored")
    print(f"generated {len(records)} records → {args.out}")
    print(f"  {len(clean)} pending human review, {len(flagged)} auto-flagged for attention")
    print("  NOTE: all records are review-pending. Approve them (set meta.review='approved')")
    print("  before promoting into a shard — nothing here is shard-ready yet.")
    return 0


def _cmd_assemble_core(args: argparse.Namespace) -> int:
    build = build_core(args.source, test_modulus=args.test_modulus)
    paths = write_core(build, args.out)
    manifest = build_manifest(build.train + build.test)

    print(f"assembled lurebench-core: {build.n} records "
          f"({len(build.train)} train / {len(build.test)} test)")
    print(f"  deduped {build.n_before_dedup} -> {build.n_after_dedup}")
    if build.dropped_pending or build.dropped_flagged:
        print(f"  dropped {build.dropped_pending} pending + {build.dropped_flagged} "
              f"flagged generated records (not approved)")
    print(f"  by source: {build.per_source}")
    print(f"  fraud_ratio={manifest['fraud_ratio']} ai_ratio={manifest['ai_ratio']}")
    for warning in check_balance(manifest):
        print(f"  ! balance: {warning}", file=sys.stderr)

    print(f"\nwrote {paths['train']} and {paths['test']}")
    print("Next — assemble the Hub dir and (optionally) push:")
    print(f"  lurebench publish -s train={paths['train']} -s test={paths['test']} "
          f"-r lurebench/core -o {args.out}/hub --push")
    return 0


def _cmd_publish(args: argparse.Namespace) -> int:
    try:
        splits = _parse_splits(args.split)
    except ValueError as exc:
        print(f"! {exc}", file=sys.stderr)
        return 1

    result = assemble(splits, out_dir=args.out, repo_id=args.repo, version=args.version)
    print(f"assembled {result['manifest']['n']} records into {result['out_dir']}")
    for warning in result["warnings"]:
        print(f"! balance: {warning}", file=sys.stderr)

    if args.push:
        try:
            url = push(args.out, args.repo, private=not args.public)
        except Exception as exc:  # noqa: BLE001
            print(f"! push failed: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
        print(f"pushed to {url}")
    else:
        print("(dry run — pass --push to upload to the Hugging Face Hub)")
    return 0


def _cmd_eval(args: argparse.Namespace) -> int:
    dataset = load_jsonl(args.dataset)
    names: List[str] = args.detector or ["heuristic-v0"]

    reports: List[Report] = []
    for name in names:
        try:
            detector = get_detector(name)
            reports.append(run(detector, dataset, threshold=args.threshold, task=args.task))
        except Exception as exc:  # noqa: BLE001 - one detector must not abort the run
            print(f"! skipping {name}: {type(exc).__name__}: {exc}", file=sys.stderr)
            continue

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

    p_ing = sub.add_parser("ingest", help="normalize an external corpus into LureBench JSONL")
    p_ing.add_argument("--adapter", "-a", required=True, help=f"one of {ingest_available()}")
    p_ing.add_argument("--input", "-i", required=True, help="path to the downloaded source file")
    p_ing.add_argument("--out", "-o", required=True, help="output JSONL path")
    p_ing.add_argument("--generator", default=None, help="generator id to stamp on AI records")
    p_ing.add_argument("--dedupe", action="store_true", help="drop normalized-text duplicates")
    p_ing.set_defaults(func=_cmd_ingest)

    p_lb = sub.add_parser("leaderboard", help="run detectors and render a leaderboard")
    p_lb.add_argument("--dataset", "-d", required=True, help="path to a JSONL dataset")
    p_lb.add_argument("--detector", "-m", action="append", help="detector name (repeatable); default: all")
    p_lb.add_argument("--threshold", type=float, default=0.5)
    p_lb.add_argument("--task", "-t", choices=["fraud", "provenance"], default=None,
                      help="override each detector's task (score any dataset on either question)")
    p_lb.add_argument("--out", "-o", default=None, help="write Markdown here (else stdout)")
    p_lb.add_argument("--json", default=None, help="also write results JSON here")
    p_lb.set_defaults(func=_cmd_leaderboard)

    p_cg = sub.add_parser("cross-generator",
                          help="leave-one-generator-out provenance (the headline finding)")
    p_cg.add_argument("--dataset", "-d", action="append", required=True,
                      help="JSONL with human + multi-generator AI records (repeatable)")
    p_cg.add_argument("--threshold", type=float, default=0.5)
    p_cg.add_argument("--out", "-o", default=None, help="write Markdown here (else stdout)")
    p_cg.set_defaults(func=_cmd_cross_generator)

    p_man = sub.add_parser("manifest", help="print the composition manifest for a dataset")
    p_man.add_argument("--dataset", "-d", required=True, help="path to a JSONL dataset")
    p_man.set_defaults(func=_cmd_manifest)

    p_train = sub.add_parser("train", help="train the tfidf-logreg baseline detector")
    p_train.add_argument("--dataset", "-d", required=True, help="training JSONL (use the train split)")
    p_train.add_argument("--out", "-o", default="models/tfidf-logreg-fraud.joblib", help="model output path")
    p_train.add_argument("--task", "-t", choices=["fraud", "provenance"], default="fraud")
    p_train.set_defaults(func=_cmd_train)

    p_pub = sub.add_parser("publish", help="assemble a Hub-ready dataset dir (and optionally push)")
    p_pub.add_argument("--split", "-s", action="append", required=True, help="name=path (repeatable)")
    p_pub.add_argument("--repo", "-r", required=True, help="Hub dataset repo id, e.g. lurebench/core")
    p_pub.add_argument("--out", "-o", required=True, help="local output directory to assemble into")
    p_pub.add_argument("--version", default="v1")
    p_pub.add_argument("--push", action="store_true", help="upload to the Hub (needs 'hub' extra + auth)")
    p_pub.add_argument("--public", action="store_true", help="create a public repo (default: private)")
    p_pub.set_defaults(func=_cmd_publish)

    p_gen = sub.add_parser("generate", help="controlled generation of synthetic AI lures (review-pending)")
    p_gen.add_argument("--typology", "-t", required=True, choices=["phishing", "bec", "romance", "pig_butchering"])
    p_gen.add_argument("--n", type=int, default=10, help="number of records to generate")
    p_gen.add_argument("--engine", "-e", default="template", help=f"one of {gen_available()}")
    p_gen.add_argument("--model", default=None, help="model id (defaults per engine/provider preset)")
    p_gen.add_argument("--max-tokens", type=int, default=None, help="output token budget (raise for reasoning models, e.g. kimi)")
    p_gen.add_argument("--base-url", default=None, help="required for engine 'openai-compat'")
    p_gen.add_argument("--api-key-env", default=None, help="env var holding the provider key (openai-compat)")
    p_gen.add_argument("--generator-id", default=None, help="provenance label stamped on records")
    p_gen.add_argument("--channel", default="email")
    p_gen.add_argument("--language", default="en")
    p_gen.add_argument("--persona", default=None, help="non-identifying scenario seed")
    p_gen.add_argument("--persuasion", action="append", help="persuasion tag (repeatable)")
    p_gen.add_argument("--hard", action="store_true", help="subtler, more varied lures (no stock spam markers)")
    p_gen.add_argument("--out", "-o", required=True, help="staging JSONL path (review-pending)")
    p_gen.set_defaults(func=_cmd_generate)

    p_core = sub.add_parser("assemble-core", help="merge sourced + approved-generated shards into lurebench-core")
    p_core.add_argument("--source", "-s", action="append", required=True, help="input JSONL (repeatable)")
    p_core.add_argument("--out", "-o", required=True, help="output dir for train.jsonl / test.jsonl")
    p_core.add_argument("--test-modulus", type=int, default=10, help="1/N held out as the frozen test split")
    p_core.set_defaults(func=_cmd_assemble_core)

    return parser


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
