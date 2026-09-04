"""Command-line interface: ``lurebench eval`` / ``lurebench detectors``."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import List

from .attacks import available as attacks_available
from .attacks import get_attack
from .audit import audit_splits
from .calibration import build_policy, calibration_metrics
from .corpus import build_core, write_core
from .corpus_v2 import build_core_v2, write_core_v2
from .crossgen import cross_generator_provenance
from .crossgen import render_markdown as render_crossgen
from .detectors import available, get_detector
from .generate import GenerationSpec, generate_records, get_generator, screen
from .generate import available as gen_available
from .harness import Report, collect_scores, run
from .hub import assemble, push
from .ingest import available as ingest_available
from .ingest import dedupe, get_adapter
from .leaderboard import evaluate_detectors, render_markdown, write_json
from .manifest import build_manifest, check_balance
from .robustness import render_markdown as render_robustness
from .robustness import run_robustness
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
    print(
        f"trained {detector.name} (task={args.task}) on {len(records)} records "
        f"({n_pos} positive) -> {args.out}"
    )
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
    results = evaluate_detectors(
        dataset,
        names,
        threshold=args.threshold,
        task=args.task,
        cache_dir=args.cache_dir,
        workers=args.workers,
    )
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


def _cmd_audit_splits(args: argparse.Namespace) -> int:
    try:
        split_paths = _parse_splits(args.split)
    except ValueError as exc:
        print(f"! {exc}", file=sys.stderr)
        return 1
    audit = audit_splits(
        {name: load_jsonl(path) for name, path in split_paths.items()},
        threshold=args.threshold,
        shingle_size=args.shingle_size,
    )
    payload = json.dumps(audit.as_dict(), indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(payload + "\n")
        print(f"wrote {args.out}")
    else:
        print(payload)
    if not audit.passed:
        print(
            f"! leakage: {len(audit.family_overlaps)} family overlaps, "
            f"{len(audit.near_duplicates)} near-duplicate pairs",
            file=sys.stderr,
        )
    return int(args.fail_on_leakage and not audit.passed)


def _cmd_calibrate(args: argparse.Namespace) -> int:
    kwargs = {"model_path": args.model_path} if args.model_path else {}
    try:
        detector = get_detector(args.detector, **kwargs)
        records = load_jsonl(args.validation)
        ids, truths, scores = collect_scores(detector, records, task=args.task)
        policy, metrics = build_policy(
            detector=getattr(detector, "name", args.detector),
            task=args.task,
            record_ids=ids,
            y_true=truths,
            scores=scores,
            objective=args.objective,
            target_fpr=args.target_fpr,
            confidence=args.confidence,
            threshold_grid_size=args.threshold_grid_size,
        )
        diagnostics = calibration_metrics(truths, scores, n_bins=args.bins)
    except (ImportError, KeyError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 1
    policy.save(args.out)
    print(f"wrote policy {policy.policy_id} to {args.out}")
    print(
        f"  threshold={policy.threshold:.6g} validation_MCC={metrics.mcc:.3f} "
        f"TPR={metrics.recall:.3f} FPR={metrics.fpr:.3f}"
    )
    print(f"  Brier={diagnostics.brier:.4f} ECE={diagnostics.expected_calibration_error:.4f}")
    if policy.risk_control is not None:
        control = policy.risk_control
        print(
            f"  risk-control={control.confidence:.1%} one-sided FPR bound "
            f"{control.upper_confidence_bound:.4f} <= target {policy.target_fpr:.4f} "
            f"({control.false_positives}/{control.validation_negatives} validation negatives)"
        )
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
        print(
            f"  calls: {stats['attempted']} attempted, {stats['ok']} ok, "
            f"{stats['rate_limited']} rate-limited, {stats['content_filter']} filtered, "
            f"{stats['empty']} empty, {stats['http_error']} errored"
        )
    print(f"generated {len(records)} records → {args.out}")
    print(f"  {len(clean)} pending human review, {len(flagged)} auto-flagged for attention")
    print("  NOTE: all records are review-pending. Approve them (set meta.review='approved')")
    print("  before promoting into a shard — nothing here is shard-ready yet.")
    return 0


def _cmd_assemble_core(args: argparse.Namespace) -> int:
    build = build_core(
        args.source,
        test_modulus=args.test_modulus,
        validation_modulus=args.validation_modulus,
    )
    paths = write_core(build, args.out)
    manifest = build_manifest(build.train + build.test)

    print(
        f"assembled lurebench-core: {build.n} records "
        f"({len(build.train)} train / {len(build.validation)} validation / "
        f"{len(build.test)} test)"
    )
    print(f"  deduped {build.n_before_dedup} -> {build.n_after_dedup}")
    if build.dropped_pending or build.dropped_flagged:
        print(
            f"  dropped {build.dropped_pending} pending + {build.dropped_flagged} "
            f"flagged generated records (not approved)"
        )
    print(f"  by source: {build.per_source}")
    print(f"  fraud_ratio={manifest['fraud_ratio']} ai_ratio={manifest['ai_ratio']}")
    for warning in check_balance(manifest):
        print(f"  ! balance: {warning}", file=sys.stderr)

    print(f"\nwrote {paths['train']}, {paths['validation']} and {paths['test']}")
    print("Next — assemble the Hub dir and (optionally) push:")
    print(
        f"  lurebench publish -s train={paths['train']} "
        f"-s validation={paths['validation']} -s test={paths['test']} "
        f"-r lurebench/core -o {args.out}/hub --push"
    )
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
        payload = []
        for r in reports:
            item = {
                "detector": r.detector,
                "task": r.task,
                "threshold": r.threshold,
                "n_skipped": r.n_skipped,
                "metrics": r.metrics.as_dict(),
            }
            if args.bootstrap:
                item["confidence_intervals"] = {
                    name: interval.__dict__
                    for name, interval in r.confidence_intervals(
                        args.bootstrap, args.confidence
                    ).items()
                }
            payload.append(item)
        print(json.dumps(payload, indent=2))
    else:
        print(f"\nLureBench eval — {len(dataset)} records — {args.dataset}\n")
        for r in reports:
            print("  " + r.summary_line())
            if args.bootstrap:
                intervals = r.confidence_intervals(args.bootstrap, args.confidence)
                rendered = "  ".join(
                    f"{name.upper()} {ci.estimate:.3f} [{ci.lower:.3f}, {ci.upper:.3f}]"
                    for name, ci in intervals.items()
                )
                print(f"    {int(args.confidence * 100)}% paired bootstrap: {rendered}")
        print()
    return 0


def _cmd_robustness(args: argparse.Namespace) -> int:
    dataset = load_jsonl(args.dataset)
    try:
        detector = get_detector(args.detector)
    except Exception as exc:  # noqa: BLE001
        print(f"! {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    reports = []
    for aname in args.attack:
        try:
            if aname.startswith("llm-"):
                if not args.engine:
                    print(f"! {aname} needs --engine <provider>", file=sys.stderr)
                    continue
                from .attacks.llm import (
                    LLMKeywordEvasionAttack,
                    LLMParaphraseAttack,
                    provider_complete_fn,
                )

                complete_fn = provider_complete_fn(args.engine, args.model)
                if aname == "llm-keyword-evasion":
                    words = _predictive_words(detector)
                    attack = LLMKeywordEvasionAttack(complete_fn, words)
                else:
                    attack = LLMParaphraseAttack(complete_fn)
            else:
                attack = get_attack(aname)
        except Exception as exc:  # noqa: BLE001 - one attack must not abort the run
            print(f"! skipping {aname}: {type(exc).__name__}: {exc}", file=sys.stderr)
            continue
        reports.append(
            run_robustness(detector, dataset, attack, threshold=args.threshold, task=args.task)
        )

    if not reports:
        print("No attack could be run.", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps([r.as_dict() for r in reports], indent=2))
    else:
        md = render_robustness(reports, dataset_label=args.dataset)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(md + "\n")
            print(f"wrote {args.out}")
        else:
            print("\n" + md + "\n")
    return 0


def _predictive_words(detector, top_k: int = 25) -> List[str]:
    """Pull a detector's most lure-predictive words for targeted evasion, falling back
    to a generic phishing-keyword list for detectors that can't expose their features."""
    extract = getattr(detector, "top_positive_features", None)
    if callable(extract):
        try:
            words = list(extract(top_k))
            if words:
                return words
        except Exception:  # noqa: BLE001
            pass
    return ["verify", "urgent", "account", "click", "suspended", "payment"]


def _cmd_multilingual(args: argparse.Namespace) -> int:
    from .multilingual import cross_lingual_detection, render_comparison
    from .multilingual import render_markdown as render_ml

    dataset = load_jsonl(args.dataset)
    names: List[str] = args.detector or ["tfidf-logreg"]
    sections = []
    for name in names:
        try:
            detector = get_detector(name)
        except Exception as exc:  # noqa: BLE001
            print(f"! skipping {name}: {type(exc).__name__}: {exc}", file=sys.stderr)
            continue
        if cross_lingual_detection(detector, dataset, threshold=args.threshold):
            if args.raw:
                sections.append(
                    render_ml(
                        cross_lingual_detection(detector, dataset, threshold=args.threshold), name
                    )
                )
            else:
                sections.append(
                    render_comparison(detector, dataset, name, threshold=args.threshold)
                )
        else:
            print(f"! {name}: no fraud lures with a language tag found", file=sys.stderr)
            continue

    if not sections:
        print("No detector could be run.", file=sys.stderr)
        return 1
    md = "\n\n".join(sections)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(md + "\n")
        print(f"wrote {args.out}")
    else:
        print("\n" + md + "\n")
    return 0


def _cmd_stix(args: argparse.Namespace) -> int:
    from .stix import records_to_stix, taxonomy_to_stix, to_bundle

    if args.taxonomy_only:
        bundle = to_bundle(taxonomy_to_stix())
        n = len(bundle["objects"])
        label = "taxonomy"
    else:
        if not args.dataset:
            print("! provide --dataset, or use --taxonomy-only", file=sys.stderr)
            return 1
        dataset = load_jsonl(args.dataset)
        bundle = records_to_stix(dataset, include_benign=args.include_benign)
        n = len(bundle["objects"])
        label = args.dataset

    payload = json.dumps(bundle, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(payload + "\n")
        print(f"wrote {args.out} — STIX 2.1 bundle, {n} objects ({label})")
    else:
        print(payload)
    return 0


def _read_bounded_key(path: str) -> bytes:
    resolved = Path(path)
    if resolved.is_symlink():
        raise ValueError(f"refusing symbolic-link key: {resolved}")
    if not resolved.is_file():
        raise FileNotFoundError(resolved)
    if resolved.stat().st_size > 64 * 1024:
        raise ValueError(f"key file exceeds 64 KiB: {resolved}")
    return resolved.read_bytes()


def _write_new_private(path: str, payload: str) -> None:
    target = Path(path)
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(payload)
    except Exception:
        target.unlink(missing_ok=True)
        raise


def _cmd_verify_receipt(args: argparse.Namespace) -> int:
    from .receipts import load_verified_artifact

    try:
        public_key = _read_bounded_key(args.public_key) if args.public_key else None
        verified = load_verified_artifact(
            Path(args.artifact),
            public_key_pem=public_key,
            require_signature=args.require_signature,
        )
    except (FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 1
    predicate = verified.statement["predicate"]
    kind = predicate["spec"]
    identifier = predicate.get("receipt_id", predicate.get("aggregate_id"))
    authentication = (
        "authenticated"
        if verified.authenticated
        else "signed-unverified"
        if verified.signed
        else "unsigned"
    )
    print(
        f"verified {kind} {identifier} — sha256={verified.statement_sha256} "
        f"authentication={authentication}"
    )
    return 0


def _parse_source_keys(values: List[str]) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    for value in values:
        if "=" not in value:
            raise ValueError("--source-key expects RECEIPT=PUBLIC_KEY")
        receipt, key = value.split("=", 1)
        identity = str(Path(receipt).absolute())
        if identity in result:
            raise ValueError(f"duplicate source-key mapping for {receipt}")
        result[identity] = _read_bounded_key(key)
    return result


def _cmd_aggregate_receipts(args: argparse.Namespace) -> int:
    from . import __version__
    from .receipts import (
        aggregate_receipts,
        dumps_artifact,
        load_verified_artifact,
        sign_statement,
    )

    try:
        source_keys = _parse_source_keys(args.source_key or [])
        receipts = []
        for value in args.receipt:
            identity = str(Path(value).absolute())
            public_key = source_keys.get(identity)
            receipts.append(
                load_verified_artifact(
                    Path(value),
                    public_key_pem=public_key,
                    require_signature=args.require_source_signatures,
                )
            )
        aggregate = aggregate_receipts(
            receipts,
            producer_version=__version__,
            issuer=args.issuer,
            require_authenticated_sources=args.require_source_signatures,
        )
        artifact = (
            sign_statement(aggregate, _read_bounded_key(args.signing_key))
            if args.signing_key
            else aggregate
        )
        _write_new_private(args.out, dumps_artifact(artifact))
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 1
    predicate = aggregate["predicate"]
    metrics = predicate["pooled"]["metrics"]
    print(
        f"wrote {args.out} — {predicate['source_receipt_count']} compatible receipts, "
        f"recall={metrics['recall_estimate']} "
        f"FPR={metrics['false_positive_rate_estimate']}"
    )
    return 0


def _cmd_conformance(args: argparse.Namespace) -> int:
    from .conformance import dumps_report, run_conformance_suite, write_report

    try:
        report = run_conformance_suite(Path(args.suite) if args.suite else None)
        if args.out:
            write_report(Path(args.out), report)
        if args.json:
            print(dumps_report(report), end="")
        else:
            summary = report["summary"]
            destination = f"; report={args.out}" if args.out else ""
            print(
                f"LUREEVAL CONFORMANCE: {summary['verdict'].upper()} — "
                f"{summary['passed']}/{summary['total']} cases passed{destination}"
            )
        return 0 if report["summary"]["verdict"] == "pass" else 1
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _cmd_boundary_eval(args: argparse.Namespace) -> int:
    from .boundary import (
        dumps_boundary_evaluation,
        run_boundary_evaluation,
        write_boundary_evaluation,
    )

    monitor = None
    try:
        if args.container_report and not args.image:
            raise ValueError("--container-report requires --image")
        kwargs = {}
        if args.image:
            from .boundary_container import PROTOCOL, BoundaryContainerMonitor

            monitor = BoundaryContainerMonitor(
                args.image,
                runtime=args.runtime,
                timeout_seconds=args.timeout,
                memory=args.memory,
                cpus=args.cpus,
                allow_mutable_image=args.allow_mutable_image,
            )
            kwargs = {
                "monitor": monitor,
                "monitor_id": args.monitor_id,
                "monitor_version": args.monitor_version,
                "monitor_artifact_sha256": monitor.artifact_sha256,
            }
        report = run_boundary_evaluation(Path(args.suite) if args.suite else None, **kwargs)
        if args.out:
            write_boundary_evaluation(Path(args.out), report)
        if args.container_report:
            assert monitor is not None
            wrapper = {
                "schema": (
                    "https://github.com/immu4989/lurebench/spec/"
                    "agent-boundary-container-evaluation/v1"
                ),
                "schema_version": 1,
                "generated_at": report["generated_at"],
                "protocol": PROTOCOL,
                "runtime": args.runtime,
                "image_reference": args.image,
                "image_id": monitor.image_id,
                "mutable_reference_allowed": bool(args.allow_mutable_image),
                "isolation": monitor.isolation_claims(),
                "privacy": {
                    "ground_truth_transmitted": False,
                    "scenario_identifiers_transmitted": False,
                    "scenario_prose_transmitted": False,
                    "acceptance_thresholds_transmitted": False,
                },
                "evaluation": report,
                "limitations": [
                    "container_isolation_depends_on_the_local_runtime_and_kernel",
                    "image_identity_does_not_authenticate_a_vendor_without_external_provenance",
                    "protocol_conformance_does_not_establish_deployment_containment",
                ],
            }
            _write_new_private(
                args.container_report,
                json.dumps(wrapper, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            )
        if args.json:
            print(dumps_boundary_evaluation(report), end="")
        else:
            summary = report["summary"]
            destination = f"; report={args.out}" if args.out else ""
            print(
                f"LUREBOUNDARY: {summary['verdict'].upper()} — "
                f"recall={summary['trajectory_recall']:.3f} "
                f"benign-FPR={summary['benign_false_positive_rate']:.3f} "
                f"max-delay={summary['maximum_detection_delay_events']} event(s){destination}"
            )
        return 0 if report["summary"]["verdict"] == "pass" else 1
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2
    finally:
        if monitor is not None:
            monitor.close()


def _cmd_coverage_canaries(args: argparse.Namespace) -> int:
    try:
        from .coverage import build_coverage_canaries, write_coverage_artifact

        artifact = build_coverage_canaries(Path(args.manifest), replicates=args.replicates)
        write_coverage_artifact(Path(args.out), artifact)
        print(f"LURECOVERAGE CANARIES: {len(artifact['probes'])} payload-free probes — {args.out}")
        print("boundary: descriptors only; LureBench does not execute agent actions")
        return 0
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _cmd_coverage_eval(args: argparse.Namespace) -> int:
    try:
        from .coverage import evaluate_coverage, write_coverage_artifact

        report = evaluate_coverage(
            Path(args.manifest), Path(args.canaries), Path(args.observations)
        )
        write_coverage_artifact(Path(args.out), report)
        summary = report["summary"]
        print(
            f"LURECOVERAGE: {summary['verdict'].upper()} — "
            f"routes={summary['covered_required_routes']}/{summary['required_routes']} "
            f"delivery={summary['probe_delivery_rate']:.3f} "
            f"lineage={summary['lineage_continuity']:.3f} — {args.out}"
        )
        return 0 if summary["verdict"] == "pass" else 1
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _cmd_delegation_eval(args: argparse.Namespace) -> int:
    try:
        from .delegation import run_delegation_evaluation, write_delegation_evaluation

        report = run_delegation_evaluation()
        if args.out:
            write_delegation_evaluation(Path(args.out), report)
        if args.json:
            print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
        else:
            summary = report["summary"]
            print(
                f"LUREDELEGATION: {summary['verdict'].upper()} — "
                f"recall={summary['recall']:.3f} "
                f"benign-FPR={summary['benign_false_positive_rate']:.3f} "
                f"category={summary['category_accuracy']:.3f}"
            )
        return 0 if report["summary"]["verdict"] == "pass" else 1
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _cmd_ir_tasks(args: argparse.Namespace) -> int:
    try:
        from .incident_response import export_ir_tasks, write_ir_artifact

        tasks = export_ir_tasks()
        write_ir_artifact(Path(args.out), tasks)
        print(f"LUREIR TASKS: {len(tasks['cases'])} defanged cases — {args.out}")
        return 0
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _cmd_ir_eval(args: argparse.Namespace) -> int:
    try:
        from .incident_response import evaluate_ir_responses, write_ir_artifact

        report = evaluate_ir_responses(
            Path(args.responses),
            responder_id=args.responder_id,
            responder_version=args.responder_version,
        )
        write_ir_artifact(Path(args.out), report)
        summary = report["summary"]
        print(
            f"LUREIR: {summary['verdict'].upper()} — "
            f"fact-recall={summary['fact_recall']:.3f} "
            f"support={summary['evidence_support_rate']:.3f} "
            f"unsafe-action-rate={summary['unsafe_action_rate']:.3f} — {args.out}"
        )
        return 0 if summary["verdict"] == "pass" else 1
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _cmd_invariant_eval(args: argparse.Namespace) -> int:
    try:
        from .invariant import evaluate_invariants, write_invariant_artifact

        report = evaluate_invariants(Path(args.plan), Path(args.observations))
        if args.out:
            write_invariant_artifact(Path(args.out), report)
        if args.json:
            print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
        else:
            summary = report["summary"]
            destination = f" — {args.out}" if args.out else ""
            print(
                f"LUREINVARIANT: {summary['verdict'].upper()} — "
                f"violated={summary['violated']} "
                f"not-observed={summary['not_observed_within_declared_boundary']} "
                f"insufficient={summary['insufficient_evidence']} "
                f"source-coverage={summary['source_coverage']:.3f}{destination}"
            )
        return 0 if report["summary"]["verdict"] == "pass" else 1
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _cmd_permit_init(args: argparse.Namespace) -> int:
    try:
        from .permit import default_permit, write_permit

        permit = default_permit()
        write_permit(Path(args.out), permit)
        print(
            f"LUREPERMIT CREATED: {permit['permit_id']} — {args.out}\n"
            "boundary: synthetic conformance contract only; not a runtime credential or authorization"
        )
        return 0
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _cmd_range_export(args: argparse.Namespace) -> int:
    try:
        from .permit import default_range_suite, write_range_suite

        suite = default_range_suite()
        write_range_suite(Path(args.out), suite)
        print(
            f"LURERANGE EXPORTED: {len(suite['scenarios'])} offline scenarios — {args.out}\n"
            "boundary: typed synthetic metadata only; no live actions or network access"
        )
        return 0
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _cmd_range_eval(args: argparse.Namespace) -> int:
    try:
        from .permit import run_range_evaluation, write_range_evaluation

        report = run_range_evaluation(
            Path(args.permit) if args.permit else None,
            Path(args.suite) if args.suite else None,
            engine_id=args.engine_id,
            engine_version=args.engine_version,
            engine_artifact_sha256=args.engine_artifact_sha256,
        )
        if args.out:
            write_range_evaluation(Path(args.out), report)
        if args.json:
            print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
        else:
            summary = report["summary"]
            destination = f" — {args.out}" if args.out else ""
            print(
                f"LURERANGE: {summary['verdict'].upper()} — "
                f"controlled={summary['violation_control_rate']:.3f} "
                f"benign-allow={summary['benign_allow_rate']:.3f} "
                f"safe-stop={summary['safe_stop_recall']:.3f}{destination}"
            )
            print("boundary: conformance evidence only; no agent action was executed")
        return 0 if report["summary"]["verdict"] == "pass" else 1
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _cmd_runtime_init(args: argparse.Namespace) -> int:
    try:
        from .runtime import default_runtime_profile, write_runtime_profile

        profile = default_runtime_profile()
        write_runtime_profile(Path(args.out), profile)
        print(
            f"LUREPERMIT RUNTIME PROFILE CREATED: {profile['profile_id']} — {args.out}\n"
            "boundary: typed authorization metadata only; not a credential or deployment approval"
        )
        return 0
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _cmd_runtime_trace(args: argparse.Namespace) -> int:
    try:
        from .runtime import default_runtime_trace, write_runtime_trace

        trace = default_runtime_trace()
        write_runtime_trace(Path(args.out), trace)
        print(
            f"LUREPERMIT RUNTIME TRACE CREATED: {len(trace['requests'])} requests — {args.out}\n"
            "boundary: synthetic decisions and sensor metadata; no action was executed"
        )
        return 0
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _cmd_runtime_eval(args: argparse.Namespace) -> int:
    try:
        from .runtime import (
            evaluate_runtime_trace,
            load_runtime_trace,
            write_runtime_evaluation,
        )

        trace = load_runtime_trace(Path(args.trace) if args.trace else None)
        report = evaluate_runtime_trace(trace)
        if args.out:
            write_runtime_evaluation(Path(args.out), report)
        if args.json:
            print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
        else:
            summary = report["summary"]
            destination = f" — {args.out}" if args.out else ""
            print(
                f"LUREPERMIT RUNTIME: {summary['verdict'].upper()} — "
                f"request-coverage={summary['mediation_coverage_rate']:.3f} "
                f"point-coverage={summary['mediation_point_coverage_rate']:.3f} "
                f"bypasses={summary['control_bypass_count']} "
                f"unmediated={summary['unmediated_count']} "
                f"unknown={summary['unknown_count']}{destination}"
            )
            print("boundary: receipt/sensor reconciliation only; no runtime action was executed")
        return 0 if report["summary"]["verdict"] == "pass" else 1
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _cmd_revocation_export(args: argparse.Namespace) -> int:
    try:
        from .revocation import default_revocation_plan, write_revocation_plan

        plan = default_revocation_plan()
        write_revocation_plan(Path(args.out), plan)
        print(
            f"LUREREVOKE PLAN EXPORTED: {len(plan['events'])} events across "
            f"{len(plan['nodes'])} nodes — {args.out}\n"
            "boundary: CAEP-shaped synthetic metadata only; no SET or network traffic"
        )
        return 0
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _cmd_revocation_compose(args: argparse.Namespace) -> int:
    try:
        from .revocation import write_revocation_plan
        from .revocation_campaign import compose_revocation_plan, load_revocation_campaign

        campaign = load_revocation_campaign(Path(args.campaign))
        plan = compose_revocation_plan(campaign)
        write_revocation_plan(Path(args.out), plan)
        print(
            f"LUREREVOKE PLAN COMPOSED: {len(plan['events'])} projected events, "
            f"{len(plan['nodes'])} nodes, {len(plan['probes'])} probes — {args.out}\n"
            "boundary: composition only; no SET verification, signal delivery, or access action"
        )
        return 0
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _cmd_revocation_run(args: argparse.Namespace) -> int:
    try:
        from .revocation import (
            load_revocation_plan,
            reference_revocation_run,
            write_revocation_run,
        )

        plan = load_revocation_plan(Path(args.plan) if args.plan else None)
        run = reference_revocation_run(
            plan,
            run_id=args.run_id,
            implementation_name=args.engine_id,
            implementation_version=args.engine_version,
            implementation_artifact_sha256=args.engine_artifact_sha256,
        )
        write_revocation_run(Path(args.out), run, plan)
        print(
            f"LUREREVOKE RUN CREATED: {len(run['signal_observations'])} signal and "
            f"{len(run['access_observations'])} access observations — {args.out}\n"
            "boundary: offline reference receiver only; no identity provider or agent contacted"
        )
        return 0
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _cmd_revocation_otel_project(args: argparse.Namespace) -> int:
    try:
        from .revocation import load_revocation_plan
        from .revocation_otel import (
            load_otel_log_export,
            project_otel_revocation_run,
            write_otel_projection_and_run,
        )

        plan = load_revocation_plan(Path(args.plan))
        export = load_otel_log_export(Path(args.logs), plan)
        projection = project_otel_revocation_run(plan, export, run_id=args.run_id)
        write_otel_projection_and_run(Path(args.out), Path(args.run_out), projection)
        print(
            f"LUREREVOKE OTEL PROJECTED: {len(export['records'])} body-free records — "
            f"projection={args.out}; run={args.run_out}\n"
            "boundary: strict Logs Data Model projection only; not raw OTLP or telemetry proof"
        )
        return 0
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _cmd_revocation_otel_verify(args: argparse.Namespace) -> int:
    try:
        from .revocation_otel import load_otel_revocation_projection

        projection = load_otel_revocation_projection(Path(args.projection))
        print(
            f"LUREREVOKE OTEL VERIFIED: {len(projection['inputs']['otel_log_export']['records'])} "
            f"records; run-sha256={projection['run_sha256']} — {args.projection}\n"
            "boundary: deterministic projection only; no clock, completeness, or causality proof"
        )
        return 0
    except (FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _cmd_revocation_eval(args: argparse.Namespace) -> int:
    try:
        from .revocation import (
            evaluate_revocation_run,
            load_revocation_plan,
            load_revocation_run,
            reference_revocation_run,
            write_revocation_evaluation,
        )

        plan = load_revocation_plan(Path(args.plan) if args.plan else None)
        run = (
            load_revocation_run(Path(args.run), plan)
            if args.run
            else reference_revocation_run(plan)
        )
        report = evaluate_revocation_run(plan, run)
        if args.out:
            write_revocation_evaluation(Path(args.out), report)
        if args.json:
            print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
        else:
            summary = report["summary"]
            destination = f" — {args.out}" if args.out else ""
            print(
                f"LUREREVOKE: {summary['verdict'].upper()} — "
                f"coverage={summary['delivery_coverage_rate']:.3f} "
                f"p95={summary['p95_convergence_ms']}ms "
                f"deadline-misses={summary['deadline_miss_count']} "
                f"post-deadline-allows={summary['post_deadline_allow_count']}"
                f"{destination}"
            )
            print("boundary: convergence evidence only; no complete-mediation or compliance claim")
        return 0 if report["summary"]["verdict"] == "pass" else 1
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _cmd_identity_export(args: argparse.Namespace) -> int:
    try:
        from .identity import default_identity_plan, write_identity_plan

        plan = default_identity_plan()
        write_identity_plan(Path(args.out), plan)
        print(
            f"LUREIDENTITY PLAN EXPORTED: {len(plan['events'])} lifecycle events, "
            f"{len(plan['principals'])} principals, {len(plan['nodes'])} nodes — {args.out}\n"
            "boundary: synthetic SCIM-shaped lifecycle metadata; no directory or target contacted"
        )
        return 0
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _cmd_artifact_compose(args: argparse.Namespace) -> int:
    try:
        from .artifact import (
            compose_artifact_plan,
            load_artifact_campaign,
            write_artifact_plan,
        )
        from .identity import load_identity_plan

        identity_plan = load_identity_plan(Path(args.identity_plan))
        campaign = load_artifact_campaign(Path(args.campaign), identity_plan)
        plan = compose_artifact_plan(identity_plan, campaign)
        write_artifact_plan(Path(args.out), plan)
        deployment_count = sum(len(item["node_ids"]) for item in plan["workloads"])
        print(
            f"LUREARTIFACT PLAN COMPOSED: {len(plan['workloads'])} active workloads, "
            f"{deployment_count} deployments, 4 required artifacts and 3 provenance "
            f"statements per deployment — {args.out}\n"
            "boundary: declared digest metadata only; no artifact fetched, loaded, "
            "imported, executed, or deserialized"
        )
        return 0
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _cmd_artifact_observe(args: argparse.Namespace) -> int:
    try:
        from .artifact import (
            load_artifact_plan,
            reference_artifact_observation,
            write_artifact_observation,
        )

        plan = load_artifact_plan(Path(args.plan))
        observation = reference_artifact_observation(
            plan,
            observation_id=args.observation_id,
            captured_at=args.captured_at,
        )
        write_artifact_observation(Path(args.out), observation)
        print(
            f"LUREARTIFACT REFERENCE OBSERVATION: "
            f"{len(observation['deployments'])} claimed deployments — {args.out}\n"
            "boundary: deterministic metadata fixture only; not trusted runtime measurement"
        )
        return 0
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _cmd_artifact_eval(args: argparse.Namespace) -> int:
    try:
        from .artifact import (
            evaluate_artifact_observation,
            load_artifact_observation,
            load_artifact_plan,
            write_artifact_evaluation,
        )

        plan = load_artifact_plan(Path(args.plan))
        observation = load_artifact_observation(Path(args.observation))
        evaluation = evaluate_artifact_observation(
            plan, observation, generated_at=args.generated_at
        )
        if args.out:
            write_artifact_evaluation(Path(args.out), evaluation)
        if args.json:
            print(json.dumps(evaluation, ensure_ascii=False, sort_keys=True, indent=2))
        else:
            summary = evaluation["summary"]
            destination = f" — {args.out}" if args.out else ""
            print(
                f"LUREARTIFACT: {summary['verdict'].upper()} — "
                f"deployments={summary['compliant_deployment_count']}/"
                f"{summary['expected_deployment_count']} findings={summary['finding_count']}"
                f"{destination}"
            )
            print(
                "boundary: declared metadata equality only; no artifact safety, provenance "
                "authenticity, or deployment authorization claim"
            )
        return 0 if evaluation["summary"]["verdict"] == "pass" else 1
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _cmd_artifact_verify(args: argparse.Namespace) -> int:
    try:
        from .artifact import load_artifact_evaluation

        evaluation = load_artifact_evaluation(Path(args.evaluation))
        summary = evaluation["summary"]
        print(
            f"LUREARTIFACT VERIFIED: {summary['verdict'].upper()} — "
            f"deployments={summary['compliant_deployment_count']}/"
            f"{summary['expected_deployment_count']} findings={summary['finding_count']}"
        )
        return 0 if summary["verdict"] == "pass" else 1
    except (FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _cmd_bom_reconcile(args: argparse.Namespace) -> int:
    try:
        from .bom import reconcile_bom_files

        evaluation = reconcile_bom_files(
            Path(args.artifact_plan),
            Path(args.manifest),
            Path(args.cyclonedx),
            Path(args.spdx),
            Path(args.out),
            evaluated_at=args.evaluated_at,
        )
        summary = evaluation["summary"]
        if args.json:
            print(json.dumps(evaluation, ensure_ascii=False, sort_keys=True, indent=2))
        else:
            print(
                f"LUREBOM TWIN: {summary['verdict'].upper()} — "
                f"components={summary['matched_component_count']}/{summary['component_count']} "
                f"dependencies={summary['matched_dependency_count']}/"
                f"{summary['dependency_count']} findings={summary['finding_count']} — {args.out}"
            )
            print(
                "boundary: explicit SHA-256, Package URL, class, and dependsOn projection; "
                "not full SPDX/CycloneDX conformance, completeness, authenticity, or safety"
            )
        return 0 if summary["verdict"] == "pass" else 1
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! LureBOM reconciliation failed: {exc}", file=sys.stderr)
        return 2


def _cmd_bom_verify(args: argparse.Namespace) -> int:
    try:
        from .bom import load_bom_evaluation

        evaluation = load_bom_evaluation(Path(args.evaluation))
        summary = evaluation["summary"]
        print(
            f"LUREBOM VERIFIED: {summary['verdict'].upper()} — "
            f"components={summary['matched_component_count']}/{summary['component_count']} "
            f"dependencies={summary['matched_dependency_count']}/{summary['dependency_count']} "
            f"findings={summary['finding_count']}"
        )
        return 0 if summary["verdict"] == "pass" else 1
    except (FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! LureBOM verification failed: {exc}", file=sys.stderr)
        return 2


def _cmd_channel_eval(args: argparse.Namespace) -> int:
    try:
        from .channel import evaluate_channel_files

        evaluation = evaluate_channel_files(
            Path(args.plan),
            Path(args.run),
            Path(args.out),
            evaluated_at=args.evaluated_at,
        )
        summary = evaluation["summary"]
        if args.json:
            print(json.dumps(evaluation, ensure_ascii=False, sort_keys=True, indent=2))
        else:
            print(
                f"LURECHANNEL: {summary['verdict'].upper()} — "
                f"tests={summary['passed_test_count']}/{summary['test_count']} "
                f"inconclusive={summary['inconclusive_test_count']} "
                f"unauthorized={summary['unauthorized_flow_count']} "
                f"residual={summary['residual_flow_count']} "
                f"sensor-coverage={summary['sensor_coverage_rate']:.3f} — {args.out}"
            )
            print(
                "boundary: non-sensitive canaries across declared runs, channels, sensors, "
                "and windows; not universal noninterference, containment, or safety"
            )
        return 0 if summary["verdict"] == "pass" else 1
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! LureChannel evaluation failed: {exc}", file=sys.stderr)
        return 2


def _cmd_channel_verify(args: argparse.Namespace) -> int:
    try:
        from .channel import load_channel_evaluation

        evaluation = load_channel_evaluation(Path(args.evaluation))
        summary = evaluation["summary"]
        print(
            f"LURECHANNEL VERIFIED: {summary['verdict'].upper()} — "
            f"tests={summary['passed_test_count']}/{summary['test_count']} "
            f"inconclusive={summary['inconclusive_test_count']} "
            f"findings={summary['finding_count']}"
        )
        return 0 if summary["verdict"] == "pass" else 1
    except (FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! LureChannel verification failed: {exc}", file=sys.stderr)
        return 2


def _cmd_recall_compose(args: argparse.Namespace) -> int:
    try:
        from .artifact import load_artifact_plan
        from .recall import (
            compose_recall_plan,
            load_artifact_advisory,
            load_artifact_lineage,
            write_recall_plan,
        )

        artifact_plan = load_artifact_plan(Path(args.artifact_plan))
        lineage = load_artifact_lineage(Path(args.lineage), artifact_plan)
        advisory = load_artifact_advisory(Path(args.advisory), artifact_plan, lineage)
        plan = compose_recall_plan(artifact_plan, lineage, advisory)
        write_recall_plan(Path(args.out), plan)
        impact = plan["impact"]
        affected = sum(item["affected"] for item in plan["deployments"])
        print(
            f"LURERECALL PLAN COMPOSED: {len(impact['actionable_component_ids'])} actionable "
            f"component(s), {impact['affected_root_artifact_count']} affected root(s), "
            f"{affected}/{len(plan['deployments'])} affected deployments, "
            f"{len(plan['probes'])} probes — {args.out}\n"
            "boundary: caller-supplied lineage and VEX-like metadata only; no artifact, "
            "advisory, workload, or network accessed"
        )
        return 0
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _cmd_recall_run(args: argparse.Namespace) -> int:
    try:
        from .recall import load_recall_plan, reference_recall_run, write_recall_run

        plan = load_recall_plan(Path(args.plan))
        run = reference_recall_run(
            plan,
            run_id=args.run_id,
            generated_at=args.generated_at,
            implementation_name=args.engine_id,
            implementation_version=args.engine_version,
            implementation_artifact_sha256=args.engine_artifact_sha256,
        )
        write_recall_run(Path(args.out), run)
        print(
            f"LURERECALL REFERENCE RUN: {len(run['advisory_observations'])} delivery and "
            f"{len(run['response_observations'])} response observations — {args.out}\n"
            "boundary: deterministic metadata fixture only; no quarantine, replacement, "
            "deployment, or artifact access occurred"
        )
        return 0
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _cmd_recall_eval(args: argparse.Namespace) -> int:
    try:
        from .recall import (
            evaluate_recall_run,
            load_recall_plan,
            load_recall_run,
            write_recall_evaluation,
        )

        plan = load_recall_plan(Path(args.plan))
        run = load_recall_run(Path(args.run))
        evaluation = evaluate_recall_run(plan, run, generated_at=args.generated_at)
        if args.out:
            write_recall_evaluation(Path(args.out), evaluation)
        if args.json:
            print(json.dumps(evaluation, ensure_ascii=False, sort_keys=True, indent=2))
        else:
            summary = evaluation["summary"]
            destination = f" — {args.out}" if args.out else ""
            print(
                f"LURERECALL: {summary['verdict'].upper()} — "
                f"affected-deployments={summary['affected_deployment_count']} "
                f"quarantine-recall={summary['quarantine_recall']:.3f} "
                f"recovery-recall={summary['recovery_recall']:.3f} "
                f"findings={summary['finding_count']}{destination}"
            )
            print(
                "boundary: declared lineage, advisory, and response metadata only; no proof "
                "of containment, replacement safety, recovery, or authorization"
            )
        return 0 if evaluation["summary"]["verdict"] == "pass" else 1
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _cmd_recall_verify(args: argparse.Namespace) -> int:
    try:
        from .recall import load_recall_evaluation

        evaluation = load_recall_evaluation(Path(args.evaluation))
        summary = evaluation["summary"]
        print(
            f"LURERECALL VERIFIED: {summary['verdict'].upper()} — "
            f"affected-deployments={summary['affected_deployment_count']} "
            f"quarantine-recall={summary['quarantine_recall']:.3f} "
            f"recovery-recall={summary['recovery_recall']:.3f} "
            f"findings={summary['finding_count']}"
        )
        return 0 if summary["verdict"] == "pass" else 1
    except (FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _cmd_attest_compose(args: argparse.Namespace) -> int:
    try:
        from .artifact import load_artifact_plan
        from .attest import (
            compose_attest_plan,
            load_trust_policy,
            write_attest_plan,
        )

        artifact_plan = load_artifact_plan(Path(args.artifact_plan))
        policy = load_trust_policy(Path(args.policy), artifact_plan)
        plan = compose_attest_plan(artifact_plan, policy)
        write_attest_plan(Path(args.out), plan)
        attestation_count = sum(len(item["attestations"]) for item in plan["workloads"])
        print(
            f"LUREATTEST PLAN COMPOSED: {len(plan['workloads'])} workload(s), "
            f"{attestation_count} authenticated provenance expectation(s), "
            f"{len(plan['trusted_builders'])} pinned builder(s) — {args.out}\n"
            "boundary: trust-policy compilation only; no envelope, public key, source, "
            "build, or artifact bytes opened"
        )
        return 0
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _cmd_attest_verify(args: argparse.Namespace) -> int:
    try:
        from .attest import load_attest_plan

        plan = load_attest_plan(Path(args.plan))
        count = sum(len(item["attestations"]) for item in plan["workloads"])
        print(
            f"LUREATTEST PLAN VERIFIED: {count} provenance expectation(s), "
            f"{len(plan['trusted_builders'])} pinned builder(s)\n"
            "boundary: structural plan recomputation only; use LureScope for DSSE and "
            "SLSA semantic verification"
        )
        return 0
    except (FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _cmd_identity_compose(args: argparse.Namespace) -> int:
    try:
        from .identity import write_identity_plan
        from .identity_campaign import compose_identity_plan, load_identity_campaign

        campaign = load_identity_campaign(Path(args.campaign))
        plan = compose_identity_plan(campaign)
        write_identity_plan(Path(args.out), plan)
        cut_count = sum(
            len(event["required_cut_actor_ids"]) for event in plan["events"]
        )
        preserve_count = sum(
            len(event["required_preserve_actor_ids"]) for event in plan["events"]
        )
        print(
            f"LUREIDENTITY PLAN COMPOSED: {len(plan['events'])} events, "
            f"{cut_count} cut actors, {preserve_count} preserved controls, "
            f"{len(plan['probes'])} probes — {args.out}\n"
            "boundary: compiled declared graph metadata only; no discovery, delivery, "
            "identity authentication, or access execution"
        )
        return 0
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _cmd_identity_run(args: argparse.Namespace) -> int:
    try:
        from .identity import load_identity_plan, reference_identity_run, write_identity_run

        plan = load_identity_plan(Path(args.plan) if args.plan else None)
        run = reference_identity_run(
            plan,
            run_id=args.run_id,
            implementation_name=args.engine_id,
            implementation_version=args.engine_version,
            implementation_artifact_sha256=args.engine_artifact_sha256,
        )
        write_identity_run(Path(args.out), run, plan)
        print(
            f"LUREIDENTITY RUN CREATED: {len(run['event_observations'])} event and "
            f"{len(run['access_observations'])} access observations — {args.out}\n"
            "boundary: offline reference decisions only; no identity or authorization action"
        )
        return 0
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _cmd_identity_otel_project(args: argparse.Namespace) -> int:
    try:
        from .identity import load_identity_plan
        from .identity_otel import (
            load_identity_otel_log_export,
            project_identity_otel_run,
            write_identity_otel_projection_and_run,
        )

        plan = load_identity_plan(Path(args.plan))
        export = load_identity_otel_log_export(Path(args.logs), plan)
        projection = project_identity_otel_run(plan, export, run_id=args.run_id)
        write_identity_otel_projection_and_run(
            Path(args.out), Path(args.run_out), projection
        )
        print(
            f"LUREIDENTITY OTEL PROJECTED: {len(export['records'])} records, "
            f"{len(projection['run']['event_observations'])} lifecycle observations, "
            f"{len(projection['run']['access_observations'])} access observations — "
            f"{args.out}\n"
            "boundary: strict body-free log-model projection; not raw OTLP, authenticity, "
            "completeness, or enforcement proof"
        )
        return 0
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _cmd_identity_otel_verify(args: argparse.Namespace) -> int:
    try:
        from .identity_otel import load_identity_otel_projection

        projection = load_identity_otel_projection(Path(args.projection))
        print(
            f"LUREIDENTITY OTEL VERIFIED: {len(projection['inputs']['otel_log_export']['records'])} "
            f"records — {args.projection}\n"
            "boundary: projection semantics and exact bytes only; no telemetry completeness, "
            "clock, causality, or enforcement claim"
        )
        return 0
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _cmd_identity_eval(args: argparse.Namespace) -> int:
    try:
        from .identity import (
            evaluate_identity_run,
            load_identity_plan,
            load_identity_run,
            reference_identity_run,
            write_identity_evaluation,
        )

        plan = load_identity_plan(Path(args.plan) if args.plan else None)
        run = load_identity_run(Path(args.run), plan) if args.run else reference_identity_run(plan)
        report = evaluate_identity_run(plan, run)
        if args.out:
            write_identity_evaluation(Path(args.out), report)
        if args.json:
            print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
        else:
            summary = report["summary"]
            destination = f" — {args.out}" if args.out else ""
            print(
                f"LUREIDENTITY: {summary['verdict'].upper()} — "
                f"cut={summary['affected_authorization_count']} "
                f"recall={summary['cut_recall']:.3f} "
                f"preserved={summary['preserved_allow_rate']:.3f} "
                f"coverage={summary['delivery_coverage_rate']:.3f} "
                f"p95={summary['p95_convergence_ms']}ms{destination}"
            )
            print(
                "boundary: graph-closure evidence only; no identity authenticity, mediation, "
                "or compliance claim"
            )
        return 0 if report["summary"]["verdict"] == "pass" else 1
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _cmd_identity_topology_audit(args: argparse.Namespace) -> int:
    try:
        from .identity import load_identity_plan
        from .identity_topology import (
            audit_identity_topology,
            write_identity_topology_audit,
        )
        from .runtime import load_runtime_profile

        plan = load_identity_plan(Path(args.plan) if args.plan else None)
        profile = load_runtime_profile(Path(args.profile) if args.profile else None)
        report = audit_identity_topology(plan, profile)
        if args.out:
            write_identity_topology_audit(Path(args.out), report)
        if args.json:
            print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
        else:
            summary = report["summary"]
            destination = f" — {args.out}" if args.out else ""
            print(
                f"LUREIDENTITY TOPOLOGY: {summary['verdict'].upper()} — "
                f"coverage={summary['covered_enforcement_point_count']}/"
                f"{summary['required_enforcement_point_count']} "
                f"unmapped={summary['unmapped_node_count']} "
                f"untrusted-workloads={summary['untrusted_workload_identity_count']}"
                f"{destination}"
            )
            print(
                "boundary: declared topology and trust-domain comparison only; "
                "no discovery, SVID, delivery, or enforcement claim"
            )
        return 0 if report["summary"]["verdict"] == "pass" else 1
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _cmd_revocation_topology_audit(args: argparse.Namespace) -> int:
    try:
        from .revocation import load_revocation_plan
        from .revocation_topology import (
            audit_revocation_topology,
            write_revocation_topology_audit,
        )
        from .runtime import load_runtime_profile

        plan = load_revocation_plan(Path(args.plan) if args.plan else None)
        profile = load_runtime_profile(Path(args.profile) if args.profile else None)
        report = audit_revocation_topology(plan, profile)
        if args.out:
            write_revocation_topology_audit(Path(args.out), report)
        if args.json:
            print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
        else:
            summary = report["summary"]
            destination = f" — {args.out}" if args.out else ""
            print(
                f"LUREREVOKE TOPOLOGY: {summary['verdict'].upper()} — "
                f"coverage={summary['covered_mediation_point_count']}/"
                f"{summary['required_mediation_point_count']} "
                f"missing={summary['missing_mediation_point_count']} "
                f"unmapped={summary['unmapped_node_count']}{destination}"
            )
            print("boundary: declared topology comparison only; no discovery or delivery claim")
        return 0 if report["summary"]["verdict"] == "pass" else 1
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _cmd_stateful_range_export(args: argparse.Namespace) -> int:
    try:
        from .runtime import default_stateful_range_suite, write_stateful_range_suite

        suite = default_stateful_range_suite()
        write_stateful_range_suite(Path(args.out), suite)
        steps = sum(len(item["steps"]) for item in suite["trajectories"])
        print(
            f"STATEFUL LURERANGE EXPORTED: {len(suite['trajectories'])} trajectories, "
            f"{steps} steps — {args.out}\n"
            "boundary: deterministic synthetic metadata only; no live target or exploit"
        )
        return 0
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _cmd_stateful_range_eval(args: argparse.Namespace) -> int:
    try:
        from .runtime import (
            load_stateful_range_suite,
            run_stateful_range_evaluation,
            write_stateful_range_evaluation,
        )

        suite = load_stateful_range_suite(Path(args.suite) if args.suite else None)
        report = run_stateful_range_evaluation(
            suite,
            engine_id=args.engine_id,
            engine_version=args.engine_version,
            engine_artifact_sha256=args.engine_artifact_sha256,
        )
        if args.out:
            write_stateful_range_evaluation(Path(args.out), report)
        if args.json:
            print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
        else:
            summary = report["summary"]
            destination = f" — {args.out}" if args.out else ""
            print(
                f"STATEFUL LURERANGE: {summary['verdict'].upper()} — "
                f"trajectories={summary['passed_trajectories']}/"
                f"{summary['total_trajectories']} steps={summary['correct_steps']}/"
                f"{summary['total_steps']}{destination}"
            )
            print("boundary: offline conformance only; no agent action was executed")
        return 0 if report["summary"]["verdict"] == "pass" else 1
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _cmd_permit_serve(args: argparse.Namespace) -> int:
    try:
        from .runtime_service import serve_runtime

        if args.unix_socket and (args.host != "127.0.0.1" or args.port != 8765):
            raise ValueError("--unix-socket cannot be combined with --host or --port")
        endpoint = (
            f"unix:{args.unix_socket}" if args.unix_socket else f"http://{args.host}:{args.port}"
        )
        print(f"LUREPERMIT RUNTIME READY: {endpoint}")
        print("boundary: decision service only; it never executes or proxies an action")
        serve_runtime(
            profile_path=Path(args.profile) if args.profile else None,
            host=args.host,
            port=args.port,
            unix_socket=Path(args.unix_socket) if args.unix_socket else None,
            receipt_log=Path(args.receipt_log) if args.receipt_log else None,
        )
        return 0
    except KeyboardInterrupt:
        return 0
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 2


def _sha256_regular_file(path: Path) -> str:
    if path.is_symlink():
        raise ValueError(f"refusing symbolic-link dataset: {path}")
    if not path.is_file():
        raise FileNotFoundError(path)
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _cmd_container_eval(args: argparse.Namespace) -> int:
    from .detectors.container import PROTOCOL, ContainerDetector

    detector = None
    try:
        dataset_path = Path(args.dataset)
        dataset_digest = _sha256_regular_file(dataset_path)
        dataset = load_jsonl(args.dataset)
        if not dataset:
            raise ValueError("dataset must contain at least one record")
        if not math.isfinite(args.threshold) or not 0 <= args.threshold <= 1:
            raise ValueError("threshold must be finite and between zero and one")
        detector = ContainerDetector(
            args.image,
            task=args.task,
            runtime=args.runtime,
            timeout_seconds=args.timeout,
            memory=args.memory,
            cpus=args.cpus,
            allow_mutable_image=args.allow_mutable_image,
        )
        report = run(detector, dataset, threshold=args.threshold, task=args.task)
        payload = {
            "schema": ("https://github.com/immu4989/lurebench/spec/container-evaluation/v1"),
            "schema_version": 1,
            "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "protocol": PROTOCOL,
            "runtime": args.runtime,
            "image_reference": args.image,
            "image_id": detector.image_id,
            "mutable_reference_allowed": bool(args.allow_mutable_image),
            "isolation": {
                "network": "none",
                "read_only_root": True,
                "capabilities_dropped": "ALL",
                "no_new_privileges": True,
                "host_mounts": False,
                "memory": detector.memory,
                "cpus": detector.cpus,
            },
            "dataset": {
                "sha256": dataset_digest,
                "record_count": len(dataset),
                "ground_truth_transmitted": False,
                "original_record_ids_transmitted": False,
            },
            "evaluation": {
                "task": args.task,
                "threshold": args.threshold,
                "n_skipped": report.n_skipped,
                "metrics": report.metrics.as_dict(),
            },
            "limitations": [
                "container_isolation_depends_on_the_local_runtime_and_kernel",
                "image_id_records_content_but_does_not_identify_the_vendor",
                "benchmark_results_do_not_establish_deployment_performance",
            ],
        }
        rendered = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        if args.out:
            _write_new_private(args.out, rendered)
            print(
                f"wrote {args.out} — image={detector.image_id} "
                f"MCC={report.metrics.mcc:+.3f} TPR={report.metrics.recall:.3f} "
                f"FPR={report.metrics.fpr:.3f}"
            )
        else:
            print(rendered, end="")
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 1
    finally:
        if detector is not None:
            detector.close()
    return 0


def _cmd_assemble_core_v2(args: argparse.Namespace) -> int:
    weights = {
        "train": args.train_weight,
        "validation": args.validation_weight,
        "test": args.test_weight,
        "heldout": args.heldout_weight,
    }
    try:
        build = build_core_v2(
            args.source,
            threshold=args.near_duplicate_threshold,
            shingle_size=args.shingle_size,
            weights=weights,
        )
        paths = write_core_v2(build, args.out, args.heldout_out)
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"! {exc}", file=sys.stderr)
        return 1
    print(
        f"wrote core v2 — {build.n} records in {build.cluster_count} leakage-bound "
        f"clusters; audit=pass; heldout={paths['heldout']} (private, mode 0600)"
    )
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
    p_eval.add_argument(
        "--bootstrap",
        type=int,
        default=0,
        help="paired bootstrap replicates for MCC/TPR/FPR/AUC intervals",
    )
    p_eval.add_argument(
        "--confidence", type=float, default=0.95, help="confidence level used with --bootstrap"
    )
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
    p_lb.add_argument(
        "--detector",
        "-m",
        action="append",
        help="detector spec (repeatable); default: all. Accepts a plain "
        "name or name@engine/model, e.g. "
        "'llm-judge@openrouter/openai/gpt-5-nano', so one run can "
        "score several models",
    )
    p_lb.add_argument(
        "--cache-dir",
        default=None,
        help="cache detector scores here and pre-warm them concurrently; "
        "makes API-backed detectors practical and reruns free",
    )
    p_lb.add_argument(
        "--workers",
        type=int,
        default=8,
        help="concurrent requests when pre-warming (with --cache-dir)",
    )
    p_lb.add_argument("--threshold", type=float, default=0.5)
    p_lb.add_argument(
        "--task",
        "-t",
        choices=["fraud", "provenance"],
        default=None,
        help="override each detector's task (score any dataset on either question)",
    )
    p_lb.add_argument("--out", "-o", default=None, help="write Markdown here (else stdout)")
    p_lb.add_argument("--json", default=None, help="also write results JSON here")
    p_lb.set_defaults(func=_cmd_leaderboard)

    p_cg = sub.add_parser(
        "cross-generator", help="leave-one-generator-out provenance (the headline finding)"
    )
    p_cg.add_argument(
        "--dataset",
        "-d",
        action="append",
        required=True,
        help="JSONL with human + multi-generator AI records (repeatable)",
    )
    p_cg.add_argument("--threshold", type=float, default=0.5)
    p_cg.add_argument("--out", "-o", default=None, help="write Markdown here (else stdout)")
    p_cg.set_defaults(func=_cmd_cross_generator)

    p_rob = sub.add_parser(
        "robustness",
        help="adversarial robustness: how many caught lures evade after an attack",
    )
    p_rob.add_argument("--dataset", "-d", required=True, help="path to a JSONL dataset")
    p_rob.add_argument("--detector", "-m", required=True, help="detector to stress-test")
    p_rob.add_argument(
        "--attack",
        "-a",
        action="append",
        required=True,
        help=f"attack to apply (repeatable). available: {', '.join(attacks_available())}",
    )
    p_rob.add_argument("--task", "-t", choices=["fraud", "provenance"], default="fraud")
    p_rob.add_argument("--threshold", type=float, default=0.5)
    p_rob.add_argument(
        "--engine", default=None, help="provider engine for llm-* attacks (e.g. deepseek, mistral)"
    )
    p_rob.add_argument("--model", default=None, help="provider model id for llm-* attacks")
    p_rob.add_argument("--out", "-o", default=None, help="write Markdown here (else stdout)")
    p_rob.add_argument("--json", action="store_true", help="emit JSON instead of Markdown")
    p_rob.set_defaults(func=_cmd_robustness)

    p_ml = sub.add_parser(
        "multilingual",
        help="per-language detection recall (the cross-lingual deployment gap)",
    )
    p_ml.add_argument("--dataset", "-d", required=True, help="path to a JSONL dataset")
    p_ml.add_argument(
        "--detector",
        "-m",
        action="append",
        help="detector to evaluate (repeatable; default tfidf-logreg)",
    )
    p_ml.add_argument("--threshold", type=float, default=0.5)
    p_ml.add_argument(
        "--raw",
        action="store_true",
        help="show raw recall only (default shows raw vs artifact-controlled)",
    )
    p_ml.add_argument("--out", "-o", default=None, help="write Markdown here (else stdout)")
    p_ml.set_defaults(func=_cmd_multilingual)

    p_stix = sub.add_parser(
        "stix",
        help="export the taxonomy and/or a dataset as a STIX 2.1 bundle (threat-intel interop)",
    )
    p_stix.add_argument("--dataset", "-d", default=None, help="path to a JSONL dataset")
    p_stix.add_argument(
        "--taxonomy-only",
        action="store_true",
        help="export just the taxonomy (attack-patterns + crosswalks)",
    )
    p_stix.add_argument(
        "--include-benign", action="store_true", help="also emit indicators for benign records"
    )
    p_stix.add_argument("--out", "-o", default=None, help="write the bundle here (else stdout)")
    p_stix.set_defaults(func=_cmd_stix)

    p_verify_receipt = sub.add_parser(
        "verify-receipt",
        help="strictly verify a LureEval receipt or compatible aggregate",
    )
    p_verify_receipt.add_argument("artifact", help="receipt, aggregate, or DSSE JSON")
    p_verify_receipt.add_argument("--public-key", help="trusted ECDSA P-256 public PEM")
    p_verify_receipt.add_argument(
        "--require-signature",
        action="store_true",
        help="reject unsigned or unauthenticated artifacts",
    )
    p_verify_receipt.set_defaults(func=_cmd_verify_receipt)

    p_aggregate = sub.add_parser(
        "aggregate-receipts",
        help="pool only compatible privacy-minimized LureEval receipts",
    )
    p_aggregate.add_argument(
        "--receipt", "-r", action="append", required=True, help="source receipt (repeatable)"
    )
    p_aggregate.add_argument("--out", "-o", required=True, help="new aggregate JSON path")
    p_aggregate.add_argument("--issuer", help="optional issuer label")
    p_aggregate.add_argument(
        "--source-key",
        action="append",
        help="RECEIPT=PUBLIC_KEY mapping for a signed source (repeatable)",
    )
    p_aggregate.add_argument(
        "--require-source-signatures",
        action="store_true",
        help="require every receipt to authenticate with its mapped trusted key",
    )
    p_aggregate.add_argument(
        "--signing-key", help="optional ECDSA P-256 private PEM for the aggregate"
    )
    p_aggregate.set_defaults(func=_cmd_aggregate_receipts)

    p_conformance = sub.add_parser(
        "conformance",
        help="run the deterministic LureEval v1 semantic conformance suite",
    )
    p_conformance.add_argument(
        "--suite",
        help="optional external suite directory; defaults to the packaged reviewed vectors",
    )
    p_conformance.add_argument("--out", "-o", help="new mode-0600 JSON report path")
    p_conformance.add_argument("--json", action="store_true", help="also print JSON to stdout")
    p_conformance.set_defaults(func=_cmd_conformance)

    p_boundary = sub.add_parser(
        "boundary-eval",
        help="evaluate an agent-boundary monitor on safe incident-derived trajectories",
    )
    p_boundary.add_argument(
        "--suite",
        help="optional suite JSON or directory; defaults to the packaged reviewed suite",
    )
    p_boundary.add_argument(
        "--image",
        help="optional local OCI monitor image pinned as name@sha256:<digest>",
    )
    p_boundary.add_argument("--runtime", choices=["docker", "podman"], default="docker")
    p_boundary.add_argument("--timeout", type=float, default=10.0)
    p_boundary.add_argument("--memory", default="256m")
    p_boundary.add_argument("--cpus", type=float, default=1.0)
    p_boundary.add_argument("--monitor-id", default="oci-boundary-monitor")
    p_boundary.add_argument("--monitor-version", default="1.0.0")
    p_boundary.add_argument(
        "--allow-mutable-image",
        action="store_true",
        help="development only; immutable runtime image id is still recorded",
    )
    p_boundary.add_argument(
        "--container-report",
        help="new mode-0600 OCI protocol/isolation report; requires --image",
    )
    p_boundary.add_argument("--out", "-o", help="new mode-0600 evaluation JSON path")
    p_boundary.add_argument("--json", action="store_true", help="also print JSON to stdout")
    p_boundary.set_defaults(func=_cmd_boundary_eval)

    p_coverage_canaries = sub.add_parser(
        "coverage-canaries",
        help="create payload-free canary descriptors from a coverage manifest",
    )
    p_coverage_canaries.add_argument("--manifest", required=True)
    p_coverage_canaries.add_argument("--replicates", type=int, default=1)
    p_coverage_canaries.add_argument("--out", "-o", required=True)
    p_coverage_canaries.set_defaults(func=_cmd_coverage_canaries)

    p_coverage_eval = sub.add_parser(
        "coverage-eval",
        help="measure telemetry delivery, duplication, ordering, latency, and lineage",
    )
    p_coverage_eval.add_argument("--manifest", required=True)
    p_coverage_eval.add_argument("--canaries", required=True)
    p_coverage_eval.add_argument("--observations", required=True)
    p_coverage_eval.add_argument("--out", "-o", required=True)
    p_coverage_eval.set_defaults(func=_cmd_coverage_eval)

    p_delegation = sub.add_parser(
        "delegation-eval",
        help="evaluate identity, capability, and delegation-chain controls",
    )
    p_delegation.add_argument("--out", "-o")
    p_delegation.add_argument("--json", action="store_true")
    p_delegation.set_defaults(func=_cmd_delegation_eval)

    p_ir_tasks = sub.add_parser(
        "ir-tasks", help="export the responder-visible defanged LureIR task set"
    )
    p_ir_tasks.add_argument("--out", "-o", required=True)
    p_ir_tasks.set_defaults(func=_cmd_ir_tasks)

    p_ir_eval = sub.add_parser(
        "ir-eval", help="score structured incident-response readiness submissions"
    )
    p_ir_eval.add_argument("--responses", required=True)
    p_ir_eval.add_argument("--responder-id", required=True)
    p_ir_eval.add_argument("--responder-version", required=True)
    p_ir_eval.add_argument("--out", "-o", required=True)
    p_ir_eval.set_defaults(func=_cmd_ir_eval)

    p_invariant = sub.add_parser(
        "invariant-eval",
        help="evaluate declared graph reachability and bounded response invariants",
    )
    p_invariant.add_argument("--plan", required=True)
    p_invariant.add_argument("--observations", required=True)
    p_invariant.add_argument("--out", "-o")
    p_invariant.add_argument("--json", action="store_true")
    p_invariant.set_defaults(func=_cmd_invariant_eval)

    p_permit = sub.add_parser(
        "permit-init",
        help="write the reviewed deny-by-default LurePermit v1 contract",
    )
    p_permit.add_argument("--out", "-o", required=True, help="new mode-0600 permit JSON path")
    p_permit.set_defaults(func=_cmd_permit_init)

    p_range_export = sub.add_parser(
        "range-export",
        help="write the reviewed offline LureRange v1 scenario suite",
    )
    p_range_export.add_argument("--out", "-o", required=True, help="new mode-0600 suite JSON path")
    p_range_export.set_defaults(func=_cmd_range_export)

    p_range = sub.add_parser(
        "range-eval",
        help="evaluate an agent permit engine on safe offline control scenarios",
    )
    p_range.add_argument("--permit", help="LurePermit JSON; defaults to the reviewed reference")
    p_range.add_argument("--suite", help="LureRange JSON; defaults to the reviewed reference")
    p_range.add_argument("--engine-id", default="lurepermit-reference")
    p_range.add_argument("--engine-version", default="1.0.0")
    p_range.add_argument("--engine-artifact-sha256")
    p_range.add_argument("--out", "-o", help="new mode-0600 evaluation JSON path")
    p_range.add_argument("--json", action="store_true", help="also print JSON to stdout")
    p_range.set_defaults(func=_cmd_range_eval)

    p_runtime_init = sub.add_parser(
        "runtime-init",
        help="write the reviewed LurePermit runtime authorization profile",
    )
    p_runtime_init.add_argument(
        "--out", "-o", required=True, help="new mode-0600 runtime profile JSON"
    )
    p_runtime_init.set_defaults(func=_cmd_runtime_init)

    p_runtime_trace = sub.add_parser(
        "runtime-trace",
        help="write a healthy synthetic receipt and sensor trace",
    )
    p_runtime_trace.add_argument(
        "--out", "-o", required=True, help="new mode-0600 runtime trace JSON"
    )
    p_runtime_trace.set_defaults(func=_cmd_runtime_trace)

    p_runtime_eval = sub.add_parser(
        "runtime-eval",
        help="reconcile runtime decisions against independently registered sensors",
    )
    p_runtime_eval.add_argument("--trace", help="runtime trace; defaults to the healthy reference")
    p_runtime_eval.add_argument("--out", "-o", help="new mode-0600 runtime evaluation JSON")
    p_runtime_eval.add_argument("--json", action="store_true", help="also print JSON to stdout")
    p_runtime_eval.set_defaults(func=_cmd_runtime_eval)

    p_revocation_export = sub.add_parser(
        "revocation-export",
        help="write a CAEP-shaped distributed revocation convergence plan",
    )
    p_revocation_export.add_argument(
        "--out", "-o", required=True, help="new mode-0600 LureRevoke plan JSON"
    )
    p_revocation_export.set_defaults(func=_cmd_revocation_export)

    p_revocation_compose = sub.add_parser(
        "revocation-compose",
        help="compose a strict plan from projected CAEP events and a declared topology",
    )
    p_revocation_compose.add_argument("--campaign", required=True)
    p_revocation_compose.add_argument(
        "--out", "-o", required=True, help="new mode-0600 LureRevoke plan JSON"
    )
    p_revocation_compose.set_defaults(func=_cmd_revocation_compose)

    p_revocation_run = sub.add_parser(
        "revocation-run",
        help="create deterministic receiver observations for a revocation plan",
    )
    p_revocation_run.add_argument("--plan", help="LureRevoke plan; defaults to the reference")
    p_revocation_run.add_argument("--run-id", default="lurerevoke-reference-run")
    p_revocation_run.add_argument("--engine-id", default="lurerevoke-reference")
    p_revocation_run.add_argument("--engine-version", default="1.0.0")
    p_revocation_run.add_argument("--engine-artifact-sha256")
    p_revocation_run.add_argument(
        "--out", "-o", required=True, help="new mode-0600 receiver observation JSON"
    )
    p_revocation_run.set_defaults(func=_cmd_revocation_run)

    p_revocation_otel = sub.add_parser(
        "revocation-otel-project",
        help="project strict body-free OpenTelemetry log records into a bound revocation run",
    )
    p_revocation_otel.add_argument("--plan", required=True)
    p_revocation_otel.add_argument("--logs", required=True)
    p_revocation_otel.add_argument("--run-id", required=True)
    p_revocation_otel.add_argument("--out", "-o", required=True, help="new projection JSON")
    p_revocation_otel.add_argument("--run-out", required=True, help="new LureRevoke run JSON")
    p_revocation_otel.set_defaults(func=_cmd_revocation_otel_project)

    p_revocation_otel_verify = sub.add_parser(
        "revocation-otel-verify",
        help="independently recompute a saved OpenTelemetry revocation projection",
    )
    p_revocation_otel_verify.add_argument("projection")
    p_revocation_otel_verify.set_defaults(func=_cmd_revocation_otel_verify)

    p_revocation_eval = sub.add_parser(
        "revocation-eval",
        help="measure revocation delivery coverage, convergence, bypass, and collateral denial",
    )
    p_revocation_eval.add_argument("--plan", help="LureRevoke plan; defaults to the reference")
    p_revocation_eval.add_argument("--run", help="receiver observations; defaults to reference")
    p_revocation_eval.add_argument("--out", "-o", help="new mode-0600 evaluation JSON")
    p_revocation_eval.add_argument("--json", action="store_true")
    p_revocation_eval.set_defaults(func=_cmd_revocation_eval)

    p_identity_export = sub.add_parser(
        "identity-export",
        help="write an identity-lifecycle authorization-closure plan",
    )
    p_identity_export.add_argument(
        "--out", "-o", required=True, help="new mode-0600 LureIdentity plan JSON"
    )
    p_identity_export.set_defaults(func=_cmd_identity_export)

    p_identity_compose = sub.add_parser(
        "identity-compose",
        help="derive exhaustive graph cuts, controls, and probes from an identity campaign",
    )
    p_identity_compose.add_argument("--campaign", required=True)
    p_identity_compose.add_argument(
        "--out", "-o", required=True, help="new mode-0600 LureIdentity plan JSON"
    )
    p_identity_compose.set_defaults(func=_cmd_identity_compose)

    p_artifact_compose = sub.add_parser(
        "artifact-compose",
        help="compile complete workload-to-artifact bindings from an identity plan",
    )
    p_artifact_compose.add_argument("--identity-plan", required=True)
    p_artifact_compose.add_argument("--campaign", required=True)
    p_artifact_compose.add_argument(
        "--out", "-o", required=True, help="new mode-0600 LureArtifact plan JSON"
    )
    p_artifact_compose.set_defaults(func=_cmd_artifact_compose)

    p_artifact_observe = sub.add_parser(
        "artifact-observe",
        help="create a deterministic claimed-inventory fixture for a LureArtifact plan",
    )
    p_artifact_observe.add_argument("--plan", required=True)
    p_artifact_observe.add_argument(
        "--observation-id", default="lureartifact-reference-observation"
    )
    p_artifact_observe.add_argument("--captured-at")
    p_artifact_observe.add_argument(
        "--out", "-o", required=True, help="new mode-0600 observation JSON"
    )
    p_artifact_observe.set_defaults(func=_cmd_artifact_observe)

    p_artifact_eval = sub.add_parser(
        "artifact-eval",
        help="compare claimed deployment inventory with exact authorized artifact bindings",
    )
    p_artifact_eval.add_argument("--plan", required=True)
    p_artifact_eval.add_argument("--observation", required=True)
    p_artifact_eval.add_argument("--generated-at")
    p_artifact_eval.add_argument("--out", "-o", help="new mode-0600 evaluation JSON")
    p_artifact_eval.add_argument("--json", action="store_true")
    p_artifact_eval.set_defaults(func=_cmd_artifact_eval)

    p_artifact_verify = sub.add_parser(
        "artifact-verify",
        help="strictly parse and recompute a saved LureArtifact evaluation",
    )
    p_artifact_verify.add_argument("evaluation")
    p_artifact_verify.set_defaults(func=_cmd_artifact_verify)

    p_bom_reconcile = sub.add_parser(
        "bom-reconcile",
        help="compare exact CycloneDX 1.7 and SPDX 3.0.1 AI-BOM projections",
    )
    p_bom_reconcile.add_argument("--artifact-plan", required=True)
    p_bom_reconcile.add_argument("--manifest", required=True)
    p_bom_reconcile.add_argument("--cyclonedx", required=True)
    p_bom_reconcile.add_argument("--spdx", required=True)
    p_bom_reconcile.add_argument("--evaluated-at")
    p_bom_reconcile.add_argument(
        "--out", "-o", required=True, help="new mode-0600 LureBOM evaluation JSON"
    )
    p_bom_reconcile.add_argument("--json", action="store_true")
    p_bom_reconcile.set_defaults(func=_cmd_bom_reconcile)

    p_bom_verify = sub.add_parser(
        "bom-verify",
        help="strictly parse and recompute a saved LureBOM Twin evaluation",
    )
    p_bom_verify.add_argument("evaluation")
    p_bom_verify.set_defaults(func=_cmd_bom_verify)

    p_channel_eval = sub.add_parser(
        "channel-eval",
        help="evaluate canary flows across declared agent-run isolation boundaries",
    )
    p_channel_eval.add_argument("--plan", required=True)
    p_channel_eval.add_argument("--run", required=True)
    p_channel_eval.add_argument("--evaluated-at")
    p_channel_eval.add_argument(
        "--out", "-o", required=True, help="new mode-0600 LureChannel evaluation JSON"
    )
    p_channel_eval.add_argument("--json", action="store_true")
    p_channel_eval.set_defaults(func=_cmd_channel_eval)

    p_channel_verify = sub.add_parser(
        "channel-verify",
        help="strictly parse and recompute a saved LureChannel evaluation",
    )
    p_channel_verify.add_argument("evaluation")
    p_channel_verify.set_defaults(func=_cmd_channel_verify)

    p_recall_compose = sub.add_parser(
        "recall-compose",
        help="derive transitive artifact blast radius, replacements, and response probes",
    )
    p_recall_compose.add_argument("--artifact-plan", required=True)
    p_recall_compose.add_argument("--lineage", required=True)
    p_recall_compose.add_argument("--advisory", required=True)
    p_recall_compose.add_argument(
        "--out", "-o", required=True, help="new mode-0600 LureRecall plan JSON"
    )
    p_recall_compose.set_defaults(func=_cmd_recall_compose)

    p_recall_run = sub.add_parser(
        "recall-run",
        help="create deterministic advisory-delivery, quarantine, and recovery observations",
    )
    p_recall_run.add_argument("--plan", required=True)
    p_recall_run.add_argument("--run-id", default="lurerecall-reference-run")
    p_recall_run.add_argument("--generated-at")
    p_recall_run.add_argument("--engine-id", default="reference-recall-controller")
    p_recall_run.add_argument("--engine-version", default="1.0.0")
    p_recall_run.add_argument("--engine-artifact-sha256")
    p_recall_run.add_argument(
        "--out", "-o", required=True, help="new mode-0600 LureRecall run JSON"
    )
    p_recall_run.set_defaults(func=_cmd_recall_run)

    p_recall_eval = sub.add_parser(
        "recall-eval",
        help="measure transitive artifact quarantine, recovery, and collateral disruption",
    )
    p_recall_eval.add_argument("--plan", required=True)
    p_recall_eval.add_argument("--run", required=True)
    p_recall_eval.add_argument("--generated-at")
    p_recall_eval.add_argument("--out", "-o", help="new mode-0600 evaluation JSON")
    p_recall_eval.add_argument("--json", action="store_true")
    p_recall_eval.set_defaults(func=_cmd_recall_eval)

    p_recall_verify = sub.add_parser(
        "recall-verify",
        help="strictly parse and independently recompute a saved LureRecall evaluation",
    )
    p_recall_verify.add_argument("evaluation")
    p_recall_verify.set_defaults(func=_cmd_recall_verify)

    p_attest_compose = sub.add_parser(
        "attest-compose",
        help="bind SLSA claims to reviewed signer, builder, source, and parameter expectations",
    )
    p_attest_compose.add_argument("--artifact-plan", required=True)
    p_attest_compose.add_argument("--policy", required=True)
    p_attest_compose.add_argument(
        "--out", "-o", required=True, help="new mode-0600 LureAttest plan JSON"
    )
    p_attest_compose.set_defaults(func=_cmd_attest_compose)

    p_attest_verify = sub.add_parser(
        "attest-verify", help="strictly parse a saved LureAttest expectation plan"
    )
    p_attest_verify.add_argument("plan")
    p_attest_verify.set_defaults(func=_cmd_attest_verify)

    p_identity_run = sub.add_parser(
        "identity-run",
        help="create deterministic event and access observations for an identity plan",
    )
    p_identity_run.add_argument("--plan", help="LureIdentity plan; defaults to the reference")
    p_identity_run.add_argument("--run-id", default="lureidentity-reference-run")
    p_identity_run.add_argument("--engine-id", default="lureidentity-reference")
    p_identity_run.add_argument("--engine-version", default="1.0.0")
    p_identity_run.add_argument("--engine-artifact-sha256")
    p_identity_run.add_argument(
        "--out", "-o", required=True, help="new mode-0600 identity observation JSON"
    )
    p_identity_run.set_defaults(func=_cmd_identity_run)

    p_identity_otel = sub.add_parser(
        "identity-otel-project",
        help="project strict body-free OpenTelemetry events into a bound identity run",
    )
    p_identity_otel.add_argument("--plan", required=True)
    p_identity_otel.add_argument("--logs", required=True)
    p_identity_otel.add_argument("--run-id", required=True)
    p_identity_otel.add_argument("--out", "-o", required=True, help="new projection JSON")
    p_identity_otel.add_argument("--run-out", required=True, help="new LureIdentity run JSON")
    p_identity_otel.set_defaults(func=_cmd_identity_otel_project)

    p_identity_otel_verify = sub.add_parser(
        "identity-otel-verify",
        help="independently recompute a saved OpenTelemetry identity projection",
    )
    p_identity_otel_verify.add_argument("projection")
    p_identity_otel_verify.set_defaults(func=_cmd_identity_otel_verify)

    p_identity_eval = sub.add_parser(
        "identity-eval",
        help="measure lifecycle graph closure, convergence, stale access, and collateral denial",
    )
    p_identity_eval.add_argument("--plan", help="LureIdentity plan; defaults to the reference")
    p_identity_eval.add_argument("--run", help="receiver observations; defaults to reference")
    p_identity_eval.add_argument("--out", "-o", help="new mode-0600 identity evaluation JSON")
    p_identity_eval.add_argument("--json", action="store_true")
    p_identity_eval.set_defaults(func=_cmd_identity_eval)

    p_identity_topology = sub.add_parser(
        "identity-topology-audit",
        help="cross-check identity nodes and workload trust domains against runtime",
    )
    p_identity_topology.add_argument("--plan", help="defaults to the identity reference plan")
    p_identity_topology.add_argument("--profile", help="defaults to the runtime reference")
    p_identity_topology.add_argument("--out", "-o", help="new mode-0600 audit JSON")
    p_identity_topology.add_argument("--json", action="store_true")
    p_identity_topology.set_defaults(func=_cmd_identity_topology_audit)

    p_revocation_topology = sub.add_parser(
        "revocation-topology-audit",
        help="cross-check revocation nodes against every runtime mediation point",
    )
    p_revocation_topology.add_argument("--plan", help="defaults to the reference plan")
    p_revocation_topology.add_argument("--profile", help="defaults to the runtime reference")
    p_revocation_topology.add_argument("--out", "-o", help="new mode-0600 audit JSON")
    p_revocation_topology.add_argument("--json", action="store_true")
    p_revocation_topology.set_defaults(func=_cmd_revocation_topology_audit)

    p_stateful_export = sub.add_parser(
        "stateful-range-export",
        help="write long-task and multi-agent containment trajectories",
    )
    p_stateful_export.add_argument(
        "--out", "-o", required=True, help="new mode-0600 stateful suite JSON"
    )
    p_stateful_export.set_defaults(func=_cmd_stateful_range_export)

    p_stateful_eval = sub.add_parser(
        "stateful-range-eval",
        help="evaluate a runtime policy engine over stateful containment trajectories",
    )
    p_stateful_eval.add_argument("--suite", help="stateful suite; defaults to the reference")
    p_stateful_eval.add_argument("--engine-id", default="lurepermit-runtime-reference")
    p_stateful_eval.add_argument("--engine-version", default="1.0.0")
    p_stateful_eval.add_argument("--engine-artifact-sha256")
    p_stateful_eval.add_argument("--out", "-o", help="new mode-0600 stateful evaluation JSON")
    p_stateful_eval.add_argument("--json", action="store_true", help="also print JSON to stdout")
    p_stateful_eval.set_defaults(func=_cmd_stateful_range_eval)

    p_permit_serve = sub.add_parser(
        "permit-serve",
        help="serve the metadata-only policy decision API on loopback or a Unix socket",
    )
    p_permit_serve.add_argument("--profile", help="runtime profile; defaults to the reference")
    p_permit_serve.add_argument("--host", default="127.0.0.1", help="explicit loopback IP")
    p_permit_serve.add_argument("--port", type=int, default=8765)
    p_permit_serve.add_argument("--unix-socket", help="new private Unix socket path")
    p_permit_serve.add_argument("--receipt-log", help="new append-only mode-0600 receipt JSONL")
    p_permit_serve.set_defaults(func=_cmd_permit_serve)

    p_container = sub.add_parser(
        "container-eval",
        help="evaluate an isolated language-independent detector container",
    )
    p_container.add_argument("--dataset", "-d", required=True, help="benchmark JSONL")
    p_container.add_argument(
        "--image", required=True, help="local image pinned as name@sha256:<digest>"
    )
    p_container.add_argument("--runtime", choices=["docker", "podman"], default="docker")
    p_container.add_argument("--task", choices=["fraud", "provenance"], default="fraud")
    p_container.add_argument("--threshold", type=float, default=0.5)
    p_container.add_argument("--timeout", type=float, default=10.0)
    p_container.add_argument("--memory", default="512m")
    p_container.add_argument("--cpus", type=float, default=1.0)
    p_container.add_argument(
        "--allow-mutable-image",
        action="store_true",
        help="permit a local tag for development; the immutable image id is still recorded",
    )
    p_container.add_argument("--out", "-o", help="new evaluation JSON path")
    p_container.set_defaults(func=_cmd_container_eval)

    p_man = sub.add_parser("manifest", help="print the composition manifest for a dataset")
    p_man.add_argument("--dataset", "-d", required=True, help="path to a JSONL dataset")
    p_man.set_defaults(func=_cmd_manifest)

    p_audit = sub.add_parser(
        "audit-splits", help="detect family overlap and near-duplicate text across splits"
    )
    p_audit.add_argument(
        "--split", "-s", action="append", required=True, help="name=path (repeatable)"
    )
    p_audit.add_argument(
        "--threshold", type=float, default=0.8, help="word-shingle Jaccard threshold (default: 0.8)"
    )
    p_audit.add_argument("--shingle-size", type=int, default=5)
    p_audit.add_argument("--out", "-o", default=None, help="write JSON report here")
    p_audit.add_argument(
        "--fail-on-leakage",
        action="store_true",
        help="exit non-zero when any cross-split leakage is found",
    )
    p_audit.set_defaults(func=_cmd_audit_splits)

    p_cal = sub.add_parser(
        "calibrate", help="select a decision threshold on validation data and export a policy"
    )
    p_cal.add_argument("--validation", "-d", required=True, help="validation JSONL")
    p_cal.add_argument("--detector", "-m", required=True)
    p_cal.add_argument(
        "--model-path",
        default=None,
        help="serialized model path for detectors such as tfidf-logreg",
    )
    p_cal.add_argument("--task", "-t", choices=["fraud", "provenance"], default="fraud")
    p_cal.add_argument(
        "--objective",
        choices=["max_mcc", "target_fpr", "risk_controlled_fpr"],
        default="max_mcc",
    )
    p_cal.add_argument("--target-fpr", type=float, default=None)
    p_cal.add_argument(
        "--confidence",
        type=float,
        default=0.95,
        help="confidence for risk_controlled_fpr (default: 0.95)",
    )
    p_cal.add_argument(
        "--threshold-grid-size",
        type=int,
        default=1001,
        help="predeclared [0,1] threshold grid for risk control (default: 1001)",
    )
    p_cal.add_argument("--bins", type=int, default=10)
    p_cal.add_argument("--out", "-o", required=True, help="versioned policy JSON")
    p_cal.set_defaults(func=_cmd_calibrate)

    p_train = sub.add_parser("train", help="train the tfidf-logreg baseline detector")
    p_train.add_argument(
        "--dataset", "-d", required=True, help="training JSONL (use the train split)"
    )
    p_train.add_argument(
        "--out", "-o", default="models/tfidf-logreg-fraud.joblib", help="model output path"
    )
    p_train.add_argument("--task", "-t", choices=["fraud", "provenance"], default="fraud")
    p_train.set_defaults(func=_cmd_train)

    p_pub = sub.add_parser("publish", help="assemble a Hub-ready dataset dir (and optionally push)")
    p_pub.add_argument(
        "--split", "-s", action="append", required=True, help="name=path (repeatable)"
    )
    p_pub.add_argument(
        "--repo", "-r", required=True, help="Hub dataset repo id, e.g. lurebench/core"
    )
    p_pub.add_argument("--out", "-o", required=True, help="local output directory to assemble into")
    p_pub.add_argument("--version", default="v1")
    p_pub.add_argument(
        "--push", action="store_true", help="upload to the Hub (needs 'hub' extra + auth)"
    )
    p_pub.add_argument(
        "--public", action="store_true", help="create a public repo (default: private)"
    )
    p_pub.set_defaults(func=_cmd_publish)

    p_gen = sub.add_parser(
        "generate", help="controlled generation of synthetic AI lures (review-pending)"
    )
    p_gen.add_argument(
        "--typology", "-t", required=True, choices=["phishing", "bec", "romance", "pig_butchering"]
    )
    p_gen.add_argument("--n", type=int, default=10, help="number of records to generate")
    p_gen.add_argument("--engine", "-e", default="template", help=f"one of {gen_available()}")
    p_gen.add_argument(
        "--model", default=None, help="model id (defaults per engine/provider preset)"
    )
    p_gen.add_argument(
        "--max-tokens",
        type=int,
        default=None,
        help="output token budget (raise for reasoning models, e.g. kimi)",
    )
    p_gen.add_argument("--base-url", default=None, help="required for engine 'openai-compat'")
    p_gen.add_argument(
        "--api-key-env", default=None, help="env var holding the provider key (openai-compat)"
    )
    p_gen.add_argument("--generator-id", default=None, help="provenance label stamped on records")
    p_gen.add_argument("--channel", default="email")
    p_gen.add_argument("--language", default="en")
    p_gen.add_argument("--persona", default=None, help="non-identifying scenario seed")
    p_gen.add_argument("--persuasion", action="append", help="persuasion tag (repeatable)")
    p_gen.add_argument(
        "--hard", action="store_true", help="subtler, more varied lures (no stock spam markers)"
    )
    p_gen.add_argument("--out", "-o", required=True, help="staging JSONL path (review-pending)")
    p_gen.set_defaults(func=_cmd_generate)

    p_core = sub.add_parser(
        "assemble-core", help="merge sourced + approved-generated shards into lurebench-core"
    )
    p_core.add_argument(
        "--source", "-s", action="append", required=True, help="input JSONL (repeatable)"
    )
    p_core.add_argument(
        "--out", "-o", required=True, help="output dir for train.jsonl / test.jsonl"
    )
    p_core.add_argument(
        "--test-modulus", type=int, default=10, help="1/N held out as the frozen test split"
    )
    p_core.add_argument(
        "--validation-modulus",
        type=int,
        default=10,
        help="1/N of the non-test pool held out for validation",
    )
    p_core.set_defaults(func=_cmd_assemble_core)

    p_core_v2 = sub.add_parser(
        "assemble-core-v2",
        help="build leakage-clustered public splits plus a separate private held-out split",
    )
    p_core_v2.add_argument(
        "--source", "-s", action="append", required=True, help="input JSONL (repeatable)"
    )
    p_core_v2.add_argument("--out", "-o", required=True, help="new/empty public output directory")
    p_core_v2.add_argument(
        "--heldout-out",
        required=True,
        help="private held-out JSONL outside --out; created mode 0600",
    )
    p_core_v2.add_argument("--near-duplicate-threshold", type=float, default=0.8)
    p_core_v2.add_argument("--shingle-size", type=int, default=5)
    p_core_v2.add_argument("--train-weight", type=float, default=0.7)
    p_core_v2.add_argument("--validation-weight", type=float, default=0.1)
    p_core_v2.add_argument("--test-weight", type=float, default=0.1)
    p_core_v2.add_argument("--heldout-weight", type=float, default=0.1)
    p_core_v2.set_defaults(func=_cmd_assemble_core_v2)

    return parser


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
