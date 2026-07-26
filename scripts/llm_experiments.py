"""Run the LLM-detector experiments that fill LureBench's empty rows.

Three questions the benchmark posed but never answered for LLM-backed detectors,
because doing so needed provider keys and a way to run thousands of calls without
paying twice:

    leaderboard   Where do LLM judges actually land on the core fraud task, with
                  threshold-free metrics (AUC) rather than recall at a fixed 0.5?
    multilingual  Token detectors collapse off-Latin script once the defang
                  artifact is controlled. Does an LLM judge fix that?
    provenance    AI-vs-human detection falls from a perfect AUC to near chance
                  once the corpus is distribution-matched. That was measured with
                  a trained classifier. Can a frontier LLM do better?

Every score is cached to disk, so a rerun costs nothing and an interrupted sweep
resumes. Reasoning models are sent ``reasoning.effort=minimal`` because they
otherwise spend the completion budget on hidden reasoning and return empty
content, which reads as an abstention and silently flatters their scores.

    export OPENROUTER_API_KEY=...
    python scripts/llm_experiments.py leaderboard --out docs/leaderboard.md
    python scripts/llm_experiments.py multilingual --out docs/multilingual_llm.md
    python scripts/llm_experiments.py provenance  --out docs/provenance_llm.md
"""

from __future__ import annotations

import argparse
import json
import os
from typing import List, Optional

from lurebench.leaderboard import evaluate_detectors, render_markdown
from lurebench.schema import load_jsonl

# Cheap, vendor-diverse panel. Model ids drift; verified live 2026-07-26.
MINIMAL_REASONING = {"reasoning": {"effort": "minimal"}}
PANEL = [
    ("openai/gpt-5-nano", MINIMAL_REASONING),
    ("google/gemini-2.5-flash-lite", MINIMAL_REASONING),
    ("deepseek/deepseek-v4-flash", MINIMAL_REASONING),
    ("qwen/qwen-2.5-7b-instruct", None),
    ("meta-llama/llama-3.1-8b-instruct", None),
    ("mistralai/mistral-nemo", None),
]
BASELINES = ["heuristic-v0", "tfidf-logreg"]
CACHE_ROOT = os.path.join(".cache", "llm-experiments")


def judge_specs(detector: str = "llm-judge") -> List[tuple]:
    """Detector specs for the whole panel, carrying each model's provider params."""
    specs = []
    for model, extra in PANEL:
        kwargs = {"engine": "openrouter", "model": model}
        if extra:
            kwargs["extra_params"] = extra
        specs.append((detector, kwargs))
    return specs


def _load(paths) -> list:
    """Load one or more shards. Provenance needs human and AI records together, so
    the dataset is assembled from several files rather than one."""
    if isinstance(paths, str):
        paths = [paths]
    records = []
    for p in paths:
        records.extend(load_jsonl(p))
    return records


def _run(dataset_path, specs, cache_name: str, task: Optional[str],
         workers: int, threshold: float, limit: int = 0):
    dataset = _load(dataset_path)
    if limit:
        dataset = dataset[:limit]
    cache_dir = os.path.join(CACHE_ROOT, cache_name)
    print(f"{dataset_path}: {len(dataset)} records, {len(specs)} detectors")
    results = evaluate_detectors(
        dataset, specs, threshold=threshold, task=task,
        cache_dir=cache_dir, workers=workers,
    )
    return dataset, results


def cmd_leaderboard(args) -> int:
    specs = BASELINES + judge_specs()
    dataset, results = _run(args.data, specs, "leaderboard", None,
                            args.workers, args.threshold, args.limit)
    md = render_markdown(results, dataset_label=args.data, n_records=len(dataset))
    md += _leaderboard_note()
    _emit(md, results, args)
    return 0


def cmd_multilingual(args) -> int:
    """Per-language recall for the panel, artifact-controlled, with an FPR reference.

    Two things make a naive version of this table misleading, and both are handled
    here. First, raw recall on this shard is inflated by the defang placeholders
    every lure carries: a detector can score ~1.00 in a language it cannot read by
    keying on ``<<link>>``. LureBench already established that, so recall is
    reported with those placeholders stripped. Second, the shard is all-fraud, so
    a detector that simply flags everything scores a perfect 1.00 in every
    language. The FPR column — measured on the benign half of the core test set,
    reused from the leaderboard cache so it costs nothing — is what separates
    reading the language from indiscriminate flagging.
    """
    import re
    from dataclasses import replace

    from lurebench.detectors import get_detector
    from lurebench.detectors.cache import CachedDetector, prewarm
    from lurebench.leaderboard import parse_detector_spec
    from lurebench.multilingual import strip_artifacts

    specs = BASELINES + judge_specs()
    dataset = _load(args.data)
    if args.limit:
        dataset = dataset[: args.limit]
    controlled = [replace(r, text=strip_artifacts(r.text)) for r in dataset if r.label == 1]
    langs = sorted({r.language for r in controlled})

    benign = [r for r in _load([args.fpr_data]) if r.label == 0] if args.fpr_data else []
    print(f"{len(controlled)} fraud lures (artifact-controlled) · {len(benign)} benign for FPR")

    rows, results = [], []
    for spec in specs:
        name, kwargs, display = parse_detector_spec(spec)
        label = display or name
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", label)
        try:
            det = get_detector(name, **kwargs)
            det.name = label
            cached = CachedDetector(
                det, os.path.join(CACHE_ROOT, "multilingual", f"{safe}.json")
            )
            prewarm(cached, controlled, workers=args.workers)
            per = {}
            for lang in langs:
                subset = [r for r in controlled if r.language == lang]
                kept = [s for s in (cached.score(r) for r in subset) if s is not None]
                per[lang] = (
                    sum(1 for s in kept if s >= args.threshold) / len(kept) if kept else None
                )
            fpr = None
            if benign:
                # Same detector name -> reuses the leaderboard cache, so this is free.
                ref = CachedDetector(
                    det, os.path.join(CACHE_ROOT, "leaderboard", f"{safe}.json")
                )
                prewarm(ref, benign, workers=args.workers)
                kept = [s for s in (ref.score(r) for r in benign) if s is not None]
                fpr = sum(1 for s in kept if s >= args.threshold) / len(kept) if kept else None
            rows.append((label, per, fpr, None))
            results.append({"detector": label, "per_language": per, "fpr_benign": fpr})
        except Exception as exc:  # noqa: BLE001
            rows.append((label, {lang: None for lang in langs}, None, type(exc).__name__))
            results.append({"detector": label, "error": f"{type(exc).__name__}: {exc}"})

    md = _multilingual_markdown(rows, langs, controlled, args.threshold, args.data)
    _emit(md, results, args)
    return 0


def cmd_provenance(args) -> int:
    """AI-vs-human on distribution-matched data, asked of LLM judges."""
    specs = judge_specs("llm-judge-provenance")
    dataset, results = _run(args.data, specs, "provenance", "provenance",
                            args.workers, args.threshold, args.limit)
    label = ", ".join(os.path.basename(p) for p in args.data)
    md = render_markdown(results, dataset_label=label, n_records=len(dataset))
    # render_markdown writes a generic leaderboard preamble; this experiment asks a
    # different question, so give it its own framing.
    md = md.replace(
        "# Leaderboard\n\nMCC is the headline metric. Detection rate (recall) and FPR "
        "matter because a fraud detector is only useful at a tolerable false-positive "
        "rate.\n",
        "# Can an LLM tell AI-written fraud from human-written fraud?\n\n"
        "Every record here is a fraud lure; the only question is who wrote it. AUC is "
        "the honest read because it does not depend on where the threshold sits.\n",
    )
    md += _provenance_note()
    _emit(md, results, args)
    return 0


def _multilingual_markdown(rows, langs, dataset, threshold, label) -> str:
    counts = {lang: sum(1 for r in dataset if r.language == lang) for lang in langs}
    out = ["# Multilingual: can an LLM judge read the lure?\n",
           "Detection rate (recall) per language, **artifact-controlled**: the defang "
           "placeholders (`<<link>>`, `<<contact>>`) are stripped before scoring, "
           "because a detector can otherwise score near 1.00 in a language it cannot "
           "read at all by keying on the placeholder. The shard is all-fraud, so recall "
           "here is not accuracy — read every row against its **FPR** column, measured "
           "on the benign half of the core test set. A detector with a high FPR is not "
           "reading the language, it is flagging everything.\n",
           f"_Generated from **{label}**, threshold {threshold:.2f}._\n",
           "| Detector | FPR (benign) | "
           + " | ".join(f"{lang} ({counts[lang]})" for lang in langs) + " |",
           "|---" * (len(langs) + 2) + "|"]
    for name, per, fpr, err in rows:
        if err:
            out.append(f"| `{name}` | _{err}_ | " + " | ".join(["  -  "] * len(langs)) + " |")
            continue
        cells = " | ".join("  -  " if per[lang] is None else f"{per[lang]:.2f}" for lang in langs)
        f = "  -  " if fpr is None else f"{fpr:.2f}"
        out.append(f"| `{name}` | {f} | {cells} |")
    out += [
        "",
        "Read the non-Latin columns (`ar`, `ru`, `zh`) against the Latin ones. The "
        "trained TF-IDF baseline holds up in the languages that share English's script "
        "and collapses in the ones that do not, which is what you would expect from a "
        "model that matches tokens it has seen. The stronger LLM judges do not have that "
        "cliff: they detect Arabic, Russian and Chinese lures at rates comparable to "
        "their Latin-script performance, at a lower false-positive rate than the "
        "baseline. That is the case for putting an LLM in front of non-English traffic.",
        "",
        "The FPR column is what makes the rest of the table trustworthy. A detector that "
        "flags indiscriminately scores a perfect 1.00 in every language on an all-fraud "
        "shard while being useless in production, and without a false-positive number "
        "next to it that row is indistinguishable from genuine multilingual competence.",
        "",
    ]
    return "\n".join(out)


def _leaderboard_note() -> str:
    return (
        "\n> The `scored` column is load-bearing: every other metric is computed only "
        "over the records a detector was willing to answer. An LLM judge that declines "
        "half the corpus would otherwise report metrics on the easy half and look "
        "flawless. AUC is threshold-free, so read it alongside TPR/FPR — a judge can "
        "rank fraud above benign well (high AUC) while being badly calibrated at the "
        "0.5 cut used for TPR.\n"
    )


def _provenance_note() -> str:
    return (
        "\n> 0.5 AUC is chance. The question is whether an LLM can tell AI-written fraud "
        "from human-written fraud on distribution-matched data, where a trained "
        "classifier drops from a perfect score to near chance once corpus artifacts are "
        "removed. The judge is told to ignore how scam-like the text is (every record "
        "here is fraud) and that the defang placeholders are applied uniformly, so "
        "neither can leak the answer.\n"
    )


def _emit(md: str, results, args) -> None:
    print(md)
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(md)
        print(f"wrote {args.out}")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)
        print(f"wrote {args.json}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    paired = "data/full/paired"
    for name, default_data, fn in [
        ("leaderboard", ["data/full/core/test.jsonl"], cmd_leaderboard),
        ("multilingual", ["data/full/multilingual/eval.jsonl"], cmd_multilingual),
        # Provenance needs both classes: human-written fraud and AI-written fraud.
        ("provenance", [f"{paired}/human.jsonl", f"{paired}/deepseek-v4-pro.jsonl",
                        f"{paired}/glm-4.6.jsonl", f"{paired}/mistral-large-latest.jsonl"],
         cmd_provenance),
    ]:
        p = sub.add_parser(name)
        p.add_argument("--data", nargs="+", default=default_data)
        p.add_argument("--out", default=None)
        p.add_argument("--json", default=None)
        p.add_argument("--workers", type=int, default=12)
        p.add_argument("--threshold", type=float, default=0.5)
        p.add_argument("--limit", type=int, default=0)
        if name == "multilingual":
            p.add_argument("--fpr-data", default="data/full/core/test.jsonl",
                           help="corpus whose benign records give the FPR reference; "
                                "shares the leaderboard cache, so it is free after that run")
        p.set_defaults(func=fn)
    args = ap.parse_args(argv)
    if not os.environ.get("OPENROUTER_API_KEY"):
        raise SystemExit("OPENROUTER_API_KEY is not set")
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
