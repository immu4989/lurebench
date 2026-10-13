"""Exercise installed panel comparison/reproduction using standard-library fixtures.

Run outside the checkout with ``python -I -S`` after installing a trusted local
wheel into --installed-root. No providers, model libraries, or network are used.
"""

from __future__ import annotations

import argparse
import contextlib
import importlib.abc
import io
import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace


class ForbidOptionalImports(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".", 1)[0] in {
            "torch", "transformers", "sklearn", "numpy", "joblib", "pickle",
            "openai", "anthropic", "huggingface_hub", "httpx", "requests",
            "binoculars",
        }:
            raise ImportError("optional dependency forbidden in installed panel check")
        return None


def check(root: Path) -> None:
    root = root.resolve(strict=True)
    checkout = Path(__file__).resolve().parents[1]
    if Path.cwd().resolve().is_relative_to(checkout) or root == checkout:
        raise ValueError("run against an installed wheel outside the checkout")
    if any(name == "lurebench" or name.startswith("lurebench.") for name in sys.modules):
        raise ValueError("fresh interpreter required")
    sys.meta_path.insert(0, ForbidOptionalImports())
    sys.path.insert(0, str(root))
    from lurebench import cli, leaderboard
    from lurebench.cli import main
    from lurebench.detectors.binoculars import BinocularsDetector
    from lurebench.detectors.cache import CachedDetector
    from lurebench.harness import collect_scores, run
    from lurebench.schema import Lure, save_jsonl

    try:
        BinocularsDetector()
    except ValueError as exc:
        if "allow_unsafe_upstream" not in str(exc):
            raise
    else:
        raise ValueError("installed Binoculars adapter implicitly loaded upstream")
    backend = SimpleNamespace(max_token_observed=512,
        tokenizer=lambda *a, **kw: {"input_ids": [1, 2, 3]},
        compute_score=lambda text: float("nan"))
    binoculars = BinocularsDetector(backend=backend, cache_context="a" * 64)
    try:
        binoculars.score(Lure("synthetic", "Synthetic input", 1, "ai", "phishing"))
    except ValueError:
        pass
    else:
        raise ValueError("installed Binoculars adapter clipped invalid raw output")

    for operation in (run, collect_scores):
        record = Lure("snapshot", "Synthetic input", 1, "human", "phishing",
                      meta={"nested": ["unchanged"]})
        before = record.to_dict()

        def mutate(value):
            value.label = 0
            value.id = "modified"
            value.meta["nested"].clear()
            return 0.

        result = operation(SimpleNamespace(task="fraud", score=mutate), [record])
        if record.to_dict() != before:
            raise ValueError("installed harness let a callback modify caller records")
        if operation is run:
            if result.metrics.fn != 1 or result.metrics.tn != 0:
                raise ValueError("installed harness scored against callback-modified truth")
        elif result != (["snapshot"], [1], [0.]):
            raise ValueError("installed score collection lost captured IDs or targets")

    with tempfile.TemporaryDirectory(prefix="lure-panel-install-") as directory:
        work = Path(directory)
        records = [Lure(str(i), f"Synthetic installed fixture {i}", 1, "human", "phishing",
                        meta={"family_id": f"family-{i // 2}"}) for i in range(8)]
        save_jsonl(records, work / "records.jsonl")
        descriptors = []
        for name, value in (("baseline", .1), ("candidate", .9)):
            cache = CachedDetector(SimpleNamespace(name=name, task="fraud",
                score=lambda record, result=value: result), str(work / f"{name}.json"), flush_every=0)
            for record in records:
                cache.score(record)
            cache.flush()
            descriptors.append({"id": name, "name": name, "cache": f"{name}.json", "threshold": .5})
        (work / "plan.json").write_text(json.dumps({"schema_version": 1, "task": "fraud",
            "pairing_unit": "lineage", "baseline": descriptors[0], "candidates": descriptors[1:]}))
        arguments = ["--dataset", str(work / "records.jsonl"), "--plan", str(work / "plan.json")]

        def command(args, status):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                actual = main(args)
            if actual != status:
                raise ValueError("installed panel command returned unexpected status")
            return json.loads(output.getvalue())

        evaluated = command(["eval", "--dataset", str(work / "records.jsonl"),
                             "--bootstrap", "20", "--seed", "41", "--json"], 0)[0]
        if (evaluated["metrics"]["n"] != 8 or evaluated["confidence_intervals"]["auc"] is not None
                or evaluated["confidence_interval_status"]["auc"]["status"] != "undefined_estimate"
                or evaluated["bootstrap"]["seed"] != 41):
            raise ValueError("installed evaluation lost single-class results")
        original_constructor = cli.get_detector
        original_leaderboard_constructor = leaderboard.get_detector
        attempted_constructors = []

        def forbidden(*args, **kwargs):
            attempted_constructors.append(True)
            raise AssertionError("invalid evaluation plan constructed a detector")

        cli.get_detector = leaderboard.get_detector = forbidden
        try:
            output, errors = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                invalid = main(["eval", "--dataset", str(work / "records.jsonl"), "--bootstrap", "-1"])
            if invalid != 2 or output.getvalue():
                raise ValueError("installed evaluation did not reject invalid bootstrap controls")
            try:
                leaderboard.evaluate_detectors(records, ["heuristic-v0", ["malformed"]])
            except ValueError:
                pass
            else:
                raise ValueError("installed leaderboard accepted a malformed plan")
            if attempted_constructors:
                raise ValueError("installed preflight ran a detector constructor")
        finally:
            cli.get_detector = original_constructor
            leaderboard.get_detector = original_leaderboard_constructor

        report = command(["compare-panel", *arguments], 0)
        if report["family_adjustment"]["adjusted_p_values"] != {"candidate": .125}:
            raise ValueError("installed panel arithmetic differs from synthetic reference")
        report_path = work / "report.json"
        report_path.write_text(json.dumps(report))
        before = {p.name: p.read_bytes() for p in work.iterdir()}
        verified = command(["verify-panel", *arguments, "--report", str(report_path)], 0)
        if not verified["matches_replay"] or before != {p.name: p.read_bytes() for p in work.iterdir()}:
            raise ValueError("installed verification failed or mutated inputs")
        report["family_adjustment"]["adjusted_p_values"]["candidate"] = 0.
        report_path.write_text(json.dumps(report))
        if command(["verify-panel", *arguments, "--report", str(report_path)], 1)["matches_replay"]:
            raise ValueError("installed verification accepted altered report")
        uncertainty_args = ["--dataset", str(work / "records.jsonl"), "--cache",
                            str(work / "baseline.json"), "--detector-name", "baseline",
                            "--task", "fraud", "--replicates", "30"]
        uncertainty = command(["uncertainty-cached", *uncertainty_args], 0)
        if (uncertainty["sample"]["resampling_units"] != 4
                or uncertainty["metrics"]["auc"]["status"] != "undefined_estimate"
                or uncertainty["metrics"]["recall"]["estimate"] != 0.):
            raise ValueError("installed uncertainty did not preserve grouping or undefined metrics")
        uncertainty_path = work / "uncertainty.json"
        uncertainty_path.write_text(json.dumps(uncertainty))
        verification_args = ["verify-uncertainty", *uncertainty_args,
                             "--report", str(uncertainty_path)]
        before = {p.name: p.read_bytes() for p in work.iterdir()}
        if not command(verification_args, 0)["matches_replay"]:
            raise ValueError("installed uncertainty did not reproduce")
        if before != {p.name: p.read_bytes() for p in work.iterdir()}:
            raise ValueError("installed uncertainty verification mutated inputs")
        uncertainty["metrics"]["recall"]["estimate"] = 1.
        uncertainty_path.write_text(json.dumps(uncertainty))
        if command(verification_args, 1)["matches_replay"]:
            raise ValueError("installed uncertainty accepted altered report")
        schema = root / "lurebench/spec/detector-uncertainty-v1.schema.json"
        if not schema.is_file() or json.loads(schema.read_text())["properties"]["schema_version"] != {"const": 1}:
            raise ValueError("installed uncertainty schema is missing")
    for name, module in tuple(sys.modules.items()):
        if name == "lurebench" or name.startswith("lurebench."):
            location = getattr(module, "__file__", None)
            if not location or not Path(location).resolve().is_relative_to(root):
                raise ValueError("producer import escaped installed root")
    print("Verified installed evaluation preflight, interval availability, harness isolation, "
          "panel and uncertainty replay without optional imports")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installed-root", type=Path, required=True)
    check(parser.parse_args().installed_root)
