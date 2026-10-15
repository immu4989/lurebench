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
import math
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace


class ForbidOptionalImports(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".", 1)[0] in {
            "torch", "transformers", "sklearn", "numpy", "joblib", "pickle",
            "openai", "anthropic", "huggingface_hub", "httpx", "requests",
            "binoculars", "accelerate",
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
    from lurebench.calibration import (
        DetectorBinding,
        binomial_cdf,
        build_policy,
        clopper_pearson_upper,
        validate_calibration_configuration,
    )
    from lurebench.cli import main
    from lurebench.detectors.binoculars import BinocularsDetector
    from lurebench.detectors.cache import CachedDetector
    from lurebench.detectors.llama_guard import LlamaGuardDetector
    from lurebench.detectors.moderation import CATEGORIES, OpenAIModerationDetector
    from lurebench.detectors.tfidf import TfidfLogisticDetector
    from lurebench.diskcache import CacheReadError
    from lurebench.harness import collect_scores, run
    from lurebench.schema import Lure, save_jsonl

    if binomial_cdf(40000, 100000, .5) != 0.:
        raise ValueError("installed binomial recurrence retained a subnormal plateau")
    expected_bound = -math.expm1(math.log1p(-.95) / 10000000)
    if not expected_bound <= clopper_pearson_upper(0, 10000000, .95) <= math.nextafter(
        expected_bound, math.inf,
    ):
        raise ValueError("installed zero-event bound lost its stable closed form")

    first, _ = build_policy("installed", "fraud", ["a", "b"], [0, 1], [.1, .9])
    changed, _ = build_policy("installed", "fraud", ["a", "b"], [0, 1], [.11, .9])
    if first.threshold != changed.threshold or first.policy_id == changed.policy_id:
        raise ValueError("installed policy identity lost its validation observations")
    binding = DetectorBinding("lurescope-portable-tfidf-exact-v1", "a" * 64, "b" * 64, "c" * 64)
    bound, _ = build_policy("tfidf-logreg", "fraud", ["a", "b"], [0, 1], [.1, .9],
                            detector_binding=binding)
    if bound.schema_version != 3 or bound.detector_binding != binding:
        raise ValueError("installed calibration lost exact configuration binding")
    try:
        validate_calibration_configuration("max_mcc", None, .95, 1001, 0)
    except ValueError:
        pass
    else:
        raise ValueError("installed calibration preflight accepted invalid diagnostic controls")

    probe = Lure("synthetic", "Synthetic input", 1, "ai", "phishing")
    try:
        LlamaGuardDetector()
    except ValueError as exc:
        if "allow_unsafe_upstream" not in str(exc):
            raise
    else:
        raise ValueError("installed Llama Guard implicitly loaded model frameworks")
    token_ids = SimpleNamespace(shape=(1, 2))
    token_ids.to = lambda device: token_ids
    reviewed = SimpleNamespace(
        tokenizer=SimpleNamespace(apply_chat_template=lambda *a, **kw: token_ids,
                                  decode=lambda *a, **kw: "safe", chat_template="synthetic"),
        model=SimpleNamespace(device="cpu", eval=lambda: None,
                              generate=lambda *a, **kw: [[1, 2, 3]]),
        inference_context=contextlib.nullcontext,
    )
    if LlamaGuardDetector(backend=reviewed, cache_context="d" * 64).score(probe) != 0.:
        raise ValueError("installed reviewed safety backend changed its verdict")
    moderation_scores = {name: .25 for name in CATEGORIES}
    moderation_result = {"results": [{"flagged": False, "category_scores": moderation_scores}]}
    moderation_client = SimpleNamespace(moderations=SimpleNamespace(
        create=lambda **kwargs: moderation_result,
    ))
    moderation = OpenAIModerationDetector(client=moderation_client, cache_context="c" * 64)
    if moderation.score(probe) != .25:
        raise ValueError("installed moderation adapter changed valid proxy scores")
    moderation_scores["violence"] = float("nan")
    try:
        moderation.score(probe)
    except RuntimeError:
        pass
    else:
        raise ValueError("installed moderation adapter masked invalid category scores")
    pipeline = SimpleNamespace(classes_=[1, 0], predict_proba=lambda texts: [[.75, .25]])
    trained = TfidfLogisticDetector.from_pipeline(pipeline, "provenance")
    if trained.task != "provenance" or trained.score(probe) != .75:
        raise ValueError("installed trained adapter lost task or class polarity")
    pipeline.predict_proba = lambda texts: [[.75, float("nan")]]
    try:
        trained.score(probe)
    except ValueError:
        pass
    else:
        raise ValueError("installed trained adapter accepted an invalid probability row")
    try:
        TfidfLogisticDetector.from_pipeline(
            SimpleNamespace(classes_=[0], predict_proba=lambda texts: [[1.]]), "fraud",
        )
    except ValueError:
        pass
    else:
        raise ValueError("installed trained adapter relabelled a one-class estimator")

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
        moderation_cache = CachedDetector(moderation, str(work / "moderation.json"))
        try:
            moderation_cache.score(probe)
        except RuntimeError:
            pass
        else:
            raise ValueError("installed moderation cache accepted invalid provider evidence")
        if moderation_cache._cache:
            raise ValueError("installed moderation cache retained a malformed response")
        try:
            CachedDetector(trained, str(work / "unbound.json"))
        except ValueError:
            pass
        else:
            raise ValueError("installed trained adapter persisted unidentified pipeline scores")
        pipeline.predict_proba = lambda texts: [[.75, .25]]
        bound = TfidfLogisticDetector.from_pipeline(pipeline, "provenance", cache_context="a" * 64)
        bound_cache = CachedDetector(bound, str(work / "trained.json"))
        if bound_cache.score(probe) != .75:
            raise ValueError("installed bound pipeline changed class polarity")
        bound_cache.flush()
        changed = TfidfLogisticDetector.from_pipeline(pipeline, "provenance", cache_context="b" * 64)
        try:
            CachedDetector(changed, str(work / "trained.json"))
        except CacheReadError:
            pass
        else:
            raise ValueError("installed trained cache accepted another pipeline identity")
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
