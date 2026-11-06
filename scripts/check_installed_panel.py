"""Exercise installed panel comparison/reproduction using standard-library fixtures.

Run outside the checkout with ``python -I -S`` after installing a trusted local
wheel into --installed-root. No providers, model libraries, or external network
are used. Unix lifecycle checks bind sockets only in owned temporary directories.
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
from unittest.mock import patch


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
    from lurebench.boundary_container import BoundaryContainerMonitor
    from lurebench.calibration import (
        DetectorBinding,
        binomial_cdf,
        build_policy,
        clopper_pearson_upper,
        validate_calibration_configuration,
    )
    from lurebench.cli import main
    from lurebench.container_lifecycle import OWNER_LABEL
    from lurebench.detectors.binoculars import BinocularsDetector
    from lurebench.detectors.cache import CachedDetector
    from lurebench.detectors.container import ContainerDetector
    from lurebench.detectors.llama_guard import LlamaGuardDetector
    from lurebench.detectors.moderation import CATEGORIES, OpenAIModerationDetector
    from lurebench.detectors.tfidf import TfidfLogisticDetector
    from lurebench.diskcache import CacheReadError
    from lurebench.harness import collect_scores, run
    from lurebench.permit import build_permit_request
    from lurebench.receipts import loads_strict_json
    from lurebench.runtime import RuntimePDP, build_runtime_request, default_runtime_profile
    from lurebench.runtime_service import (
        RuntimeDecisionApplication,
        RuntimeDecisionBusy,
        RuntimeDecisionExhausted,
        RuntimeDecisionUnavailable,
        _Handler,
        _TCPHTTPServer,
        _UnixHTTPServer,
    )
    from lurebench.schema import Lure, save_jsonl

    identity = 'sha256:' + 'a' * 64
    reference = 'installed-probe:dev'
    for runtime_name in ('docker', 'podman'):
        inspected = identity if runtime_name == 'docker' else identity.removeprefix('sha256:')
        for adapter_class in (ContainerDetector, BoundaryContainerMonitor):
            state = {'exists': False}
            identifier = 'b' * 64

            def control(command, *, inspected=inspected, state=state,
                        identifier=identifier, **kwargs):
                if command[1:3] == ['image', 'inspect']:
                    output = inspected
                elif command[1] == 'create':
                    state.update(exists=True, command=command)
                    state['name'] = command[command.index('--name') + 1]
                    state['owner'] = command[command.index('--label') + 1].split('=', 1)[1]
                    output = identifier
                elif command[1:3] == ['container', 'inspect']:
                    output = json.dumps({'id': identifier, 'name': state['name'],
                                         'image': inspected, 'owner': state['owner']})
                elif command[1:3] == ['container', 'ls']:
                    output = identifier if state['exists'] else ''
                elif command[1:3] == ['container', 'rm']:
                    if command[-1] != identifier:
                        raise ValueError('installed OCI cleanup selected an unexpected container')
                    state['exists'] = False
                    output = identifier
                else:
                    raise ValueError('installed OCI control used an unexpected operation')
                return SimpleNamespace(stdout=output + '\n')

            with (patch('shutil.which', return_value='/synthetic/runtime'),
                  patch('subprocess.run', side_effect=control),
                  patch('subprocess.Popen', return_value=SimpleNamespace()) as launch):
                adapter = adapter_class(reference, runtime=runtime_name, allow_mutable_image=True)
                adapter._start()
                command = state['command']
                if adapter.image_id != identity or command[-1] != inspected:
                    raise ValueError('installed OCI adapter lost its admitted image binding')
                if not command[command.index('--label') + 1].startswith(OWNER_LABEL + '='):
                    raise ValueError('installed OCI container lacks an ownership marker')
                if command[command.index('--pull') + 1] != 'never':
                    raise ValueError('installed OCI adapter enabled implicit image pulls')
                if launch.call_args.args[0] != [runtime_name, 'start', '--attach',
                                                '--interactive', identifier]:
                    raise ValueError('installed OCI adapter attached to an unexpected container')
                adapter.close()
                if state['exists']:
                    raise ValueError('installed OCI adapter left its owned container behind')

    if loads_strict_json(b'{"a":[0]}', max_nodes=4) != {"a": [0]}:
        raise ValueError("installed JSON decoder changed bounded values")
    for payload in (b'[0,1,2,3]', b'0.' + b'0' * 5000):
        try:
            loads_strict_json(payload, max_nodes=4)
        except ValueError:
            pass
        else:
            raise ValueError("installed JSON decoder lost complexity admission")

    class HttpConnection:
        def __init__(self, wire):
            self.input = io.BytesIO(wire)
            self.output = bytearray()

        def makefile(self, *args, **kwargs):
            return self.input

        def sendall(self, payload):
            self.output.extend(payload)

        def settimeout(self, value):
            pass

    for headers, payload, expected in (
        (b'Content-Length: 2\r\n', b'{}', 200),
        (b'Content-Length: 2\r\nContent-Length: 2\r\n', b'{}', 400),
        (b'Content-Length: 9\r\n', b'{}', 400),
        (b'Content-Length: 45\r\n', b'{"PRIVATE_INSTALLED":1,"PRIVATE_INSTALLED":2}', 400),
    ):
        connection = HttpConnection(b'POST /v1/decide HTTP/1.1\r\n' + headers
                                    + b'Content-Type: application/json\r\n\r\n' + payload)
        server = SimpleNamespace(application=SimpleNamespace(decide=loads_strict_json))
        _Handler(connection, ('127.0.0.1', 1), server)
        response = bytes(connection.output)
        if (int(response.split(b' ', 2)[1]) != expected or b'PRIVATE_INSTALLED' in response
                or b'Connection: close' not in response):
            raise ValueError("installed runtime HTTP framing/redaction failed")

    malformed = HttpConnection(b'GET / HTTP/PRIVATE_INSTALLED\r\n\r\n')
    _Handler(malformed, ('127.0.0.1', 1), SimpleNamespace())
    head, separator, body = bytes(malformed.output).partition(b'\r\n\r\n')
    if (not separator or int(head.split(b' ', 2)[1]) != 400
            or b'Content-Type: application/json' not in head
            or b'Connection: close' not in head
            or b'PRIVATE_INSTALLED' in head + body
            or json.loads(body) != {"error": "invalid_http_request"}):
        raise ValueError("installed runtime malformed-version response lost HTTP framing")

    for wire, expected in (
        (b'GET /health HTTP/1.1\r\nX-PRIVATE_INSTALLED: ' + b'x' * 20000 + b'\r\n\r\n', 431),
        (b'GET /health HTTP/1.1\r\n', 400),
        (b'GET /health\r\n\r\n', 400),
    ):
        connection = HttpConnection(wire)
        _Handler(connection, ('127.0.0.1', 1), SimpleNamespace())
        output = bytes(connection.output)
        if int(output.split(b' ', 2)[1]) != expected or b'PRIVATE_INSTALLED' in output:
            raise ValueError('installed runtime head preflight failed')

    clock = [0.]

    class LateHead(io.BytesIO):
        def read1(self, size=-1):
            clock[0] = 6.
            return super().read1(size)

    connection = HttpConnection(b'')
    connection.input = LateHead(b'GET /health HTTP/1.1\r\n\r\n')
    with patch('lurebench.runtime_service.time.monotonic', side_effect=lambda: clock[0]):
        _Handler(connection, ('127.0.0.1', 1), SimpleNamespace())
    if int(connection.output.split(b' ', 2)[1]) != 408:
        raise ValueError('installed runtime head deadline admitted late input')

    with _TCPHTTPServer(('127.0.0.1', 0), _Handler, bind_and_activate=False,
                        max_connections=1) as server:
        closed = []
        server.shutdown_request = closed.append
        server._connection_slots.acquire()
        try:
            server.process_request('synthetic-at-capacity', None)
            if closed != ['synthetic-at-capacity']:
                raise ValueError("installed runtime lost pre-worker capacity rejection")
        finally:
            server._connection_slots.release()

    with tempfile.TemporaryDirectory(prefix='lru-') as directory:
        target = Path(directory) / 's'
        with _UnixHTTPServer(str(target), _Handler):
            if not target.is_socket() or target.stat().st_mode & 0o777 != 0o600:
                raise ValueError('installed Unix socket lost private permission setup')
        if target.exists():
            raise ValueError('installed Unix socket did not clean its owned entry')
        with _UnixHTTPServer(str(target), _Handler):
            target.rename(Path(directory) / 'original')
            target.write_bytes(b'synthetic replacement')
        if target.read_bytes() != b'synthetic replacement':
            raise ValueError('installed Unix cleanup removed a replacement')
        Path(directory).chmod(0o755)
        try:
            try:
                _UnixHTTPServer(str(Path(directory) / 'other'), _Handler)
            except ValueError:
                pass
            else:
                raise ValueError('installed Unix socket admitted a non-private parent')
        finally:
            Path(directory).chmod(0o700)

    with tempfile.TemporaryDirectory(prefix="lure-runtime-audit-install-") as directory:
        profile = default_runtime_profile()
        log = Path(directory) / 'receipts.jsonl'
        application = RuntimeDecisionApplication(RuntimePDP(profile), log, decision_wait_seconds=0)

        def runtime_request(sequence):
            return json.dumps(build_runtime_request(build_permit_request(sequence=sequence),
                profile=profile, correlation_id=f'installed-{sequence}',
                nonce=f'installed-nonce-{sequence}')).encode()

        with application._lock:
            try:
                application.decide(runtime_request(1))
            except RuntimeDecisionBusy:
                pass
            else:
                raise ValueError("installed runtime entered a busy decision engine")
            if log.read_bytes() or application.pdp._receipt_sequence != 0:
                raise ValueError("installed runtime changed state after busy admission")
        application.decide(runtime_request(1))
        with patch('lurebench.runtime_service.os.fsync', side_effect=OSError('synthetic sync fault')):
            try:
                application.decide(runtime_request(2))
            except RuntimeDecisionUnavailable:
                pass
            else:
                raise ValueError("installed runtime returned a decision after sync failure")
        preserved = log.read_bytes()
        try:
            application.decide(runtime_request(3))
        except RuntimeDecisionUnavailable:
            pass
        else:
            raise ValueError("installed runtime resumed after uncertain audit persistence")
        if log.read_bytes() != preserved or application.readiness()['ready']:
            raise ValueError("installed runtime modified failed evidence or lost its failure latch")
        connection = HttpConnection(b'GET /health HTTP/1.1\r\n\r\n')
        _Handler(connection, ('127.0.0.1', 1), SimpleNamespace(application=application))
        if int(connection.output.split(b' ', 2)[1]) != 503:
            raise ValueError("installed runtime health ignored its failure latch")

    limited = RuntimeDecisionApplication(RuntimePDP(), max_decisions=1)
    payload = json.dumps(build_runtime_request(build_permit_request(sequence=1),
        profile=limited.pdp.profile, correlation_id='installed-limit', nonce='installed-limit')).encode()
    if limited.decide(payload)['receipt']['chain']['sequence'] != 1:
        raise ValueError("installed runtime did not return the final permitted receipt")
    try:
        limited.decide(payload)
    except RuntimeDecisionExhausted:
        pass
    else:
        raise ValueError("installed runtime ignored its session ceiling")
    if (limited.pdp.receipt_count != 1
            or limited.readiness()['reason'] != 'decision_limit_reached'
            or limited.readiness()['decision_budget']['remaining'] != 0):
        raise ValueError("installed runtime changed exhausted state or lost its budget")

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
