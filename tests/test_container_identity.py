"""Executed OCI identity must stay bound to the content inspected at admission."""

import io
import json
import subprocess
from pathlib import Path

import pytest
from oci_stub import FakeRuntime

from lurebench import boundary_container
from lurebench.detectors import container
from lurebench.schema import Lure

FIRST = 'sha256:' + 'a' * 64
SECOND = 'sha256:' + 'b' * 64
PINNED = 'example.invalid/probe@sha256:' + 'c' * 64


class Process:
    def __init__(self, identity, available):
        self.identity = identity
        self.stdin = io.StringIO()
        self.stdout = self
        self.returncode = None if available else 125

    def readline(self, size=-1):
        request = json.loads(self.stdin.getvalue().splitlines()[-1])
        response = {key: request[key] for key in ('protocol', 'request_id')}
        if request['protocol'] == container.PROTOCOL:
            response['score'] = 0.125 if self.identity == FIRST else 0.875
        else:
            response['alerts'] = [] if self.identity == FIRST else [{'changed': True}]
        return (json.dumps(response) + '\n')[:size]

    def poll(self):
        return self.returncode

    def terminate(self):
        self.returncode = -15

    def kill(self):
        self.returncode = -9

    def wait(self, timeout=None):
        self.returncode = 0
        return 0

    def close(self):
        pass


@pytest.fixture(params=[container.ContainerDetector, boundary_container.BoundaryContainerMonitor])
def runtime(request, monkeypatch):
    registry = {'local-probe:dev': FIRST, PINNED: FIRST}
    available = {FIRST, SECOND}
    daemon = FakeRuntime(lambda reference: registry[reference],
                         lambda command, selected: Process(selected, True), available=available)
    daemon.install(monkeypatch)
    return request.param, registry, available, daemon.inspected, daemon.created


def evaluate(adapter):
    if isinstance(adapter, container.ContainerDetector):
        return adapter.score(Lure(id='synthetic', text='Synthetic fixture', label=0,
                                  source='human', typology='benign', language='en', channel='email'))
    return adapter({'events': []}, {})


@pytest.mark.parametrize('engine', ['docker', 'podman'])
@pytest.mark.parametrize('reference', ['local-probe:dev', PINNED])
def test_launch_and_restart_use_inspected_identity(runtime, engine, reference):
    factory, registry, _, inspected, launched = runtime
    adapter = factory(reference, runtime=engine, allow_mutable_image=reference != PINNED)
    registry[reference] = SECOND
    expected = 0.125 if factory is container.ContainerDetector else []
    try:
        assert evaluate(adapter) == expected
        adapter.close()
        assert evaluate(adapter) == expected
        assert adapter.image == reference
        assert adapter.image_id == FIRST
        if factory is container.ContainerDetector:
            assert adapter.name == 'container:' + FIRST
        else:
            assert adapter.artifact_sha256 == 'a' * 64
        assert len(inspected) == 1
        execution_id = FIRST if engine == 'docker' else FIRST.removeprefix('sha256:')
        assert [command[-1] for command in launched] == [execution_id, execution_id]
        assert all(command[0] == engine for command in launched)
    finally:
        adapter.close()


def test_removed_identity_fails_without_falling_back_to_retargeted_tag(runtime):
    factory, registry, available, inspected, launched = runtime
    adapter = factory('local-probe:dev', allow_mutable_image=True)
    registry['local-probe:dev'] = SECOND
    available.remove(FIRST)
    try:
        with pytest.raises(RuntimeError, match='OCI control operation failed'):
            evaluate(adapter)
        with pytest.raises(RuntimeError, match='failed'):
            evaluate(adapter)
        assert len(inspected) == len(launched) == 1
        assert launched[0][-1] == FIRST
    finally:
        with pytest.raises(RuntimeError, match='creation outcome remains uncertain'):
            adapter.close()


@pytest.mark.parametrize('value', ['', 'sha256:a', 'sha256:' + 'A' * 64,
                                    'sha512:' + 'a' * 64, FIRST + '\n' + SECOND,
                                    FIRST + '\x00', 'unavailable'])
def test_invalid_inspected_identity_cannot_launch(runtime, value):
    factory, registry, _, _, launched = runtime
    registry[PINNED] = value
    with pytest.raises(RuntimeError, match='invalid immutable image id'):
        factory(PINNED)
    assert not launched


@pytest.mark.parametrize('prefixed', [False, True])
def test_podman_full_identity_is_normalized_for_evidence(runtime, prefixed):
    factory, registry, _, _, launched = runtime
    registry[PINNED] = FIRST if prefixed else FIRST.removeprefix('sha256:')
    adapter = factory(PINNED, runtime='podman')
    try:
        assert adapter.image_id == FIRST
        assert evaluate(adapter) == (0.125 if factory is container.ContainerDetector else [])
        assert launched[0][-1] == FIRST.removeprefix('sha256:')
    finally:
        adapter.close()


@pytest.mark.parametrize('value', ['false', 'true', 0, 1, None, [], {}])
def test_mutable_override_requires_an_actual_boolean_before_inspection(runtime, value):
    factory, _, _, inspected, launched = runtime
    with pytest.raises(ValueError, match='allow_mutable_image must be a boolean'):
        factory(PINNED, allow_mutable_image=value)
    assert not inspected and not launched


@pytest.mark.parametrize('failure', [OSError('unavailable'),
                                    subprocess.TimeoutExpired('inspect', 30),
                                    subprocess.CalledProcessError(1, 'inspect')])
def test_inspection_failure_cannot_launch_or_pull(runtime, monkeypatch, failure):
    factory, _, _, _, launched = runtime

    def fail(*args, **kwargs):
        raise failure

    monkeypatch.setattr(subprocess, 'run', fail)
    with pytest.raises(RuntimeError, match='never pulls it implicitly') as caught:
        factory(PINNED)
    assert caught.value.__cause__ is failure
    assert not launched


def test_ci_exercises_real_identity_reassignment():
    workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/ci.yml').read_text()
    assert 'tests/fixtures/container-identity' in workflow
    assert 'LUREBENCH_TEST_DOCKER=1' in workflow
    assert 'tests/test_container_identity_docker.py' in workflow


@pytest.mark.parametrize('field', ['timeout_seconds', 'cpus'])
@pytest.mark.parametrize('value', [True, False, None, '1', float('nan'), float('inf'),
                                    -(10**400), 10**400, 0, 301],
                         ids=['true', 'false', 'none', 'string', 'nan', 'infinity',
                              'huge-negative', 'huge-positive', 'zero', 'over-limit'])
def test_resource_numbers_fail_cleanly_before_inspection(runtime, field, value):
    factory, _, _, inspected, launched = runtime
    with pytest.raises(ValueError, match=field):
        factory(PINNED, **{field: value})
    assert not inspected and not launched
