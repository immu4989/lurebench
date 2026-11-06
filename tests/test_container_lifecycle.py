"""Do not confuse reaping the CLI with verified daemon workload removal."""

import subprocess
import threading
from pathlib import Path

import pytest
from oci_stub import FakeRuntime
from test_container_identity import FIRST, PINNED, Process, evaluate

from lurebench import container_lifecycle as lifecycle
from lurebench.boundary_container import BoundaryContainerMonitor
from lurebench.cli import main
from lurebench.detectors.container import ContainerDetector


@pytest.fixture(params=['docker', 'podman'])
def owned(request, monkeypatch):
    daemon = FakeRuntime(lambda _: FIRST, lambda command, identity: Process(identity, True))
    daemon.install(monkeypatch)
    lease = lifecycle.OwnedContainer(request.param, FIRST)
    return daemon, lease


def create(lease):
    return lease.create(['--interactive', '--pull', 'never', '--network', 'none'])


def removals(daemon):
    return [command for command in daemon.calls if command[1:3] == ['container', 'rm']]


def test_create_is_owned_and_verified_before_start_and_cleanup_is_exact(owned):
    daemon, lease = owned
    command = create(lease)
    identifier = lease.container_id
    assert command == [lease.runtime, 'start', '--attach', '--interactive', identifier]
    assert daemon.calls[-1][1:3] == ['container', 'inspect']
    assert len(daemon.created) == 1
    lease.close()
    assert removals(daemon) == [[lease.runtime, 'container', 'rm', '--force', '--volumes', identifier]]
    assert not daemon.containers and lease.closed
    count = len(daemon.calls)
    lease.close()
    assert len(daemon.calls) == count
    with pytest.raises(RuntimeError, match='cannot be retried'):
        create(lease)


def test_unstarted_close_never_contacts_the_runtime(owned):
    daemon, lease = owned
    lease.close()
    assert not daemon.calls and lease.closed


def test_removed_id_does_not_adopt_or_delete_a_name_replacement(owned):
    daemon, lease = owned
    create(lease)
    replacement = daemon.containers.pop(lease.container_id)
    replacement.update(id='f' * 64, owner='unrelated-owner')
    daemon.containers[replacement['id']] = replacement
    lease.close()
    assert list(daemon.containers) == ['f' * 64]
    assert not removals(daemon)


@pytest.mark.parametrize('field,value', [
    ('owner', 'someone-else'), ('image', 'sha256:' + 'b' * 64),
    ('name', 'unrelated'), ('id', 'f' * 64), ('name', None),
])
def test_changed_metadata_is_not_cleanup_authority(owned, field, value):
    daemon, lease = owned
    create(lease)
    record = daemon.containers[lease.container_id]
    previous, record[field] = record[field], value
    with pytest.raises(RuntimeError, match='ownership could not be verified'):
        lease.close()
    assert not removals(daemon) and not lease.closed
    record[field] = previous
    lease.close()
    assert not daemon.containers


@pytest.mark.parametrize('value', ['', '{}', '[]', '{"id":1,"id":2}',
                                    '{"a":NaN}', 'x' * 4097])
def test_invalid_projection_prevents_start_and_removal(owned, monkeypatch, value):
    daemon, lease = owned
    original = daemon.run

    def run(command, **kwargs):
        if command[1:3] == ['container', 'inspect']:
            return subprocess.CompletedProcess(command, 0, value, '')
        return original(command, **kwargs)

    monkeypatch.setattr(subprocess, 'run', run)
    with pytest.raises(RuntimeError, match='ownership could not be verified'):
        create(lease)
    with pytest.raises(RuntimeError, match='ownership could not be verified'):
        lease.close()
    assert not removals(daemon)
    monkeypatch.setattr(subprocess, 'run', original)
    lease.close()


@pytest.mark.parametrize('outcome', ['timeout', 'malformed-id', 'nonzero'])
def test_uncertain_creation_recovers_only_verified_owned_id(owned, monkeypatch, outcome):
    daemon, lease = owned
    original = daemon.run

    def create_then_fail(command, **kwargs):
        result = original(command, **kwargs)
        if command[1] == 'create':
            if outcome == 'timeout':
                raise subprocess.TimeoutExpired(command, 10)
            if outcome == 'nonzero':
                raise subprocess.CalledProcessError(1, command)
            result.stdout = 'not-an-id\n'
        return result

    monkeypatch.setattr(subprocess, 'run', create_then_fail)
    with pytest.raises(RuntimeError):
        create(lease)
    assert lease.container_id is None
    assert len(daemon.containers) == 1
    lease.close()
    assert not daemon.containers and lease.closed
    assert len(daemon.created) == len(removals(daemon)) == 1


def test_absent_uncertain_creation_is_not_success_and_late_completion_can_be_cleaned(owned, monkeypatch):
    daemon, lease = owned
    original = daemon.run

    def fail(command, **kwargs):
        if command[1] == 'create':
            raise subprocess.TimeoutExpired(command, 10)
        return original(command, **kwargs)

    monkeypatch.setattr(subprocess, 'run', fail)
    with pytest.raises(RuntimeError, match='control operation failed'):
        create(lease)
    with pytest.raises(RuntimeError, match='outcome remains uncertain'):
        lease.close()
    assert not lease.closed and not removals(daemon)
    # The already-issued daemon request completes later; the adapter never
    # issues a second create and never treats an empty lookup as final proof.
    identifier = 'e' * 64
    daemon.containers[identifier] = {
        'id': identifier, 'name': lease.name, 'owner': lease.owner, 'image': FIRST,
    }
    lease.close()
    assert lease.closed and not daemon.containers


@pytest.mark.parametrize('result', ['short', 'f' * 64, 'a' * 64 + '\n' + 'b' * 64])
def test_ambiguous_or_changed_lookup_never_removes(owned, monkeypatch, result):
    daemon, lease = owned
    create(lease)
    original = daemon.run

    def changed(command, **kwargs):
        if command[1:3] == ['container', 'ls']:
            return subprocess.CompletedProcess(command, 0, result, '')
        return original(command, **kwargs)

    monkeypatch.setattr(subprocess, 'run', changed)
    with pytest.raises(RuntimeError, match='ambiguous or unexpected'):
        lease.close()
    assert not removals(daemon)
    monkeypatch.setattr(subprocess, 'run', original)
    lease.close()


@pytest.mark.parametrize('stage', ['ls', 'inspect', 'rm'])
@pytest.mark.parametrize('failure', [OSError('unavailable'),
                                    subprocess.TimeoutExpired('control', 10),
                                    subprocess.CalledProcessError(1, 'control')])
def test_control_failure_retains_cleanup_state_and_can_be_retried(owned, monkeypatch, stage, failure):
    daemon, lease = owned
    create(lease)
    original = daemon.run

    def fail(command, **kwargs):
        if command[1:3] == ['container', stage]:
            raise failure
        return original(command, **kwargs)

    monkeypatch.setattr(subprocess, 'run', fail)
    with pytest.raises(RuntimeError, match='control operation failed'):
        lease.close()
    assert lease.container_id in daemon.containers and not lease.closed
    monkeypatch.setattr(subprocess, 'run', original)
    lease.close()
    assert lease.closed


@pytest.mark.parametrize('mode', ['false-ack', 'still-present', 'removed-before-error'])
def test_remove_acknowledgment_is_not_sufficient_without_absence(owned, monkeypatch, mode):
    daemon, lease = owned
    create(lease)
    original = daemon.run

    def remove(command, **kwargs):
        if command[1:3] != ['container', 'rm']:
            return original(command, **kwargs)
        if mode == 'still-present':
            return subprocess.CompletedProcess(command, 0, command[-1], '')
        result = original(command, **kwargs)
        if mode == 'removed-before-error':
            raise subprocess.TimeoutExpired(command, 10)
        result.stdout = 'wrong-acknowledgment'
        return result

    monkeypatch.setattr(subprocess, 'run', remove)
    with pytest.raises(RuntimeError):
        lease.close()
    assert not lease.closed
    monkeypatch.setattr(subprocess, 'run', original)
    lease.close()
    assert lease.closed and not daemon.containers


def test_control_budget_is_shared_across_cleanup_commands(owned, monkeypatch):
    daemon, lease = owned
    create(lease)
    original = daemon.run
    clock, timeouts = [0.0], []
    monkeypatch.setattr(lifecycle.time, 'monotonic', lambda: clock[0])

    def slow(command, **kwargs):
        timeouts.append(kwargs['timeout'])
        clock[0] += 4
        return original(command, **kwargs)

    monkeypatch.setattr(subprocess, 'run', slow)
    with pytest.raises(RuntimeError, match='control deadline exceeded'):
        lease.close()
    assert timeouts == [10, 6, 2]
    assert not lease.closed
    monkeypatch.setattr(subprocess, 'run', original)
    lease.close()


@pytest.fixture(params=[ContainerDetector, BoundaryContainerMonitor])
def adapter(request, monkeypatch):
    daemon = FakeRuntime(lambda _: FIRST, lambda command, identity: Process(identity, True))
    daemon.install(monkeypatch)
    return daemon, request.param(PINNED)


@pytest.mark.parametrize('failure', [OSError('spawn'), KeyboardInterrupt(), SystemExit(3)])
def test_attach_failure_or_interruption_cleans_up_the_created_container(adapter, monkeypatch, failure):
    daemon, instance = adapter

    def fail(*args, **kwargs):
        raise failure

    monkeypatch.setattr(subprocess, 'Popen', fail)
    expected = RuntimeError if isinstance(failure, OSError) else type(failure)
    with pytest.raises(expected):
        evaluate(instance)
    assert not daemon.containers
    assert instance._container is None and instance._process is None
    with pytest.raises(RuntimeError, match='new .* for a new run'):
        evaluate(instance)


def test_primary_failure_is_preserved_and_cli_reaped_when_daemon_cleanup_fails(adapter, monkeypatch):
    daemon, instance = adapter
    evaluate(instance)
    process = instance._process
    original = daemon.run
    primary = ValueError('synthetic invalid response')

    def invalid(*args):
        raise primary

    def unavailable(command, **kwargs):
        if command[1:3] == ['container', 'rm']:
            raise OSError('unavailable')
        return original(command, **kwargs)

    monkeypatch.setattr(instance, '_parse_response', invalid)
    monkeypatch.setattr(subprocess, 'run', unavailable)
    with pytest.raises(ValueError) as caught:
        evaluate(instance)
    assert caught.value is primary and primary._container_cleanup_failed
    assert any('cleanup incomplete' in note for note in primary.__notes__)
    assert process.poll() is not None and instance._container is not None
    monkeypatch.setattr(subprocess, 'run', original)
    instance.close()
    assert not daemon.containers
    with pytest.raises(RuntimeError, match='new .* for a new run'):
        evaluate(instance)


def test_concurrent_start_or_close_cannot_replace_an_active_lease(adapter, monkeypatch):
    daemon, instance = adapter
    entered, release = threading.Event(), threading.Event()
    start = instance._start
    outcome = []

    def delayed():
        entered.set()
        assert release.wait(3)
        return start()

    def run():
        try:
            outcome.append(evaluate(instance))
        except BaseException as exc:
            outcome.append(exc)

    monkeypatch.setattr(instance, '_start', delayed)
    worker = threading.Thread(target=run)
    worker.start()
    try:
        assert entered.wait(3)
        with pytest.raises(RuntimeError, match='already has an active operation'):
            evaluate(instance)
        with pytest.raises(RuntimeError, match='already has an active operation'):
            instance.close()
        assert not daemon.created
    finally:
        release.set()
        worker.join(3)
    assert not worker.is_alive() and len(outcome) == 1
    assert not isinstance(outcome[0], BaseException)
    instance.close()
    assert len(daemon.created) == 1 and not daemon.containers


def test_context_exception_is_not_masked_by_a_cleanup_failure(adapter, monkeypatch):
    daemon, instance = adapter
    primary = ValueError('synthetic context failure')
    original = daemon.run

    def unavailable(command, **kwargs):
        if command[1:3] == ['container', 'rm']:
            raise OSError('unavailable')
        return original(command, **kwargs)

    monkeypatch.setattr(subprocess, 'run', unavailable)
    with pytest.raises(ValueError) as caught:
        with instance:
            evaluate(instance)
            raise primary
    assert caught.value is primary and primary._container_cleanup_failed
    assert instance._process.poll() is not None
    monkeypatch.setattr(subprocess, 'run', original)
    instance.close()
    assert not daemon.containers


@pytest.mark.parametrize('command', ['container-eval', 'boundary-eval'])
def test_cli_does_not_publish_when_daemon_removal_fails(monkeypatch, tmp_path, capsys, command):
    daemon = FakeRuntime(lambda _: FIRST, lambda args, identity: Process(identity, True))
    daemon.install(monkeypatch)
    original = daemon.run

    def unavailable(arguments, **kwargs):
        if arguments[1:3] == ['container', 'rm']:
            raise OSError('unavailable')
        return original(arguments, **kwargs)

    monkeypatch.setattr(subprocess, 'run', unavailable)
    output, wrapper = tmp_path / 'report.json', tmp_path / 'container.json'
    arguments = [command, '--image', PINNED, '--out', str(output)]
    if command == 'container-eval':
        samples = Path(__file__).resolve().parents[1] / 'data/samples/lures.jsonl'
        arguments += ['--dataset', str(samples)]
    else:
        arguments += ['--container-report', str(wrapper), '--json']
    assert main(arguments) == (1 if command == 'container-eval' else 2)
    assert not output.exists() and not wrapper.exists()
    captured = capsys.readouterr()
    assert captured.out == '' and 'cleanup incomplete' in captured.err
    assert 'inspect owned container lurebench-' in captured.err
