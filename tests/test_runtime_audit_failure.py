"""A broken audit sink must never be followed by another runtime decision."""

import json
import os
import threading
from unittest.mock import patch

import pytest

from lurebench.permit import build_permit_request
from lurebench.runtime import RuntimePDP, build_runtime_request, default_runtime_profile
from lurebench.runtime_service import RuntimeDecisionApplication, RuntimeDecisionUnavailable


def application(tmp_path):
    profile = default_runtime_profile()
    log = tmp_path / 'private-receipts.jsonl'
    app = RuntimeDecisionApplication(RuntimePDP(profile), log)

    def request(sequence):
        value = build_runtime_request(build_permit_request(sequence=sequence), profile=profile,
                                      correlation_id=f'fault-{sequence}', nonce=f'nonce-{sequence}')
        return json.dumps(value).encode()

    return app, log, request


@pytest.mark.parametrize('stage', ['open', 'fsync'])
def test_storage_failure_is_latched_after_fault_removed(tmp_path, monkeypatch, stage):
    app, log, request = application(tmp_path)
    with patch(f'lurebench.runtime_service.os.{stage}', side_effect=OSError('PRIVATE_FAULT')):
        with pytest.raises(RuntimeDecisionUnavailable):
            app.decide(request(1))
    preserved = log.read_bytes()
    monkeypatch.setattr(app.pdp, 'decide', lambda *a: pytest.fail('another decision evaluated'))
    with pytest.raises(RuntimeDecisionUnavailable):
        app.decide(request(2))
    assert log.read_bytes() == preserved
    assert app.readiness()['ready'] is False


@pytest.mark.parametrize('mutation', ['replace', 'truncate', 'append', 'permissions', 'hardlink'])
def test_changed_log_rejected_before_next_decision(tmp_path, monkeypatch, mutation):
    if mutation in {'permissions', 'hardlink'} and os.name != 'posix':
        pytest.skip('POSIX metadata profile')
    app, log, request = application(tmp_path)
    app.decide(request(1))
    previous = log.read_bytes()
    if mutation == 'replace':
        replacement = tmp_path / 'replacement.jsonl'
        replacement.write_bytes(previous)
        replacement.chmod(0o600)
        replacement.replace(log)
    elif mutation == 'truncate':
        log.write_bytes(b'')
    elif mutation == 'append':
        with log.open('ab') as stream:
            stream.write(b'{}\n')
    elif mutation == 'permissions':
        log.chmod(0o644)
    else:
        os.link(log, tmp_path / 'alias.jsonl')
    preserved = log.read_bytes()
    monkeypatch.setattr(app.pdp, 'decide', lambda *a: pytest.fail('changed sink reached decision'))
    with pytest.raises(RuntimeDecisionUnavailable):
        app.decide(request(2))
    assert log.read_bytes() == preserved


def test_invalid_requests_do_not_poison_readiness(tmp_path):
    app, log, request = application(tmp_path)
    for payload in (b'bad-json', b'{}', b'{"x":1,"x":2}'):
        with pytest.raises(ValueError):
            app.decide(payload)
    assert app.readiness()['ready'] is True
    assert log.read_bytes() == b''
    assert app.decide(request(1))['receipt']['chain']['sequence'] == 1


@pytest.mark.parametrize('stage', ['serialize', 'fdopen', 'write', 'short_write', 'flush', 'close'])
def test_all_append_failures_preserve_bytes_and_prevent_later_work(tmp_path, monkeypatch, stage):
    import lurebench.runtime_service as service

    app, log, request = application(tmp_path)
    original_fdopen = os.fdopen

    class FaultyStream:
        def __init__(self, descriptor):
            self.stream = original_fdopen(descriptor, 'ab')

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()
            if stage == 'close':
                raise OSError('PRIVATE_CLOSE')

        def write(self, payload):
            if stage == 'write':
                self.stream.write(payload[:10])
                raise OSError('PRIVATE_WRITE')
            if stage == 'short_write':
                return self.stream.write(payload[:10])
            return self.stream.write(payload)

        def flush(self):
            if stage == 'flush':
                raise OSError('PRIVATE_FLUSH')
            self.stream.flush()

        def fileno(self):
            return self.stream.fileno()

    with monkeypatch.context() as change:
        if stage == 'serialize':
            change.setattr(service, '_canonical', lambda *a: (_ for _ in ()).throw(
                ValueError('PRIVATE_SERIALIZATION')))
        elif stage == 'fdopen':
            change.setattr(service.os, 'fdopen', lambda *a: (_ for _ in ()).throw(
                OSError('PRIVATE_FDOPEN')))
        else:
            change.setattr(service.os, 'fdopen', lambda descriptor, mode: FaultyStream(descriptor))
        with pytest.raises(RuntimeDecisionUnavailable) as error:
            app.decide(request(1))
        assert 'PRIVATE' not in str(error.value)
    preserved = log.read_bytes()
    assert app.pdp._receipt_sequence == 1
    assert app.readiness()['reason'] == 'receipt_log_failed'
    monkeypatch.setattr(app.pdp, 'decide', lambda *a: pytest.fail('decision after failed append'))
    with pytest.raises(RuntimeDecisionUnavailable):
        app.decide(request(2))
    assert log.read_bytes() == preserved
    if stage in {'write', 'short_write'}:
        assert len(preserved) == 10  # No truncation/repair hides a partial receipt.


def test_waiting_request_cannot_overtake_failed_append(tmp_path, monkeypatch):
    app, log, request = application(tmp_path)
    writing, release, second_started = threading.Event(), threading.Event(), threading.Event()
    outcomes, decisions = [], []
    original = app.pdp.decide

    def decide(value):
        decisions.append(value['nonce'])
        return original(value)

    def failed_sync(descriptor):
        writing.set()
        assert release.wait(2.)
        raise OSError('PRIVATE_STORAGE')

    monkeypatch.setattr(app.pdp, 'decide', decide)
    monkeypatch.setattr(os, 'fsync', failed_sync)

    def run(sequence):
        if sequence == 2:
            second_started.set()
        try:
            app.decide(request(sequence))
        except BaseException as exc:
            outcomes.append(exc)

    first = threading.Thread(target=run, args=(1,), daemon=True)
    second = threading.Thread(target=run, args=(2,), daemon=True)
    first.start()
    try:
        assert writing.wait(2.)
        # Readiness is a non-blocking latch snapshot, not a disk-progress probe.
        assert app.readiness()['ready'] is True
        second.start()
        assert second_started.wait(2.)
    finally:
        release.set()
        first.join(2.)
        if second.ident is not None:
            second.join(2.)
    assert not first.is_alive() and not second.is_alive()
    assert len(outcomes) == 2 and all(isinstance(e, RuntimeDecisionUnavailable) for e in outcomes)
    assert decisions == ['nonce-1']
    assert app.readiness()['ready'] is False
    assert len(log.read_bytes().splitlines()) == 1


@pytest.mark.parametrize('memory_only', [False, True])
def test_failure_after_engine_mutation_is_not_misclassified_as_bad_input(
    tmp_path, monkeypatch, memory_only,
):
    app, log, request = application(tmp_path)
    if memory_only:
        app = RuntimeDecisionApplication(RuntimePDP(app.pdp.profile))
    original = app.pdp.decide

    def broken(value):
        original(value)
        raise ValueError('PRIVATE_INTERNAL_STATE')

    monkeypatch.setattr(app.pdp, 'decide', broken)
    with pytest.raises(RuntimeDecisionUnavailable):
        app.decide(request(1))
    assert app.readiness()['reason'] == 'decision_state_uncertain'
    assert app.pdp._receipt_sequence == 1
    with pytest.raises(RuntimeDecisionUnavailable):
        app.decide(request(2))
    assert app.pdp._receipt_sequence == 1
    assert log.read_bytes() == b''


def test_interrupted_append_latches_failure_but_preserves_interrupt(tmp_path, monkeypatch):
    app, _, request = application(tmp_path)
    with patch('lurebench.runtime_service.os.fsync', side_effect=KeyboardInterrupt):
        with pytest.raises(KeyboardInterrupt):
            app.decide(request(1))
    assert app.readiness()['ready'] is False
    with pytest.raises(RuntimeDecisionUnavailable):
        app.decide(request(2))


def test_new_log_requires_unused_engine(tmp_path):
    app, _, request = application(tmp_path)
    app.pdp.decide(json.loads(request(1)))
    target = tmp_path / 'new-log.jsonl'
    with pytest.raises(ValueError, match='unused'):
        RuntimeDecisionApplication(app.pdp, target)
    assert not target.exists()


@pytest.mark.parametrize('kind', ['symlink', 'directory', 'fifo'])
def test_non_regular_replacement_never_opens_or_enters_engine(tmp_path, monkeypatch, kind):
    if kind == 'fifo' and not hasattr(os, 'mkfifo'):
        pytest.skip('requires FIFO support')
    app, log, request = application(tmp_path)
    log.rename(tmp_path / 'preserved.jsonl')
    if kind == 'symlink':
        log.symlink_to(tmp_path / 'preserved.jsonl')
    elif kind == 'directory':
        log.mkdir()
    else:
        os.mkfifo(log)
    monkeypatch.setattr(os, 'open', lambda *a, **kw: pytest.fail('opened replaced object'))
    monkeypatch.setattr(app.pdp, 'decide', lambda *a: pytest.fail('entered decision engine'))
    with pytest.raises(RuntimeDecisionUnavailable):
        app.decide(request(1))
    assert app.readiness()['reason'] == 'receipt_log_failed'


def test_disabling_logging_cannot_clear_failure_latch(tmp_path):
    app, _, request = application(tmp_path)
    with patch('lurebench.runtime_service.os.fsync', side_effect=OSError):
        with pytest.raises(RuntimeDecisionUnavailable):
            app.decide(request(1))
    app.receipt_log = None
    with pytest.raises(RuntimeDecisionUnavailable):
        app.decide(request(2))


def test_opened_file_is_checked_before_any_write(tmp_path, monkeypatch):
    app, log, request = application(tmp_path)
    replacement = tmp_path / 'replacement.jsonl'
    replacement.write_bytes(b'PROTECTED_REPLACEMENT')
    replacement.chmod(0o600)
    original_open = os.open

    def redirect(path, flags, *args, **kwargs):
        return original_open(replacement, flags, *args, **kwargs)

    monkeypatch.setattr(os, 'open', redirect)
    with pytest.raises(RuntimeDecisionUnavailable):
        app.decide(request(1))
    assert replacement.read_bytes() == b'PROTECTED_REPLACEMENT'
    assert log.read_bytes() == b''
    assert app.readiness()['reason'] == 'receipt_log_failed'


@pytest.mark.parametrize('mutation', ['path', 'extra_bytes', 'permissions'])
def test_mutation_during_sync_withholds_result_and_latches(tmp_path, monkeypatch, mutation):
    if mutation == 'permissions' and os.name != 'posix':
        pytest.skip('POSIX permissions profile')
    app, log, request = application(tmp_path)

    def changed_sync(descriptor):
        if mutation == 'path':
            log.rename(tmp_path / 'preserved-written-log.jsonl')
            log.write_bytes(b'REPLACEMENT')
            log.chmod(0o600)
        elif mutation == 'extra_bytes':
            with log.open('ab') as stream:
                stream.write(b'EXTERNAL_WRITER')
        else:
            log.chmod(0o644)

    with monkeypatch.context() as fault:
        fault.setattr(os, 'fsync', changed_sync)
        with pytest.raises(RuntimeDecisionUnavailable):
            app.decide(request(1))
    preserved = log.read_bytes()
    with pytest.raises(RuntimeDecisionUnavailable):
        app.decide(request(2))
    assert log.read_bytes() == preserved
    assert app.pdp._receipt_sequence == 1


def test_failed_fdopen_closes_owned_descriptor(tmp_path, monkeypatch):
    app, _, request = application(tmp_path)
    descriptors = []

    def broken_fdopen(descriptor, mode):
        descriptors.append(descriptor)
        raise OSError('synthetic fdopen error')

    monkeypatch.setattr(os, 'fdopen', broken_fdopen)
    with pytest.raises(RuntimeDecisionUnavailable):
        app.decide(request(1))
    assert len(descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(descriptors[0])


def test_successful_decisions_keep_one_contiguous_log(tmp_path):
    app, log, request = application(tmp_path)
    responses = [app.decide(request(sequence)) for sequence in range(1, 4)]
    persisted = [json.loads(line) for line in log.read_bytes().splitlines()]
    assert persisted == [response['receipt'] for response in responses]
    assert [receipt['chain']['sequence'] for receipt in persisted] == [1, 2, 3]
    assert app.readiness()['ready'] is True


def test_concurrent_successes_serialize_receipts_and_log_snapshots(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    app, log, request = application(tmp_path)
    with ThreadPoolExecutor(max_workers=4) as workers:
        results = list(workers.map(lambda sequence: app.decide(request(sequence)), range(1, 13)))
    persisted = [json.loads(line) for line in log.read_bytes().splitlines()]
    assert [item['chain']['sequence'] for item in persisted] == list(range(1, 13))
    assert sorted((result['receipt'] for result in results),
                  key=lambda item: item['chain']['sequence']) == persisted
    assert app.readiness()['ready'] is True
