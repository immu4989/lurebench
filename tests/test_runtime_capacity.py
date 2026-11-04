"""Bound worker admission and avoid indefinite waiters behind a decision."""

import json
import socket
import tempfile
import threading
from pathlib import Path
from queue import Queue
from types import SimpleNamespace

import pytest

from lurebench import runtime_service as service
from lurebench.permit import build_permit_request
from lurebench.runtime import RuntimePDP, build_runtime_request, default_runtime_profile


def request(profile, sequence=1):
    return json.dumps(build_runtime_request(build_permit_request(sequence=sequence),
        profile=profile, correlation_id=f'capacity-{sequence}',
        nonce=f'capacity-nonce-{sequence}')).encode()


@pytest.mark.parametrize('transport', ['tcp', 'unix', 'ipv6'])
def test_default_worker_admission_is_bounded(transport):
    server = unbound_server(transport)
    release = threading.Event()
    entered = Queue()
    closed = Queue()
    workers = []

    def finish(connection, address):
        workers.append(threading.current_thread())
        entered.put(connection)
        assert release.wait(3.)

    server.finish_request = finish
    server.shutdown_request = closed.put
    try:
        for connection in range(16):
            server.process_request(connection, None)
            assert entered.get(timeout=1.) == connection
        server.process_request(16, None)
        assert closed.get(timeout=.2) == 16
        assert entered.empty()
    finally:
        release.set()
        for worker in workers:
            worker.join(2.)
        server.server_close()


def test_busy_decision_never_enters_engine_and_recovers(tmp_path, monkeypatch):
    profile = default_runtime_profile()
    log = tmp_path / 'receipts.jsonl'
    app = service.RuntimeDecisionApplication(RuntimePDP(profile), log, decision_wait_seconds=0)
    app._lock.acquire()
    try:
        with monkeypatch.context() as blocked:
            blocked.setattr(app.pdp, 'decide', lambda *_: pytest.fail('busy engine entered'))
            with pytest.raises(service.RuntimeDecisionBusy):
                app.decide(request(profile))
        assert log.read_bytes() == b''
        assert app.readiness()['ready'] is True
        assert app.pdp._receipt_sequence == 0
    finally:
        app._lock.release()
    assert app.decide(request(profile))['receipt']['chain']['sequence'] == 1


def test_unix_health_not_serialized_behind_stalled_decision(tmp_path, monkeypatch):
    profile = default_runtime_profile()
    app = service.RuntimeDecisionApplication(RuntimePDP(profile), tmp_path / 'receipts.jsonl')
    server = service._UnixHTTPServer(str(tmp_path / 'unused.sock'), service._Handler,
                                     bind_and_activate=False)
    server.application = app
    writing, release = threading.Event(), threading.Event()
    pairs = [socket.socketpair(), socket.socketpair()]
    failures = []

    def stalled_sync(_):
        writing.set()
        assert release.wait(3.)

    def accept_loop():
        try:
            for peer in (pairs[0][1], pairs[1][1]):
                server.process_request(peer, ('local', 0))
        except BaseException as exc:
            failures.append(exc)

    monkeypatch.setattr(service.os, 'fsync', stalled_sync)
    payload = request(profile)
    pairs[0][0].sendall(b'POST /v1/decide HTTP/1.1\r\nContent-Type: application/json\r\n'
        + f'Content-Length: {len(payload)}\r\n\r\n'.encode() + payload)
    worker = threading.Thread(target=accept_loop)
    worker.start()
    try:
        assert writing.wait(1.)
        pairs[1][0].sendall(b'GET /health HTTP/1.1\r\n\r\n')
        pairs[1][0].settimeout(.5)
        output = bytearray()
        while data := pairs[1][0].recv(65536):
            output.extend(data)
        assert bytes(output).startswith(b'HTTP/1.0 200')
        assert json.loads(output.partition(b'\r\n\r\n')[2])['ready'] is True
    finally:
        release.set()
        worker.join(2.)
        # Drain the decision so its handler finishes before temporary files go away.
        pairs[0][0].settimeout(2.)
        while pairs[0][0].recv(65536):
            pass
        for pair in pairs:
            for peer in pair:
                peer.close()
        server.server_close()
    assert not failures
    assert not worker.is_alive()


def unbound_server(transport='tcp', **kwargs):
    cls, address = {
        'tcp': (service._TCPHTTPServer, ('127.0.0.1', 0)),
        'ipv6': (service._IPv6HTTPServer, ('::1', 0)),
        'unix': (service._UnixHTTPServer, 'unused.sock'),
    }[transport]
    return cls(address, service._Handler, bind_and_activate=False, **kwargs)


@pytest.mark.parametrize('value', [True, False, 0, -1, 257, 1.5, '2', None])
def test_invalid_capacity_refused_before_socket_creation(monkeypatch, value):
    monkeypatch.setattr(service.socket, 'socket', lambda *a: pytest.fail('socket created'))
    with pytest.raises(ValueError, match='max_connections'):
        unbound_server(max_connections=value)
    with pytest.raises(ValueError, match='max_connections'):
        service.serve_runtime(max_connections=value)


@pytest.mark.parametrize('value', [True, False, -1, 31, float('nan'), float('inf'), '1', None])
def test_invalid_wait_refused_before_files_or_socket(tmp_path, monkeypatch, value):
    log = tmp_path / 'receipts.jsonl'
    monkeypatch.setattr(service.socket, 'socket', lambda *a: pytest.fail('socket created'))
    with pytest.raises(ValueError, match='decision_wait_seconds'):
        service.RuntimeDecisionApplication(RuntimePDP(default_runtime_profile()), log,
                                            decision_wait_seconds=value)
    assert not log.exists()
    with pytest.raises(ValueError, match='decision_wait_seconds'):
        service.serve_runtime(receipt_log=log, decision_wait_seconds=value)
    assert not log.exists()


def test_admission_timeout_is_passed_to_lock_without_releasing_unowned_lock(monkeypatch):
    profile = default_runtime_profile()
    app = service.RuntimeDecisionApplication(RuntimePDP(profile), decision_wait_seconds=.125)
    calls = []

    class Lock:
        def acquire(self, *, timeout):
            calls.append(timeout)
            return False

        def release(self):
            pytest.fail('released a lock that was not acquired')

    app._lock = Lock()
    monkeypatch.setattr(app.pdp, 'decide', lambda *_: pytest.fail('engine entered'))
    with pytest.raises(service.RuntimeDecisionBusy):
        app.decide(request(profile))
    assert calls == [.125]
    assert app.readiness()['ready'] is True


def test_real_waiter_expires_without_releasing_current_decision_lock():
    profile = default_runtime_profile()
    app = service.RuntimeDecisionApplication(RuntimePDP(profile), decision_wait_seconds=.01)
    outcomes = Queue()

    def run():
        try:
            outcomes.put(app.decide(request(profile)))
        except BaseException as error:
            outcomes.put(error)

    app._lock.acquire()
    worker = threading.Thread(target=run)
    worker.start()
    try:
        assert isinstance(outcomes.get(timeout=1.), service.RuntimeDecisionBusy)
        assert app._lock.locked()
        assert app.pdp._receipt_sequence == 0
        assert app.readiness()['ready'] is True
    finally:
        app._lock.release()
        worker.join(1.)
    assert not worker.is_alive()


def test_failure_latched_while_waiting_takes_precedence_over_busy():
    app = service.RuntimeDecisionApplication(RuntimePDP(default_runtime_profile()))

    def fail_while_waiting(**kwargs):
        app._unavailable.set()
        return False

    app._lock = SimpleNamespace(acquire=fail_while_waiting)
    with pytest.raises(service.RuntimeDecisionUnavailable):
        app.decide(request(app.pdp.profile))


def test_existing_failure_latch_does_not_wait_for_decision_lock():
    app = service.RuntimeDecisionApplication(RuntimePDP(default_runtime_profile()))
    app._unavailable.set()
    app._lock = SimpleNamespace(acquire=lambda **kw: pytest.fail('waited after failure latch'))
    with pytest.raises(service.RuntimeDecisionUnavailable):
        app.decide(request(app.pdp.profile))


@pytest.mark.parametrize('failure', [False, True])
def test_worker_slot_recovered_after_handler_return_or_error(failure):
    server = unbound_server(max_connections=1)
    finished = Queue()
    workers = Queue()
    errors = []

    def finish(connection, address):
        workers.put(threading.current_thread())
        if failure:
            raise ValueError('synthetic handler failure')

    server.finish_request = finish
    server.shutdown_request = finished.put
    server.handle_error = lambda *a: errors.append(True)
    try:
        for number in range(3):
            server.process_request(number, None)
            assert finished.get(timeout=1.) == number
            worker = workers.get(timeout=1.)
            worker.join(1.)
            assert not worker.is_alive()
        assert len(errors) == (3 if failure else 0)
    finally:
        server.server_close()


@pytest.mark.parametrize('error', [RuntimeError('thread start failed'), KeyboardInterrupt()])
def test_thread_start_failure_closes_socket_and_stops_admission(monkeypatch, error):
    server = unbound_server(max_connections=1)
    client, peer = socket.socketpair()

    def fail_start(_):
        raise error

    try:
        with monkeypatch.context() as failed:
            failed.setattr(threading.Thread, 'start', fail_start)
            with pytest.raises(type(error)):
                server.process_request(peer, None)
        client.settimeout(.5)
        assert client.recv(1) == b''
        assert server._admission_failed.is_set()
        assert not server._connection_slots.acquire(blocking=False)
        # No attempt to infer that a failed/interrupted start created no thread.
        # Restoring Thread.start does not reopen this server's admission.
        another_client, another_peer = socket.socketpair()
        try:
            server.process_request(another_peer, None)
            another_client.settimeout(.5)
            assert another_client.recv(1) == b''
        finally:
            another_client.close()
            another_peer.close()
    finally:
        client.close()
        peer.close()
        server.server_close()


def test_start_error_after_worker_creation_never_releases_slot_twice(monkeypatch):
    server = unbound_server(max_connections=1)
    started, release = threading.Event(), threading.Event()
    workers, errors = [], []
    original = threading.Thread.start

    def finish(*_):
        started.set()
        assert release.wait(2.)

    def interrupted_start(worker):
        workers.append(worker)
        original(worker)
        assert started.wait(1.)
        raise RuntimeError('synthetic error after thread created')

    server.finish_request = finish
    server.shutdown_request = lambda *_: None
    server.handle_error = lambda *_: errors.append(True)
    try:
        with monkeypatch.context() as interrupted:
            interrupted.setattr(threading.Thread, 'start', interrupted_start)
            with pytest.raises(RuntimeError):
                server.process_request(object(), None)
        assert server._admission_failed.is_set()
        assert not server._connection_slots.acquire(blocking=False)
    finally:
        release.set()
        for worker in workers:
            worker.join(1.)
            assert not worker.is_alive()
        server.server_close()
    assert not errors
    assert server._connection_slots.acquire(blocking=False)
    server._connection_slots.release()


def test_saturated_server_closes_accepted_socket_without_parsing_or_writing():
    server = unbound_server(max_connections=1)
    client, peer = socket.socketpair()
    assert server._connection_slots.acquire(blocking=False)
    server.finish_request = lambda *a: pytest.fail('handler allocated at capacity')
    try:
        server.process_request(peer, None)
        client.settimeout(.5)
        assert client.recv(65536) == b''
        assert not server._connection_slots.acquire(blocking=False)
    finally:
        server._connection_slots.release()
        client.close()
        peer.close()
        server.server_close()


@pytest.mark.parametrize('host,expected', [('127.0.0.1', '_TCPHTTPServer'),
                                          ('::1', '_IPv6HTTPServer')])
def test_serve_selects_correct_address_family_and_limits(monkeypatch, host, expected):
    selected = []
    servers = []

    def constructor(name):
        def make(address, handler, **kwargs):
            selected.append((name, address, kwargs))
            server = SimpleNamespace(serve_forever=lambda: None, server_close=lambda: None)
            servers.append(server)
            return server
        return make

    for name in ('_TCPHTTPServer', '_IPv6HTTPServer'):
        monkeypatch.setattr(service, name, constructor(name))
    service.serve_runtime(host=host, max_connections=3, decision_wait_seconds=.25)
    assert selected == [(expected, (host, 8765), {'max_connections': 3})]
    assert servers[0].application._decision_wait_seconds == .25


def test_cli_forwards_limits_and_does_not_claim_readiness_before_bind(monkeypatch, capsys):
    from lurebench.cli import main

    calls = []
    monkeypatch.setattr(service, 'serve_runtime', lambda **kwargs: calls.append(kwargs))
    assert main(['permit-serve', '--host', '::1', '--max-connections', '3',
                 '--decision-wait-seconds', '.25', '--max-decisions', '2']) == 0
    assert calls[0]['max_connections'] == 3
    assert calls[0]['decision_wait_seconds'] == .25
    assert calls[0]['max_decisions'] == 2
    output = capsys.readouterr().out
    assert 'STARTING: http://[::1]:8765' in output
    assert 'READY' not in output


@pytest.mark.parametrize('transport', ['tcp', 'ipv6', 'unix'])
def test_real_listener_saturation_and_recovery(transport):
    workers = Queue()

    class Handler(service._Handler):
        def setup(self):
            super().setup()
            workers.put(threading.current_thread())

    # A short owned pathname fits Unix-domain limits on macOS as well as Linux.
    with tempfile.TemporaryDirectory(prefix='lr-', dir='/tmp') as temporary:
        cls, address = {
            'tcp': (service._TCPHTTPServer, ('127.0.0.1', 0)),
            'ipv6': (service._IPv6HTTPServer, ('::1', 0)),
            'unix': (service._UnixHTTPServer, str(Path(temporary) / 's')),
        }[transport]
        with cls(address, Handler, max_connections=1) as server:
            server.application = service.RuntimeDecisionApplication(
                RuntimePDP(default_runtime_profile()))
            loop = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .01})
            loop.start()

            def connect():
                client = socket.socket(server.address_family, socket.SOCK_STREAM)
                client.settimeout(1.)
                client.connect(server.server_address)
                return client

            def read(client):
                output = bytearray()
                while chunk := client.recv(65536):
                    output.extend(chunk)
                return bytes(output)

            try:
                with connect() as slow:
                    slow.sendall(b'G')
                    worker = workers.get(timeout=1.)
                    with connect() as excess:
                        # Capacity rejection closes without requiring an HTTP request.
                        assert read(excess) == b''
                    assert workers.empty()
                    assert server.application.pdp._receipt_sequence == 0
                    slow.sendall(b'ET /health HTTP/1.1\r\n\r\n')
                    assert read(slow).startswith(b'HTTP/1.0 200')
                worker.join(1.)
                assert not worker.is_alive()
                with connect() as recovered:
                    recovered.sendall(b'GET /health HTTP/1.1\r\n\r\n')
                    worker = workers.get(timeout=1.)
                    reply = read(recovered)
                    assert reply.startswith(b'HTTP/1.0 200')
                    assert json.loads(reply.partition(b'\r\n\r\n')[2])['ready'] is True
                worker.join(1.)
                assert not worker.is_alive()
                if transport == 'unix':
                    assert Path(server.server_address).stat().st_mode & 0o777 == 0o600
            finally:
                server.shutdown()
                loop.join(1.)
                assert not loop.is_alive()
