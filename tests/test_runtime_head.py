"""Bound the complete request head before framework parsing or application work."""

import io
import json
import select
import socket
import tempfile
import threading
import time
from pathlib import Path
from queue import Queue
from types import SimpleNamespace

import pytest

from lurebench import runtime_service as service


class Connection:
    def __init__(self, wire, source=None):
        self.source = source if source is not None else io.BytesIO(wire)
        self.output = bytearray()
        self.timeouts = []

    def makefile(self, *args, **kwargs):
        return self.source

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def sendall(self, data):
        self.output.extend(data)


def exchange(wire, *, source=None, application=None):
    calls = []

    def health():
        calls.append('health')
        return {'ready': True}

    def decide(payload):
        calls.append(payload)
        return {'synthetic': True}

    connection = Connection(wire, source)
    service._Handler(connection, ('127.0.0.1', 1), SimpleNamespace(
        application=application or SimpleNamespace(readiness=health, decide=decide)))
    raw = bytes(connection.output)
    if not raw:
        return None, b'', b'', calls, connection
    head, _, body = raw.partition(b'\r\n\r\n')
    return int(head.split(b' ', 2)[1]), head, body, calls, connection


def test_total_head_deadline_precedes_application(monkeypatch):
    clock = [0.]
    monkeypatch.setattr(service.time, 'monotonic', lambda: clock[0])

    class Trickle(io.BytesIO):
        def readline(self, size=-1):
            clock[0] += 2.
            return super().readline(size)

        def read1(self, size=-1):
            clock[0] += 2.
            return super().read1(min(size, 12))

    wire = b'GET /health HTTP/1.1\r\nX-Synthetic: yes\r\n\r\n'
    status, _, body, calls, _ = exchange(wire, source=Trickle(wire))
    assert status == 408
    assert not calls
    assert json.loads(body) == {'error': 'request_head_timeout'}


def test_aggregate_head_byte_limit_precedes_application():
    wire = b'GET /health HTTP/1.1\r\n' + b'X-Synthetic: ' + b'x' * 20000 + b'\r\n\r\n'
    status, _, body, calls, _ = exchange(wire)
    assert status == 431
    assert not calls
    assert json.loads(body) == {'error': 'request_head_too_large'}


def test_eof_without_blank_line_does_not_reach_health():
    status, _, body, calls, _ = exchange(b'GET /health HTTP/1.1\r\nX-Synthetic: yes\r\n')
    assert status == 400
    assert not calls
    assert json.loads(body) == {'error': 'incomplete_request_head'}


@pytest.mark.parametrize('delta,status', [(-1, 200), (0, 200), (1, 431)])
def test_exact_aggregate_head_boundary(delta, status):
    prefix, suffix = b'GET /health HTTP/1.1\r\nX-Pad: ', b'\r\n\r\n'
    padding = service.MAX_REQUEST_HEAD_BYTES - len(prefix + suffix) + delta
    wire = prefix + b'x' * padding + suffix
    result = exchange(wire)
    assert result[0] == status
    assert bool(result[3]) == (status == 200)


def test_many_individually_small_fields_share_one_head_budget():
    result = exchange(b'GET /health HTTP/1.1\r\n' + (b'X-Pad: ' + b'x' * 1000 + b'\r\n') * 20
                      + b'\r\n')
    assert result[0] == 431 and not result[3]


def test_request_line_overflow_is_414_without_reflection():
    result = exchange(b'GET /PRIVATE_TARGET' + b'x' * service.MAX_REQUEST_HEAD_BYTES
                      + b' HTTP/1.1\r\n\r\n')
    assert result[0] == 414 and not result[3]
    assert json.loads(result[2]) == {'error': 'request_line_too_large'}
    assert b'PRIVATE_TARGET' not in result[1] + result[2]


def test_head_size_counts_wire_bytes_not_unicode_characters():
    result = exchange(b'GET /health HTTP/1.1\r\nX-Pad: ' + 'é'.encode() * 9000 + b'\r\n\r\n')
    assert result[0] == 431 and not result[3]


def test_framework_header_count_limit_is_retained():
    result = exchange(b'GET /health HTTP/1.1\r\n' + b'X-Pad: x\r\n' * 101 + b'\r\n')
    assert result[0] == 431 and not result[3]


@pytest.mark.parametrize('width', [1, 2, 3, 17, 4096])
@pytest.mark.parametrize('ending', [b'\r\n', b'\n'])
def test_arbitrary_head_body_splits_preserve_exact_bytes_and_ignore_pipeline(width, ending):
    payload = b'x' * service.MAX_REQUEST_BYTES
    wire = ending.join([b'POST /v1/decide HTTP/1.1', b'Content-Type: application/json',
                        f'Content-Length: {len(payload)}'.encode(), b'', b'']) + payload
    wire += b'GET /health HTTP/1.1\r\n\r\n'

    class Fragmented(io.BytesIO):
        def read1(self, size=-1):
            return super().read1(min(size, width))

    result = exchange(wire, source=Fragmented(wire))
    assert result[0] == 200 and result[3] == [payload]


@pytest.mark.parametrize('wire', [b'GET /health', b'GET /health HTTP/1.1\r\n',
                                b'GET /health HTTP/1.1\r\nX-Pad: partial'])
def test_partial_request_head_eof_is_rejected(wire):
    result = exchange(wire)
    assert result[0] == 400 and not result[3]


def test_empty_connection_eof_has_no_response():
    result = exchange(b'')
    assert result[:4] == (None, b'', b'', [])


@pytest.mark.parametrize('version', [b'', b' HTTP/0.9', b' HTTP/00.09', b' HTTP/0.8'])
def test_versionless_http_is_not_a_raw_json_response(version):
    result = exchange(b'GET /health' + version + b'\r\n\r\n')
    assert result[0] == 400 and not result[3]
    assert json.loads(result[2]) == {'error': 'invalid_http_request'}


def test_http1_version_normalization_is_still_handled_by_framework():
    result = exchange(b'GET /health HTTP/01.01\r\n\r\n')
    assert result[0] == 200 and result[3] == ['health']


def test_overflow_reads_at_most_one_sentinel_byte_past_head_limit():
    class Counted(io.BytesIO):
        def __init__(self, value):
            super().__init__(value)
            self.requested = []
            self.received = 0

        def read1(self, size=-1):
            self.requested.append(size)
            value = super().read1(size)
            self.received += len(value)
            return value

    source = Counted(b'GET /health HTTP/1.1\r\nX-Pad: ' + b'x' * 100000)
    result = exchange(b'', source=source)
    assert result[0] == 431
    assert source.received == service.MAX_REQUEST_HEAD_BYTES + 1
    assert max(source.requested) <= 4096


@pytest.mark.parametrize('error,status,code', [
    (TimeoutError('PRIVATE_TIMEOUT'), 408, 'request_head_timeout'),
    (OSError('PRIVATE_SOCKET'), 400, 'request_head_unavailable'),
])
def test_head_io_failure_is_redacted_and_closes_input(error, status, code):
    class Broken(io.BytesIO):
        def read1(self, size=-1):
            raise error

    source = Broken()
    result = exchange(b'', source=source)
    assert result[0] == status and not result[3]
    assert json.loads(result[2]) == {'error': code}
    assert b'PRIVATE_' not in result[1] + result[2]
    assert source.closed
    assert result[4].timeouts[-1] == service._Handler.timeout


def test_unwritable_rejection_does_not_resume_parsing(monkeypatch):
    def broken(*args):
        raise BrokenPipeError('synthetic closed peer')

    monkeypatch.setattr(Connection, 'sendall', broken)
    result = exchange(b'GET /health HTTP/1.1\r\n')
    assert result[0] is None and not result[3]
    assert result[4].source.closed


def test_head_overflow_never_evaluates_or_appends(tmp_path, monkeypatch):
    from lurebench.runtime import RuntimePDP

    log = tmp_path / 'receipts.jsonl'
    app = service.RuntimeDecisionApplication(RuntimePDP(), log)
    monkeypatch.setattr(app.pdp, 'decide', lambda *a: pytest.fail('oversized head evaluated'))
    result = exchange(b'POST /v1/decide HTTP/1.1\r\nX-Pad: '
                      + b'x' * service.MAX_REQUEST_HEAD_BYTES + b'\r\n\r\n{}', application=app)
    assert result[0] == 431
    assert log.read_bytes() == b'' and app.pdp.receipt_count == 0
    assert app.readiness()['ready'] is True


def test_head_requests_have_no_body_even_when_head_is_rejected():
    result = exchange(b'HEAD /health HTTP/1.1\r\nX-Pad: '
                      + b'x' * service.MAX_REQUEST_HEAD_BYTES + b'\r\n\r\n')
    assert result[0] == 431 and result[2] == b'' and not result[3]


def test_header_deadline_is_not_the_body_deadline(monkeypatch):
    clock = [0.]
    monkeypatch.setattr(service.time, 'monotonic', lambda: clock[0])
    head = b'POST /v1/decide HTTP/1.1\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n'

    class Phased(io.BytesIO):
        def read1(self, size=-1):
            clock[0] += 4.
            return super().read1(min(size, len(head)))

    result = exchange(b'', source=Phased(head + b'{}'))
    assert result[0] == 200 and result[3] == [b'{}']
    assert clock[0] == 8.


def test_late_final_head_chunk_does_not_enter_application(monkeypatch):
    clock = [0.]
    monkeypatch.setattr(service.time, 'monotonic', lambda: clock[0])

    class Late(io.BytesIO):
        def read1(self, size=-1):
            clock[0] = service.REQUEST_HEAD_TIMEOUT_SECONDS
            return super().read1(size)

    wire = b'GET /health HTTP/1.1\r\n\r\n'
    result = exchange(wire, source=Late(wire))
    assert result[0] == 408 and not result[3]


@pytest.mark.parametrize('transport', ['tcp', 'ipv6', 'unix'])
def test_real_listener_slow_head_closes_and_restores_worker_capacity(transport, monkeypatch):
    monkeypatch.setattr(service, 'REQUEST_HEAD_TIMEOUT_SECONDS', .15)
    workers = Queue()
    calls = []

    class Handler(service._Handler):
        def setup(self):
            super().setup()
            workers.put(threading.current_thread())

    with tempfile.TemporaryDirectory(prefix='lh-', dir='/tmp') as directory:
        cls, address = {
            'tcp': (service._TCPHTTPServer, ('127.0.0.1', 0)),
            'ipv6': (service._IPv6HTTPServer, ('::1', 0)),
            'unix': (service._UnixHTTPServer, str(Path(directory) / 'runtime.sock')),
        }[transport]
        with cls(address, Handler, max_connections=1) as server:
            server.application = SimpleNamespace(
                readiness=lambda: calls.append('health') or {'ready': True})
            loop = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .01},
                                    daemon=True)
            loop.start()
            try:
                with socket.socket(server.address_family, socket.SOCK_STREAM) as slow:
                    slow.settimeout(2)
                    slow.connect(server.server_address)
                    worker = workers.get(timeout=1)
                    slow.sendall(b'GET /health HTTP/1.1\r\nX-Pad: ')
                    started = time.monotonic()
                    while time.monotonic() - started < .25:
                        # Stop uploading as soon as the error/EOF is readable;
                        # continuing after close can legitimately trigger TCP RST.
                        if select.select([slow], [], [], .02)[0]:
                            break
                        try:
                            slow.sendall(b'x')
                        except OSError:
                            break
                    output = bytearray()
                    try:
                        while part := slow.recv(65536):
                            output.extend(part)
                    except ConnectionResetError:
                        pass  # The response still has to be complete and correct below.
                assert int(output.split(b' ', 2)[1]) == 408
                assert json.loads(output.partition(b'\r\n\r\n')[2]) == {
                    'error': 'request_head_timeout'}
                worker.join(1)
                assert not worker.is_alive() and not calls
                with socket.socket(server.address_family, socket.SOCK_STREAM) as healthy:
                    healthy.settimeout(2)
                    healthy.connect(server.server_address)
                    next_worker = workers.get(timeout=1)
                    healthy.sendall(b'GET /health HTTP/1.1\r\n\r\n')
                    output = bytearray()
                    while part := healthy.recv(65536):
                        output.extend(part)
                assert int(output.split(b' ', 2)[1]) == 200
                next_worker.join(1)
                assert not next_worker.is_alive() and calls == ['health']
            finally:
                server.shutdown()
                loop.join(1)
                assert not loop.is_alive()
