"""Run the actual HTTP parser over deterministic in-memory socket streams."""

import io
import json
import socket
import threading
from types import SimpleNamespace

import pytest

from lurebench.runtime_service import _Handler


class MemoryConnection:
    def __init__(self, payload):
        self.input = io.BytesIO(payload)
        self.output = bytearray()
        self.timeouts = []

    def makefile(self, *args, **kwargs):
        return self.input

    def sendall(self, payload):
        self.output.extend(payload)

    def settimeout(self, value):
        self.timeouts.append(value)


def exchange(headers, body=b'{}', *, decide=None, readiness=None, method=b'POST',
             target=b'/v1/decide', suffix=b'', request_line=None):
    calls = []

    def application(payload):
        calls.append(payload)
        return decide(payload) if decide else {"synthetic": True}

    line = request_line or method + b' ' + target + b' HTTP/1.1'
    wire = line + b'\r\n' + b''.join(k + b': ' + v + b'\r\n' for k, v in headers)
    connection = MemoryConnection(wire + b'\r\n' + body + suffix)
    _Handler(connection, ('127.0.0.1', 12345),
             SimpleNamespace(application=SimpleNamespace(decide=application, readiness=readiness
                 or (lambda: {"ready": True, "status": "ready", "executes_actions": False}))))
    head, separator, content = bytes(connection.output).partition(b'\r\n\r\n')
    assert separator
    status = int(head.split(b' ', 2)[1])
    return status, head, content, calls


@pytest.mark.parametrize("headers,status", [
    ([(b'Content-Length', b'2'), (b'content-length', b'2')], 400),
    ([(b'Content-Length', b'2'), (b'content-length', b'999')], 400),
    ([(b'Content-Length', b'2, 2')], 400),
    ([(b'Content-Length', b'+2')], 400),
    ([(b'Content-Length', b'-2')], 400),
    ([(b'Content-Length', b'2_0')], 400),
    ([(b'Content-Length', b'\xb2')], 400),
    ([(b'Content-Length', b'')], 400),
    ([(b'Content-Length', b'9' * 21)], 400),
    ([(b'Content-Length', b'65537')], 413),
    ([], 411),
    ([(b'Transfer-Encoding', b'chunked'), (b'Content-Length', b'2')], 400),
    ([(b'Transfer-Encoding', b'identity'), (b'Content-Length', b'2')], 400),
    ([(b'Transfer-Encoding', b'chunked')], 400),
    ([(b'Content-Length', b'2'), (b'Content-Encoding', b'gzip')], 415),
    ([(b'Content-Length', b'2'), (b'Content-Encoding', b'identity'),
      (b'Content-Encoding', b'identity')], 400),
    ([(b'Content-Length', b'2'), (b'Expect', b'100-continue')], 417),
    ([(b'Content-Length', b'2'), (b'Content-Type', b'application/json')], 400),
    ([(b'Content-Length', b'2'), (b'Content-Type', b'text/plain')], 400),
])
def test_ambiguous_or_unsupported_headers_never_reach_application(headers, status):
    result = exchange(headers + [(b'Content-Type', b'application/json')])
    assert result[0] == status
    assert result[3] == []
    assert b'Connection: close' in result[1]


def test_truncated_body_never_reaches_application():
    status, _, body, calls = exchange(
        [(b'Content-Length', b'10'), (b'Content-Type', b'application/json')], b'{}')
    assert status == 400
    assert calls == []
    assert json.loads(body) == {"error": "incomplete_request_body"}


@pytest.mark.parametrize("error,status", [
    (ValueError('PRIVATE_SENTINEL'), 400),
    (OverflowError('PRIVATE_SENTINEL'), 413),
    (OSError('PRIVATE_SENTINEL'), 503),
    (RuntimeError('PRIVATE_SENTINEL'), 500),
])
def test_processing_errors_are_fixed_and_redacted(error, status):
    def decide(payload):
        raise error

    actual, head, body, calls = exchange(
        [(b'Content-Length', b'2'), (b'Content-Type', b'application/json')], decide=decide)
    assert actual == status
    assert len(calls) == 1
    assert b'PRIVATE_SENTINEL' not in head + body
    assert set(json.loads(body)) == {'error'}


@pytest.mark.parametrize("line", [
    b'PRIVATE_SENTINEL / HTTP/1.1',
    b'GET / HTTP/PRIVATE_SENTINEL',
    b'PRIVATE_SENTINEL',
    b'POST /PRIVATE_SENTINEL',
    b'GET /PRIVATE_SENTINEL HTTP/2.0',
    b'GET /PRIVATE_SENTINEL HTTP/12345678901.0',
    b'GET /PRIVATE_SENTINEL HTTP/1.1 EXTRA',
])
def test_framework_errors_do_not_reflect_request_line(line):
    status, head, body, calls = exchange([], request_line=line)
    assert status in (400, 501, 505)
    assert calls == []
    assert b'PRIVATE_SENTINEL' not in head + body
    assert b'Content-Type: application/json' in head
    assert b'Connection: close' in head
    assert json.loads(body) == {"error": "invalid_http_request"}


def test_valid_request_retains_exact_bytes_and_closes_before_pipeline():
    status, head, body, calls = exchange(
        [(b'Content-Length', b'2'), (b'Content-Type', b'application/json')],
        suffix=b'POST /v1/decide HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}')
    assert status == 200
    assert calls == [b'{}']
    assert json.loads(body) == {"synthetic": True}
    assert b'Connection: close' in head


def test_decision_admission_busy_is_fixed_json_without_receipt_or_state(tmp_path):
    from lurebench.permit import build_permit_request
    from lurebench.runtime import RuntimePDP, build_runtime_request, default_runtime_profile
    from lurebench.runtime_service import RuntimeDecisionApplication

    profile = default_runtime_profile()
    log = tmp_path / 'receipts.jsonl'
    app = RuntimeDecisionApplication(RuntimePDP(profile), log, decision_wait_seconds=0)
    value = build_runtime_request(build_permit_request(sequence=1), profile=profile,
                                  correlation_id='busy', nonce='busy-nonce')
    payload = json.dumps(value).encode()
    app._lock.acquire()
    try:
        status, head, body, calls = exchange([
            (b'Content-Length', str(len(payload)).encode()),
            (b'Content-Type', b'application/json'),
        ], payload, decide=app.decide)
        assert status == 503
        assert json.loads(body) == {'error': 'runtime_busy'}
        assert b'Connection: close' in head
        assert calls == [payload]
        assert app.pdp._receipt_sequence == 0
        assert app.readiness()['ready'] is True
        assert log.read_bytes() == b''
    finally:
        app._lock.release()
    assert app.decide(payload)['receipt']['chain']['sequence'] == 1


@pytest.mark.parametrize("headers", [
    [(b'Content-Length', b'\t0002\t'), (b'Content-Type', b'Application/JSON; charset=utf-8')],
    [(b'Content-Length', b'2'), (b'Content-Type', b'application/json'),
     (b'Content-Encoding', b'IDENTITY')],
])
def test_supported_fixed_length_variants(headers):
    status, _, _, calls = exchange(headers)
    assert status == 200
    assert calls == [b'{}']


@pytest.mark.parametrize("headers", [
    [(b'Content-Length', b'2')],
    [(b'Content-Length', b'2'), (b'Content-Type', b'text/plain')],
    [(b'Content-Length', b'2'), (b'Content-Type', b'application/json'),
     (b'Content-Encoding', b'')],
])
def test_unsupported_content_is_rejected_without_body_processing(headers):
    status, _, _, calls = exchange(headers)
    assert status == 415
    assert not calls


def test_obsolete_folded_headers_are_rejected():
    status, _, _, calls = exchange([
        (b'Content-Length', b'2'), (b'Content-Type', b'application/json'),
        (b'X-Note', b'first\r\n second'),
    ])
    assert status == 400
    assert not calls


def test_actual_duplicate_json_key_does_not_leak():
    from lurebench.runtime import RuntimePDP, default_runtime_profile
    from lurebench.runtime_service import RuntimeDecisionApplication

    application = RuntimeDecisionApplication(RuntimePDP(default_runtime_profile()))
    payload = b'{"PRIVATE_SENTINEL":1,"PRIVATE_SENTINEL":2}'
    status, _, body, _ = exchange(
        [(b'Content-Length', str(len(payload)).encode()), (b'Content-Type', b'application/json')],
        payload, decide=application.decide)
    assert status == 400
    assert json.loads(body) == {"error": "invalid_request"}
    assert application.pdp._receipt_sequence == 0


def test_valid_request_preserves_receipt_and_rejected_framing_has_no_state(tmp_path):
    from lurebench.permit import build_permit_request
    from lurebench.runtime import (
        RuntimePDP,
        build_runtime_request,
        default_runtime_profile,
        validate_runtime_receipt,
    )
    from lurebench.runtime_service import RuntimeDecisionApplication

    profile = default_runtime_profile()
    request = build_runtime_request(build_permit_request(sequence=1), profile=profile,
                                    correlation_id="http-test", nonce="http-nonce")
    log = tmp_path / "receipts.jsonl"
    application = RuntimeDecisionApplication(RuntimePDP(profile), log)
    payload = json.dumps(request, indent=2).encode()
    headers = [(b'Content-Length', str(len(payload)).encode()),
               (b'Content-Type', b'application/json')]
    status, _, _, calls = exchange(headers + [headers[0]], payload, decide=application.decide)
    assert status == 400 and not calls
    assert log.read_bytes() == b''
    assert application.pdp._receipt_sequence == 0
    status, _, body, calls = exchange(headers, payload, decide=application.decide)
    assert status == 200 and calls == [payload]
    receipt = json.loads(body)["receipt"]
    assert json.loads(log.read_bytes()) == receipt
    assert validate_runtime_receipt(receipt, request, previous_receipt_sha256=None,
                                    expected_sequence=1) == receipt


def test_absolute_body_deadline_does_not_reset_after_each_chunk(monkeypatch):
    import lurebench.runtime_service as service

    clock = [0.]
    monkeypatch.setattr(service.time, "monotonic", lambda: clock[0])
    handler = object.__new__(_Handler)
    handler.connection = MemoryConnection(b'')

    class Drip:
        def read1(self, maximum):
            clock[0] += 2.
            return b'x'

    handler.rfile = Drip()
    with pytest.raises(TimeoutError):
        handler._read_body(10)
    assert clock[0] == 6.
    assert handler.connection.timeouts == [5., 3., 1., 5.]


def test_last_chunk_after_deadline_is_not_admitted(monkeypatch):
    import lurebench.runtime_service as service

    clock = [0.]
    monkeypatch.setattr(service.time, "monotonic", lambda: clock[0])
    handler = object.__new__(_Handler)
    handler.connection = MemoryConnection(b'')

    class Slow:
        def read1(self, maximum):
            clock[0] = 6.
            return b'{}'

    handler.rfile = Slow()
    with pytest.raises(TimeoutError):
        handler._read_body(2)


def test_socket_timeout_returns_redacted_408_before_application(monkeypatch):
    def expired(self, length):
        raise TimeoutError('PRIVATE_SENTINEL')

    monkeypatch.setattr(_Handler, '_read_body', expired)
    status, head, body, calls = exchange(
        [(b'Content-Length', b'2'), (b'Content-Type', b'application/json')])
    assert status == 408 and not calls
    assert json.loads(body) == {"error": "request_body_timeout"}
    assert b'PRIVATE_SENTINEL' not in head + body


@pytest.mark.parametrize("target", [b'/health', b'/openapi.json'])
def test_readonly_endpoints_and_head_error_do_not_invoke_decision(target):
    status, head, body, calls = exchange([], body=b'', method=b'GET', target=target)
    assert status == 200 and not calls
    assert b'Connection: close' in head and b'Python/' not in head
    assert isinstance(json.loads(body), dict)
    status, head, body, calls = exchange([], body=b'', method=b'HEAD', target=target)
    assert status == 501 and not calls and body == b''
    assert b'Connection: close' in head


@pytest.mark.parametrize("body,half_close,expected", [
    (b'{}', True, 200), (b'{', True, 400), (b'{', False, 408),
])
def test_real_socket_body_completion_and_timeout(monkeypatch, body, half_close, expected):
    import lurebench.runtime_service as service

    monkeypatch.setattr(service, 'REQUEST_BODY_TIMEOUT_SECONDS', .05 if expected == 408 else 5.)
    calls, failures = [], []

    def decide(payload):
        calls.append(payload)
        return {"synthetic": True}

    server = SimpleNamespace(application=SimpleNamespace(decide=decide))
    client, peer = socket.socketpair()

    def handle():
        try:
            with peer:
                _Handler(peer, ('127.0.0.1', 12345), server)
        except Exception as exc:
            failures.append(exc)

    worker = threading.Thread(target=handle, daemon=True)
    worker.start()
    try:
        with client:
            client.settimeout(2.)
            client.sendall(b'POST /v1/decide HTTP/1.1\r\nContent-Length: 2\r\n'
                           b'Content-Type: application/json\r\n\r\n' + body)
            if half_close:
                client.shutdown(socket.SHUT_WR)
            chunks = []
            while chunk := client.recv(65536):
                chunks.append(chunk)
        response = b''.join(chunks)
        assert int(response.split(b' ', 2)[1]) == expected
        assert calls == ([b'{}'] if expected == 200 else [])
        assert b'Connection: close' in response
    finally:
        client.close()
        worker.join(timeout=2.)
        assert not worker.is_alive()
        assert not failures


def test_audit_failure_disables_http_decisions_and_health(tmp_path, monkeypatch):
    import os

    from lurebench.permit import build_permit_request
    from lurebench.runtime import RuntimePDP, build_runtime_request, default_runtime_profile
    from lurebench.runtime_service import RuntimeDecisionApplication

    profile = default_runtime_profile()
    log = tmp_path / 'PRIVATE_LOG_PATH.jsonl'
    app = RuntimeDecisionApplication(RuntimePDP(profile), log)

    def post(sequence):
        request = build_runtime_request(build_permit_request(sequence=sequence), profile=profile,
                                        correlation_id=f'http-{sequence}', nonce=f'nonce-{sequence}')
        payload = json.dumps(request).encode()
        return exchange([(b'Content-Length', str(len(payload)).encode()),
                         (b'Content-Type', b'application/json')], payload,
                        decide=app.decide, readiness=app.readiness)

    healthy = exchange([], body=b'', method=b'GET', target=b'/health', readiness=app.readiness)
    assert healthy[0] == 200 and json.loads(healthy[2])['receipt_logging'] is True
    with monkeypatch.context() as fault:
        def failed_sync(descriptor):
            raise OSError('PRIVATE_SYNC_DETAIL')

        fault.setattr(os, 'fsync', failed_sync)
        status, head, body, _ = post(1)
    assert status == 503
    assert json.loads(body) == {'error': 'runtime_unavailable'}
    assert b'PRIVATE' not in head + body
    preserved = log.read_bytes()
    status, head, body, _ = exchange([], body=b'', method=b'GET', target=b'/health',
                                    readiness=app.readiness)
    assert status == 503 and b'PRIVATE' not in head + body
    assert json.loads(body) == {'ready': False, 'status': 'unavailable',
                               'reason': 'receipt_log_failed', 'receipt_logging': True,
                               'decision_budget': {'limit': 512, 'evaluated': 1, 'remaining': 511},
                               'executes_actions': False}
    assert post(2)[0] == 503
    assert log.read_bytes() == preserved
    assert app.pdp._receipt_sequence == 1


def test_exhaustion_returns_fixed_error_and_unavailable_health(tmp_path):
    from lurebench.permit import build_permit_request
    from lurebench.runtime import RuntimePDP, build_runtime_request
    from lurebench.runtime_service import RuntimeDecisionApplication

    log = tmp_path / 'receipts.jsonl'
    app = RuntimeDecisionApplication(RuntimePDP(), log, max_decisions=1)
    value = build_runtime_request(build_permit_request(sequence=1), profile=app.pdp.profile,
                                  correlation_id='exhaustion', nonce='exhaustion-nonce')
    payload = json.dumps(value).encode()
    headers = [(b'Content-Length', str(len(payload)).encode()), (b'Content-Type', b'application/json')]
    assert exchange(headers, payload, decide=app.decide)[0] == 200
    preserved = log.read_bytes()
    status, head, body, _ = exchange(headers, payload, decide=app.decide)
    assert status == 503 and b'Connection: close' in head
    assert json.loads(body) == {'error': 'runtime_exhausted'}
    health = exchange([], body=b'', method=b'GET', target=b'/health', readiness=app.readiness)
    assert health[0] == 503
    assert json.loads(health[2])['reason'] == 'decision_limit_reached'
    assert json.loads(health[2])['decision_budget'] == {'limit': 1, 'evaluated': 1, 'remaining': 0}
    assert app.pdp.receipt_count == 1 and log.read_bytes() == preserved
