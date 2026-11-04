"""Loopback or Unix-socket LurePermit policy decision service."""

from __future__ import annotations

import io
import ipaddress
import json
import math
import os
import socket
import socketserver
import stat
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, Optional

from .permit import _canonical, loads_strict_json
from .runtime import (
    MAX_RUNTIME_REQUESTS,
    RECEIPT_SCHEMA,
    REQUEST_SCHEMA,
    RuntimeCapacityExceeded,
    RuntimePDP,
    load_runtime_profile,
    validate_runtime_request,
)

MAX_REQUEST_BYTES = 64 * 1024
MAX_REQUEST_JSON_NODES = 4096
REQUEST_BODY_TIMEOUT_SECONDS = 5.0
MAX_REQUEST_HEAD_BYTES = 16 * 1024
REQUEST_HEAD_TIMEOUT_SECONDS = 5.0
DEFAULT_MAX_CONNECTIONS = 16
DEFAULT_DECISION_WAIT_SECONDS = 1.0


def _decision_limit(value: int) -> int:
    if type(value) is not int or not 1 <= value <= MAX_RUNTIME_REQUESTS:
        raise ValueError(f"max_decisions must be an integer from 1 through {MAX_RUNTIME_REQUESTS}")
    return value


def _connection_limit(value: int) -> int:
    if type(value) is not int or not 1 <= value <= 256:
        raise ValueError("max_connections must be an integer from 1 through 256")
    return value


def _decision_wait(value: float) -> float:
    if type(value) not in (int, float) or not 0 <= value <= 30 or not math.isfinite(value):
        raise ValueError("decision_wait_seconds must be finite and between 0 and 30")
    return float(value)


def runtime_openapi() -> Dict[str, Any]:
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "LurePermit Runtime Decision API",
            "version": "1.0.0",
            "description": "Typed metadata-only policy decisions; this service executes no action.",
        },
        "servers": [{"url": "http://127.0.0.1:8765"}],
        "paths": {
            "/health": {"get": {"responses": {
                "200": {"description": "Ready"},
                "400": {"description": "Malformed or incomplete request head"},
                "408": {"description": "Request head deadline exceeded"},
                "414": {"description": "Request line exceeds the 16 KiB head budget"},
                "431": {"description": "Request head exceeds byte or field-count limits"},
                "503": {"description": "Runtime unavailable; operator recovery required"},
            }}},
            "/openapi.json": {"get": {"responses": {
                "200": {"description": "OpenAPI document"},
                "400": {"description": "Malformed or incomplete request head"},
                "408": {"description": "Request head deadline exceeded"},
                "414": {"description": "Request line exceeds the 16 KiB head budget"},
                "431": {"description": "Request head exceeds byte or field-count limits"},
            }}},
            "/v1/decide": {
                "post": {
                    "description": "Evaluate one LurePermit runtime request without executing it.",
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": {"$ref": REQUEST_SCHEMA}}},
                    },
                    "responses": {
                        "200": {
                            "description": "Bound decision and hash-chained receipt",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/DecisionResponse"}
                                }
                            },
                        },
                        "400": {"description": "Malformed or unsupported request"},
                        "408": {"description": "Request head or body deadline exceeded"},
                        "411": {"description": "Content-Length required"},
                        "413": {"description": "Request exceeds 64 KiB"},
                        "414": {"description": "Request line exceeds the 16 KiB head budget"},
                        "415": {"description": "Unsupported content type or encoding"},
                        "417": {"description": "Expect is not supported"},
                        "431": {"description": "Request head exceeds byte or field-count limits"},
                        "500": {"description": "Internal decision error; outcome may be uncertain"},
                        "503": {"description": (
                            "Runtime busy or exhausted before evaluation, or unavailable "
                            "with uncertain outcome"
                        )},
                    },
                }
            },
        },
        "components": {
            "schemas": {
                "Decision": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["request_id", "sequence", "decision", "reason_code"],
                    "properties": {
                        "request_id": {"type": "string"},
                        "sequence": {"type": "integer", "minimum": 1},
                        "decision": {"enum": ["allow", "block", "stop"]},
                        "reason_code": {"type": "string"},
                    },
                },
                "DecisionResponse": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["decision", "receipt", "interpretation_boundary"],
                    "properties": {
                        "decision": {"$ref": "#/components/schemas/Decision"},
                        "receipt": {"$ref": RECEIPT_SCHEMA},
                        "interpretation_boundary": {"type": "string"},
                    },
                },
            }
        },
    }


class RuntimeDecisionUnavailable(RuntimeError):
    """Latched runtime failure; no later decision is admitted by this instance."""

    def __init__(self):
        super().__init__("runtime decision service requires operator recovery")


class RuntimeDecisionBusy(RuntimeError):
    """This request did not acquire the decision lock or enter the engine."""

    def __init__(self):
        super().__init__("runtime decision admission is busy")


class RuntimeDecisionExhausted(RuntimeError):
    """Planned session exhaustion, not an authorization or a storage error."""

    def __init__(self):
        super().__init__("runtime decision budget is exhausted; operator review required")


def _log_metadata(info: os.stat_result) -> tuple:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            info.st_mode, info.st_nlink)


def _check_log_file(info: os.stat_result) -> None:
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or (os.name == "posix" and info.st_mode & 0o077)):
        raise OSError("receipt log must remain a private single-link regular file")


class RuntimeDecisionApplication:
    def __init__(self, pdp: RuntimePDP, receipt_log: Optional[Path] = None, *,
                 decision_wait_seconds: float = DEFAULT_DECISION_WAIT_SECONDS,
                 max_decisions: int = MAX_RUNTIME_REQUESTS):
        self._max_decisions = _decision_limit(max_decisions)
        self._decision_wait_seconds = _decision_wait(decision_wait_seconds)
        if pdp.receipt_count != 0:
            raise ValueError("a runtime application requires an unused runtime decision engine")
        self.pdp = pdp
        self.receipt_log = Path(receipt_log).absolute() if receipt_log is not None else None
        self._lock = threading.Lock()
        self._unavailable = threading.Event()
        self._exhausted = threading.Event()
        self._failure_reason = "ready"
        self._log_snapshot = None
        if self.receipt_log is not None:
            if self.receipt_log.exists() or self.receipt_log.is_symlink():
                raise FileExistsError(f"{self.receipt_log} already exists")
            if self.receipt_log.parent.is_symlink() or not self.receipt_log.parent.is_dir():
                raise ValueError("receipt log parent must be a regular local directory")
            descriptor = os.open(
                self.receipt_log,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                0o600,
            )
            try:
                info = os.fstat(descriptor)
                _check_log_file(info)
                if info.st_size != 0:
                    raise OSError("new receipt log is not empty")
                self._log_snapshot = _log_metadata(info)
                self._check_log_snapshot()
            finally:
                os.close(descriptor)

    def readiness(self) -> Dict[str, Any]:
        """Snapshot of failure/exhaustion state, not a live disk or progress probe."""
        evaluated = self.pdp.receipt_count
        unavailable = self._unavailable.is_set()
        exhausted = self._exhausted.is_set() or evaluated >= self._max_decisions
        ready = not unavailable and not exhausted
        reason = self._failure_reason if unavailable else (
            "decision_limit_reached" if exhausted else "ready")
        return {"ready": ready, "status": "ready" if ready else "unavailable",
                "reason": reason,
                "decision_budget": {"limit": self._max_decisions, "evaluated": evaluated,
                                    "remaining": max(0, self._max_decisions - evaluated)},
                "receipt_logging": self.receipt_log is not None, "executes_actions": False}

    def _check_admission(self) -> None:
        if self._unavailable.is_set():
            raise RuntimeDecisionUnavailable()
        if self._exhausted.is_set() or self.pdp.receipt_count >= self._max_decisions:
            self._exhausted.set()
            raise RuntimeDecisionExhausted()

    def _fail(self, reason: str, error: BaseException) -> None:
        self._failure_reason = reason
        self._unavailable.set()
        if not isinstance(error, Exception):
            raise error
        raise RuntimeDecisionUnavailable() from error

    def _check_log_snapshot(self) -> None:
        info = self.receipt_log.lstat()
        _check_log_file(info)
        if self.receipt_log.parent.is_symlink() or _log_metadata(info) != self._log_snapshot:
            raise OSError("receipt log changed outside its single writer")

    def _append_receipt(self, receipt) -> None:
        payload = _canonical(receipt)
        self._check_log_snapshot()
        descriptor = os.open(
            self.receipt_log, os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_BINARY", 0),
        )
        try:
            opened = os.fstat(descriptor)
            _check_log_file(opened)
            if _log_metadata(opened) != self._log_snapshot:
                raise OSError("receipt log changed before append")
            with os.fdopen(descriptor, "ab") as stream:
                descriptor = -1
                if stream.write(payload) != len(payload):
                    raise OSError("receipt log write was incomplete")
                stream.flush()
                os.fsync(stream.fileno())
                after = os.fstat(stream.fileno())
                _check_log_file(after)
                if ((after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
                        or after.st_size != opened.st_size + len(payload)):
                    raise OSError("receipt log size or identity changed during append")
            if _log_metadata(self.receipt_log.lstat()) != _log_metadata(after):
                raise OSError("receipt log path changed during append")
            self._log_snapshot = _log_metadata(after)
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def decide(self, payload: bytes) -> Dict[str, Any]:
        if len(payload) > MAX_REQUEST_BYTES:
            raise OverflowError("runtime request exceeds 64 KiB")
        value = loads_strict_json(payload, max_nodes=MAX_REQUEST_JSON_NODES)
        self._check_admission()
        if not self._lock.acquire(timeout=self._decision_wait_seconds):
            self._check_admission()
            raise RuntimeDecisionBusy()
        try:
            self._check_admission()
            # Ordinary malformed input must not latch a service failure. Once
            # validated input enters the stateful engine, errors are uncertain.
            validate_runtime_request(value, self.pdp.profile)
            if self.receipt_log is not None:
                try:
                    self._check_log_snapshot()
                except BaseException as exc:
                    self._fail("receipt_log_failed", exc)
            try:
                decision, receipt = self.pdp.decide(value)
            except RuntimeCapacityExceeded:
                self._exhausted.set()
                raise RuntimeDecisionExhausted() from None
            except BaseException as exc:
                self._fail("decision_state_uncertain", exc)
            if self.receipt_log is not None:
                try:
                    self._append_receipt(receipt)
                except BaseException as exc:
                    self._fail("receipt_log_failed", exc)
            if self.pdp.receipt_count >= self._max_decisions:
                self._exhausted.set()
        finally:
            self._lock.release()
        return {
            "decision": decision,
            "receipt": receipt,
            "interpretation_boundary": (
                "The service evaluated typed metadata and did not execute or proxy the action."
            ),
        }


class _RequestHeadRejected(Exception):
    def __init__(self, status, code):
        self.status = status
        self.code = code
        super().__init__(code)


class _PrefetchedRequestReader:
    """Replay a complete head and any body prefix before reading the socket.

    Only the two operations used by this single-request handler are supported.
    The underlying stream is borrowed and remains owned by the handler.
    """

    def __init__(self, prefix, stream):
        self.prefix = io.BytesIO(prefix)
        self.stream = stream

    def readline(self, size=-1):
        # The complete request head is already present; framework header
        # parsing must never restart an unbounded socket readline.
        return self.prefix.readline(size)

    def read1(self, size=-1):
        value = self.prefix.read(size)
        return value if value else self.stream.read1(size)

    def close(self):
        self.prefix.close()


class _Handler(BaseHTTPRequestHandler):
    server_version = "LurePermitRuntime/1.0"
    # Idle socket operations are separate from the total head/body budgets.
    timeout = 5.0

    def _read_request_head(self) -> Optional[bytes]:
        deadline = time.monotonic() + REQUEST_HEAD_TIMEOUT_SECONDS
        data = bytearray()
        line_start = 0
        first_line_end = None
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('request head deadline exceeded')
                self.connection.settimeout(remaining)
                # One underlying read per iteration; at most one byte past
                # the head bound is requested to distinguish exact-size input.
                chunk = self.rfile.read1(min(4096, MAX_REQUEST_HEAD_BYTES + 1 - len(data)))
                if time.monotonic() >= deadline:
                    raise TimeoutError('request head deadline exceeded')
                if not chunk:
                    if not data:
                        return None
                    raise _RequestHeadRejected(400, 'incomplete_request_head')
                data.extend(chunk)
                while True:
                    end = data.find(b'\n', line_start)
                    if end < 0:
                        break
                    end += 1
                    if first_line_end is None:
                        first_line_end = end
                        words = data[:end].split(maxsplit=1)
                        self.command = 'HEAD' if words and words[0] == b'HEAD' else None
                    elif data[line_start:end] in (b'\n', b'\r\n'):
                        if end > MAX_REQUEST_HEAD_BYTES:
                            raise _RequestHeadRejected(431, 'request_head_too_large')
                        # Preserve bytes after the blank line as an exact body
                        # prefix; they do not count toward the head budget.
                        if time.monotonic() >= deadline:
                            raise TimeoutError('request head deadline exceeded')
                        return bytes(data)
                    line_start = end
                if len(data) > MAX_REQUEST_HEAD_BYTES:
                    if first_line_end is None or first_line_end > MAX_REQUEST_HEAD_BYTES:
                        raise _RequestHeadRejected(414, 'request_line_too_large')
                    raise _RequestHeadRejected(431, 'request_head_too_large')
        finally:
            self.connection.settimeout(self.timeout)

    def _reject_request_head(self, status, code):
        self.close_connection = True
        try:
            self._json(status, {'error': code})
        except OSError:
            # A peer may already have closed. Never resume parsing or route a
            # request merely because the fixed rejection could not be sent.
            pass

    def handle_one_request(self):
        # Head failure can precede the framework's initialization of these
        # response attributes. Never retain or reflect a partial request line.
        self.requestline = ''
        self.request_version = 'HTTP/1.0'
        self.command = None
        try:
            prefix = self._read_request_head()
        except _RequestHeadRejected as exc:
            self._reject_request_head(exc.status, exc.code)
            return
        except TimeoutError:
            self._reject_request_head(408, 'request_head_timeout')
            return
        except OSError:
            self._reject_request_head(400, 'request_head_unavailable')
            return
        if prefix is None:
            self.close_connection = True
            return
        stream = self.rfile
        replay = _PrefetchedRequestReader(prefix, stream)
        self.rfile = replay
        try:
            super().handle_one_request()
        finally:
            self.rfile = stream
            replay.close()

    def version_string(self) -> str:
        return self.server_version

    def parse_request(self):
        if not super().parse_request():
            return False
        major = int(self.request_version.partition('/')[2].partition('.')[0])
        if major == 0:
            # The typed JSON service requires an HTTP status line and headers.
            self.request_version = 'HTTP/1.0'
            self._json(400, {'error': 'invalid_http_request'})
            return False
        return True

    def send_error(self, code, message=None, explain=None) -> None:
        # Framework messages may contain request lines, methods, or header data.
        # Older supported Python versions keep their HTTP/0.9 fallback until a
        # valid version is parsed, which otherwise suppresses all JSON headers.
        if self.request_version == "HTTP/0.9":
            self.request_version = "HTTP/1.0"
        self._json(code, {"error": "invalid_http_request"})

    def _json(self, status: int, value: Any) -> None:
        # One request per connection, including rejected/incomplete bodies.
        # Never interpret unread body bytes as another request.
        self.close_connection = True
        payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
        self.send_response(status)
        self.send_header("Connection", "close")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if getattr(self, "command", None) != "HEAD":
            self.wfile.write(payload)

    def _read_body(self, length: int) -> bytes:
        deadline = time.monotonic() + REQUEST_BODY_TIMEOUT_SECONDS
        body = bytearray()
        try:
            while len(body) < length:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("request body deadline exceeded")
                self.connection.settimeout(remaining)
                # A single underlying read per iteration permits an absolute
                # deadline; buffered read(length) can wait through many drips.
                chunk = self.rfile.read1(length - len(body))
                if not chunk:
                    break
                body.extend(chunk)
            if time.monotonic() > deadline:
                raise TimeoutError("request body deadline exceeded")
            return bytes(body)
        finally:
            self.connection.settimeout(self.timeout)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            result = self.server.application.readiness()  # type: ignore[attr-defined]
            self._json(200 if result["ready"] else 503, result)
        elif self.path == "/openapi.json":
            self._json(200, runtime_openapi())
        else:
            self._json(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/v1/decide":
            self._json(404, {"error": "not_found"})
            return
        # HTTPMessage.get() selects one value and hides duplicate framing.
        # This endpoint deliberately supports only unencoded fixed-length JSON.
        if any("\r" in value or "\n" in value for _, value in self.headers.raw_items()):
            self._json(400, {"error": "invalid_request_headers"})
            return
        if self.headers.get_all("Transfer-Encoding") is not None:
            self._json(400, {"error": "unsupported_transfer_encoding"})
            return
        if self.headers.get_all("Expect") is not None:
            self._json(417, {"error": "expectation_not_supported"})
            return
        lengths = self.headers.get_all("Content-Length", [])
        if not lengths:
            self._json(411, {"error": "content_length_required"})
            return
        value = lengths[0].strip(" \t")
        if (len(lengths) != 1 or not 1 <= len(value) <= 20
                or not value.isascii() or not value.isdecimal()):
            self._json(400, {"error": "invalid_content_length"})
            return
        length = int(value)
        if length > MAX_REQUEST_BYTES:
            self._json(413, {"error": "request_too_large"})
            return
        encodings = self.headers.get_all("Content-Encoding", [])
        content_types = self.headers.get_all("Content-Type", [])
        if len(encodings) > 1 or len(content_types) > 1:
            self._json(400, {"error": "ambiguous_content_headers"})
            return
        if encodings and encodings[0].strip(" \t").lower() != "identity":
            self._json(415, {"error": "unsupported_content_encoding"})
            return
        content_type = (content_types[0] if content_types else "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            self._json(415, {"error": "application_json_required"})
            return
        try:
            payload = self._read_body(length)
        except TimeoutError:
            self._json(408, {"error": "request_body_timeout"})
            return
        except OSError:
            self._json(400, {"error": "request_body_unavailable"})
            return
        if len(payload) != length:
            self._json(400, {"error": "incomplete_request_body"})
            return
        try:
            result = self.server.application.decide(payload)  # type: ignore[attr-defined]
        except RuntimeDecisionBusy:
            self._json(503, {"error": "runtime_busy"})
        except RuntimeDecisionExhausted:
            self._json(503, {"error": "runtime_exhausted"})
        except RuntimeDecisionUnavailable:
            self._json(503, {"error": "runtime_unavailable"})
        except OverflowError:
            self._json(413, {"error": "request_too_large"})
        except ValueError:
            self._json(400, {"error": "invalid_request"})
        except OSError:
            self._json(503, {"error": "decision_storage_unavailable"})
        except Exception:  # noqa: BLE001 - do not disclose private processing errors
            self._json(500, {"error": "decision_failed"})
        else:
            self._json(200, result)

    def log_message(self, format: str, *args: Any) -> None:
        return


class _BoundedThreadingMixIn(socketserver.ThreadingMixIn):
    # Shutdown does not promise to interrupt or join a stalled decision/write.
    daemon_threads = True
    block_on_close = False

    def __init__(self, *args, max_connections=DEFAULT_MAX_CONNECTIONS, **kwargs):
        self._connection_slots = threading.BoundedSemaphore(_connection_limit(max_connections))
        self._admission_failed = threading.Event()
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if (self._admission_failed.is_set()
                or not self._connection_slots.acquire(blocking=False)):
            # No parsing, body buffering, response write, or worker allocation
            # at capacity. A closed connection is never authorization to act.
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            # An interrupted start can already have created a worker. Do not
            # release its slot speculatively or allow more admissions. Only a
            # worker's finally block releases it; recovery needs a new server.
            self._admission_failed.set()
            self.shutdown_request(request)
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connection_slots.release()


class _TCPHTTPServer(_BoundedThreadingMixIn, HTTPServer):
    pass


class _IPv6HTTPServer(_TCPHTTPServer):
    address_family = socket.AF_INET6


def _close_runtime_server(server, failure=None):
    try:
        server.server_close()
    except OSError:
        if failure is None:
            raise
        failure._runtime_cleanup_failed = True
        failure.add_note('Runtime cleanup failed; inspect the dedicated socket directory.')


class _UnixSocketPath:
    """Own one socket entry relative to a retained private-directory descriptor.

    Conditional unlink is not atomic on POSIX. The directory and its ancestors
    must remain controlled by the operator; same-UID/privileged mutation is not
    an isolation boundary. Observed replacements are never adopted or removed.
    """

    def __init__(self, address):
        raw = os.fspath(address)
        if (not isinstance(raw, str) or not raw or '\x00' in raw or raw.endswith('/')
                or '..' in Path(raw).parts or not Path(raw).name):
            raise ValueError('Unix socket requires an unambiguous filesystem pathname')
        if (not hasattr(os, 'O_DIRECTORY') or not hasattr(os, 'O_NOFOLLOW')
                or any(call not in os.supports_dir_fd for call in (os.stat, os.chmod, os.unlink))):
            raise NotImplementedError('Unix socket requires directory-relative filesystem support')
        self.path = Path(os.path.abspath(raw))
        self._close_lock = threading.Lock()
        self._bound = None
        self._fd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            parent = os.fstat(self._fd)
            self._parent_identity = (parent.st_dev, parent.st_ino)
            self._check_parent()
            try:
                self._stat()
            except FileNotFoundError:
                pass
            else:
                raise FileExistsError('Unix socket pathname already exists')
        except BaseException:
            os.close(self._fd)
            self._fd = None
            raise

    @staticmethod
    def _private_directory(info):
        return (stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
                and stat.S_IMODE(info.st_mode) == 0o700)

    @staticmethod
    def _stamp(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                info.st_nlink, info.st_mtime_ns, info.st_ctime_ns)

    def _stat(self):
        return os.stat(self.path.name, dir_fd=self._fd, follow_symlinks=False)

    def _check_parent(self):
        current = os.stat(self.path.parent, follow_symlinks=False)
        held = os.fstat(self._fd)
        if (not self._private_directory(current) or not self._private_directory(held)
                or (current.st_dev, current.st_ino) != self._parent_identity):
            raise ValueError('Unix socket parent must remain a private owned mode-0700 directory')

    def capture_bound(self):
        self._check_parent()
        info = self._stat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
            raise ValueError('Unix socket binding does not match a single owned socket')
        self._bound = self._stamp(info)

    def restrict_bound(self):
        self._check_parent()
        before = self._stat()
        if self._bound is None or self._stamp(before) != self._bound:
            raise ValueError('Unix socket pathname changed before permission setup')
        # Some supported POSIX/Python combinations lack no-follow chmod. The
        # private directory is required on every platform, not just that fallback.
        options = {'dir_fd': self._fd}
        if os.chmod in os.supports_follow_symlinks:
            options['follow_symlinks'] = False
        os.chmod(self.path.name, 0o600, **options)
        after = self._stat()
        if ((after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
                or not stat.S_ISSOCK(after.st_mode) or after.st_uid != os.geteuid()
                or after.st_nlink != 1 or stat.S_IMODE(after.st_mode) != 0o600):
            raise ValueError('Unix socket pathname changed during permission setup')
        self._bound = self._stamp(after)
        self._check_parent()

    def close(self):
        with self._close_lock:
            descriptor, self._fd = self._fd, None
            expected, self._bound = self._bound, None
        if descriptor is None:
            return
        try:
            if expected is None or not self._private_directory(os.fstat(descriptor)):
                return
            try:
                current = os.stat(self.path.name, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                return
            if self._stamp(current) == expected:
                os.unlink(self.path.name, dir_fd=descriptor)
        finally:
            os.close(descriptor)


class _UnixHTTPServer(_BoundedThreadingMixIn, socketserver.UnixStreamServer):
    allow_reuse_address = False

    def __init__(self, address, handler, bind_and_activate=True, **kwargs):
        self._socket_path = None
        super().__init__(address, handler, bind_and_activate=False, **kwargs)
        if bind_and_activate:
            try:
                self.server_bind()
                self.server_activate()
            except BaseException as failure:
                _close_runtime_server(self, failure)
                raise

    def server_bind(self) -> None:
        if self._socket_path is not None:
            raise ValueError('Unix socket server cannot bind twice')
        self._socket_path = _UnixSocketPath(self.server_address)
        self.server_address = str(self._socket_path.path)
        super().server_bind()
        self._socket_path.capture_bound()
        self._socket_path.restrict_bound()

    def server_close(self):
        try:
            if self._socket_path is not None:
                self._socket_path.close()
        finally:
            super().server_close()


def serve_runtime(
    *,
    profile_path: Optional[Path] = None,
    host: str = "127.0.0.1",
    port: int = 8765,
    unix_socket: Optional[Path] = None,
    receipt_log: Optional[Path] = None,
    max_connections: int = DEFAULT_MAX_CONNECTIONS,
    decision_wait_seconds: float = DEFAULT_DECISION_WAIT_SECONDS,
    max_decisions: int = MAX_RUNTIME_REQUESTS,
) -> None:
    """Serve until interrupted; network mode is restricted to a loopback IP."""

    max_connections = _connection_limit(max_connections)
    decision_wait_seconds = _decision_wait(decision_wait_seconds)
    max_decisions = _decision_limit(max_decisions)
    socket_path = Path(unix_socket) if unix_socket is not None else None
    if socket_path is None:
        try:
            address = ipaddress.ip_address(host)
        except ValueError as exc:
            raise ValueError("runtime service host must be an explicit loopback IP") from exc
        if not address.is_loopback:
            raise ValueError("runtime service refuses non-loopback network binding")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("runtime service port is invalid")
    profile = load_runtime_profile(profile_path)
    if socket_path is not None:
        server = _UnixHTTPServer(str(socket_path), _Handler, max_connections=max_connections)
    else:
        server_type = _IPv6HTTPServer if address.version == 6 else _TCPHTTPServer
        server = server_type((host, port), _Handler, max_connections=max_connections)
    try:
        application = RuntimeDecisionApplication(RuntimePDP(profile), receipt_log,
            decision_wait_seconds=decision_wait_seconds, max_decisions=max_decisions)
        server.application = application  # type: ignore[attr-defined]
        server.serve_forever()
    except BaseException as failure:
        _close_runtime_server(server, failure)
        raise
    else:
        _close_runtime_server(server)
