"""Loopback or Unix-socket LurePermit policy decision service."""

from __future__ import annotations

import ipaddress
import json
import os
import socketserver
import stat
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional

from .permit import _canonical, loads_strict_json
from .runtime import (
    RECEIPT_SCHEMA,
    REQUEST_SCHEMA,
    RuntimePDP,
    load_runtime_profile,
    validate_runtime_request,
)

MAX_REQUEST_BYTES = 64 * 1024
MAX_REQUEST_JSON_NODES = 4096
REQUEST_BODY_TIMEOUT_SECONDS = 5.0


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
                "503": {"description": "Runtime unavailable; operator recovery required"},
            }}},
            "/openapi.json": {"get": {"responses": {"200": {"description": "OpenAPI document"}}}},
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
                        "408": {"description": "Request body deadline exceeded"},
                        "411": {"description": "Content-Length required"},
                        "413": {"description": "Request exceeds 64 KiB"},
                        "415": {"description": "Unsupported content type or encoding"},
                        "417": {"description": "Expect is not supported"},
                        "500": {"description": "Internal decision error; outcome may be uncertain"},
                        "503": {"description": "Runtime unavailable; outcome may be uncertain"},
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


def _log_metadata(info: os.stat_result) -> tuple:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            info.st_mode, info.st_nlink)


def _check_log_file(info: os.stat_result) -> None:
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or (os.name == "posix" and info.st_mode & 0o077)):
        raise OSError("receipt log must remain a private single-link regular file")


class RuntimeDecisionApplication:
    def __init__(self, pdp: RuntimePDP, receipt_log: Optional[Path] = None):
        self.pdp = pdp
        self.receipt_log = Path(receipt_log).absolute() if receipt_log is not None else None
        self._lock = threading.Lock()
        self._unavailable = threading.Event()
        self._failure_reason = "ready"
        self._log_snapshot = None
        if self.receipt_log is not None:
            if self.pdp._receipt_sequence != 0 or self.pdp._previous_receipt_sha256 is not None:
                raise ValueError("a new receipt log requires an unused runtime decision engine")
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
        """Snapshot of the failure latch, not a live disk or progress probe."""
        unavailable = self._unavailable.is_set()
        return {"ready": not unavailable, "status": "unavailable" if unavailable else "ready",
                "reason": self._failure_reason if unavailable else "ready",
                "receipt_logging": self.receipt_log is not None, "executes_actions": False}

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
        with self._lock:
            if self._unavailable.is_set():
                raise RuntimeDecisionUnavailable()
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
            except BaseException as exc:
                self._fail("decision_state_uncertain", exc)
            if self.receipt_log is not None:
                try:
                    self._append_receipt(receipt)
                except BaseException as exc:
                    self._fail("receipt_log_failed", exc)
        return {
            "decision": decision,
            "receipt": receipt,
            "interpretation_boundary": (
                "The service evaluated typed metadata and did not execute or proxy the action."
            ),
        }


class _Handler(BaseHTTPRequestHandler):
    server_version = "LurePermitRuntime/1.0"
    # Bounds idle socket operations, not total header time or worker concurrency.
    timeout = 5.0

    def version_string(self) -> str:
        return self.server_version

    def send_error(self, code, message=None, explain=None) -> None:
        # Framework messages may contain request lines, methods, or header data.
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


class _UnixHTTPServer(socketserver.UnixStreamServer):
    allow_reuse_address = False

    def server_bind(self) -> None:
        super().server_bind()
        os.chmod(self.server_address, 0o600)


def serve_runtime(
    *,
    profile_path: Optional[Path] = None,
    host: str = "127.0.0.1",
    port: int = 8765,
    unix_socket: Optional[Path] = None,
    receipt_log: Optional[Path] = None,
) -> None:
    """Serve until interrupted; network mode is restricted to a loopback IP."""

    socket_path = Path(unix_socket) if unix_socket is not None else None
    if socket_path is not None:
        if socket_path.exists() or socket_path.is_symlink():
            raise FileExistsError(f"{socket_path} already exists")
        if socket_path.parent.is_symlink() or not socket_path.parent.is_dir():
            raise ValueError("Unix socket parent must be a regular local directory")
    else:
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
        server = _UnixHTTPServer(str(socket_path), _Handler)
    else:
        server = ThreadingHTTPServer((host, port), _Handler)
    try:
        application = RuntimeDecisionApplication(RuntimePDP(profile), receipt_log)
    except Exception:
        server.server_close()
        if socket_path is not None:
            socket_path.unlink(missing_ok=True)
        raise
    server.application = application  # type: ignore[attr-defined]
    try:
        server.serve_forever()
    finally:
        server.server_close()
        if socket_path is not None:
            socket_path.unlink(missing_ok=True)
