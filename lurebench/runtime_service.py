"""Loopback or Unix-socket LurePermit policy decision service."""

from __future__ import annotations

import ipaddress
import json
import os
import socketserver
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional

from .permit import _canonical, loads_strict_json
from .runtime import RECEIPT_SCHEMA, REQUEST_SCHEMA, RuntimePDP, load_runtime_profile

MAX_REQUEST_BYTES = 64 * 1024


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
            "/health": {"get": {"responses": {"200": {"description": "Ready"}}}},
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
                        "413": {"description": "Request exceeds 64 KiB"},
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


class RuntimeDecisionApplication:
    def __init__(self, pdp: RuntimePDP, receipt_log: Optional[Path] = None):
        self.pdp = pdp
        self.receipt_log = Path(receipt_log) if receipt_log is not None else None
        self._lock = threading.Lock()
        if self.receipt_log is not None:
            if self.receipt_log.exists() or self.receipt_log.is_symlink():
                raise FileExistsError(f"{self.receipt_log} already exists")
            if self.receipt_log.parent.is_symlink() or not self.receipt_log.parent.is_dir():
                raise ValueError("receipt log parent must be a regular local directory")
            descriptor = os.open(
                self.receipt_log,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            os.close(descriptor)

    def decide(self, payload: bytes) -> Dict[str, Any]:
        if len(payload) > MAX_REQUEST_BYTES:
            raise OverflowError("runtime request exceeds 64 KiB")
        value = loads_strict_json(payload)
        with self._lock:
            decision, receipt = self.pdp.decide(value)
            if self.receipt_log is not None:
                descriptor = os.open(
                    self.receipt_log,
                    os.O_WRONLY
                    | os.O_APPEND
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                )
                try:
                    with os.fdopen(descriptor, "ab") as stream:
                        descriptor = -1
                        stream.write(_canonical(receipt))
                        stream.flush()
                        os.fsync(stream.fileno())
                finally:
                    if descriptor >= 0:
                        os.close(descriptor)
        return {
            "decision": decision,
            "receipt": receipt,
            "interpretation_boundary": (
                "The service evaluated typed metadata and did not execute or proxy the action."
            ),
        }


class _Handler(BaseHTTPRequestHandler):
    server_version = "LurePermitRuntime/1.0"

    def _json(self, status: int, value: Any) -> None:
        payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._json(200, {"status": "ready", "executes_actions": False})
        elif self.path == "/openapi.json":
            self._json(200, runtime_openapi())
        else:
            self._json(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/v1/decide":
            self._json(404, {"error": "not_found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        if length < 0:
            self._json(411, {"error": "content_length_required"})
            return
        if length > MAX_REQUEST_BYTES:
            self._json(413, {"error": "request_too_large"})
            return
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            self._json(415, {"error": "application_json_required"})
            return
        try:
            result = self.server.application.decide(self.rfile.read(length))  # type: ignore[attr-defined]
            self._json(200, result)
        except OverflowError as exc:
            self._json(413, {"error": str(exc)})
        except (UnicodeDecodeError, ValueError) as exc:
            self._json(400, {"error": str(exc)})

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
