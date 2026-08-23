#!/usr/bin/env python3
"""Dependency-free reference implementation of lurebench-detector-v1."""

from __future__ import annotations

import json
import re
import sys

PROTOCOL = "lurebench-detector-v1"
MAX_REQUEST_BYTES = 1024 * 1024
REQUEST_ID = re.compile(r"^request-[0-9]{8}$")
REQUEST_FIELDS = {"protocol", "request_id", "task", "text", "language", "channel"}
FRAUD_MARKERS = {
    "account",
    "approve",
    "confirm",
    "credential",
    "gift card",
    "kindly",
    "password",
    "payment",
    "urgent",
    "verify",
    "wallet",
    "wire",
    "<<link>>",
    "<<contact>>",
}


def score(text: str) -> float:
    lowered = text.casefold()
    matches = sum(marker in lowered for marker in FRAUD_MARKERS)
    return min(0.05 + matches * 0.18, 0.95)


def serve() -> int:
    while True:
        raw = sys.stdin.buffer.readline(MAX_REQUEST_BYTES + 1)
        if not raw:
            return 0
        if len(raw) > MAX_REQUEST_BYTES or not raw.endswith(b"\n"):
            return 2
        try:
            request = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return 2
        if not isinstance(request, dict) or set(request) != REQUEST_FIELDS:
            return 2
        if request["protocol"] != PROTOCOL:
            return 2
        if not isinstance(request["request_id"], str) or not REQUEST_ID.fullmatch(
            request["request_id"]
        ):
            return 2
        if request["task"] != "fraud" or not isinstance(request["text"], str):
            return 2
        if not isinstance(request["language"], str) or not isinstance(request["channel"], str):
            return 2
        response = {
            "protocol": PROTOCOL,
            "request_id": request["request_id"],
            "score": score(request["text"]),
        }
        print(json.dumps(response, separators=(",", ":")), flush=True)


if __name__ == "__main__":
    raise SystemExit(serve())
