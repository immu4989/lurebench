"""Constant-space JSON structure preflight, independent of semantic schemas.

Counts containers, scalar values, and object keys before decoder allocation.
This is not a JSON grammar validator; the strict decoder must still run.
Callers separately bound byte input and concurrent work.
"""

from __future__ import annotations

import math

MAX_JSON_NODES = 1_000_000
MAX_JSON_DEPTH = 128
MAX_JSON_TOKEN_CHARS = 4096


def check_json_structure(text: str, *, max_nodes: int = MAX_JSON_NODES) -> None:
    """Reject excessive breadth, depth, or unquoted token length before parsing."""
    if type(max_nodes) is not int or max_nodes < 1:
        raise ValueError("JSON node limit must be a positive integer")
    nodes = depth = token_chars = 0
    in_string = escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
            token_chars = 0
            nodes += 1
        elif character in "[{":
            depth += 1
            nodes += 1
            token_chars = 0
            if depth > MAX_JSON_DEPTH:
                raise ValueError("JSON nesting exceeds 128 container levels")
        elif character in "]}":
            depth -= 1
            token_chars = 0
        elif character in " \t\r\n,:":
            token_chars = 0
        else:
            if token_chars == 0:
                nodes += 1
            token_chars += 1
            if token_chars > MAX_JSON_TOKEN_CHARS:
                raise ValueError("JSON unquoted token exceeds 4096 characters")
        if nodes > max_nodes:
            raise ValueError("JSON node count exceeds the configured limit")


def finite_json_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("JSON number exceeds finite floating-point range")
    return number
