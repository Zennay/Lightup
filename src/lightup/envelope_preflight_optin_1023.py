"""Optional offline-only JSON envelope shape admission for #1023.

Not wired into an endpoint, issuer, grant issuance, executor, or network path.
A True return value means only *syntactically shape-eligible*. It NEVER
means trusted, signed, tenant-scoped, current, approved, or authorized.

Unlike the original test-only #1012 reference, depth and value-node limits
are enforced while scanning lexical JSON and BEFORE json.loads materializes
any Python object tree. Scanning and UTF-8 decoding are byte-size-capped.
"""
from __future__ import annotations

import json
import math
import re

_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_HEX = frozenset("0123456789abcdefABCDEF")
_WHITESPACE = frozenset(" \t\r\n")


def _after_string(source: str, index: int) -> int | None:
    """Skip one JSON string without constructing or allocating its contents."""
    if index >= len(source) or source[index] != '"':
        return None
    index += 1
    while index < len(source):
        char = source[index]
        if char == '"':
            return index + 1
        if ord(char) < 32:
            return None
        if char == "\\":
            index += 1
            if index == len(source):
                return None
            escape = source[index]
            if escape == "u":
                digits = source[index + 1:index + 5]
                if len(digits) != 4 or any(c not in _HEX for c in digits):
                    return None
                scalar = int(digits, 16)
                index += 4
                if 0xD800 <= scalar <= 0xDBFF:
                    # Escaped high surrogate must be IMMEDIATELY followed
                    # by an escaped low surrogate. This is checked before
                    # json.loads, including in JSON member names.
                    if source[index + 1:index + 3] != "\\u":
                        return None
                    second = source[index + 3:index + 7]
                    if (len(second) != 4
                            or any(c not in _HEX for c in second)
                            or not 0xDC00 <= int(second, 16) <= 0xDFFF):
                        return None
                    index += 6
                elif 0xDC00 <= scalar <= 0xDFFF:
                    return None
            elif escape not in '"\\/bfnrt':
                return None
        index += 1
    return None


def _preparse_shape(source: str, *, max_depth: int, max_nodes: int) -> bool:
    """Iterative JSON grammar scanner with exact root/depth/value counts.

    Counts each object, array and primitive VALUE as one node; an object
    member name (key) is not an additional value node. A nested child value
    has depth parent+1, including arrays. Each member name is decoded once
    into a byte-budget-bounded set so duplicate key aliases are rejected
    before the full JSON tree is materialized.
    """
    length = len(source)
    index = 0
    nodes = 0
    # Object frames also carry a key set, for duplicate denial BEFORE json.loads.
    # This is bounded by the caller's strict UTF-8 byte ceiling.
    stack: list[list[object]] = []
    root_started = False

    def begin_value(at: int) -> int | None:
        nonlocal nodes
        if at >= length:
            return None
        nodes += 1
        if nodes > max_nodes or len(stack) + 1 > max_depth:
            return None
        token = source[at]
        if token == "{":
            stack.append(["object", "key_or_end", set()])
            return at + 1
        if token == "[":
            stack.append(["array", "value_or_end"])
            return at + 1
        if token == '"':
            return _after_string(source, at)
        if token in "-0123456789":
            matched = _NUMBER.match(source, at)
            return matched.end() if matched else None
        for literal in ("true", "false", "null"):
            if source.startswith(literal, at):
                return at + len(literal)
        return None

    while True:
        while index < length and source[index] in _WHITESPACE:
            index += 1
        if not stack:
            if root_started:
                return index == length
            # Authorization envelopes must have an object root.
            if index >= length or source[index] != "{":
                return False
            root_started = True
            next_index = begin_value(index)
            if next_index is None:
                return False
            index = next_index
            continue

        if index >= length:
            return False
        kind, state = stack[-1][:2]
        token = source[index]

        if kind == "object":
            if state in ("key_or_end", "key"):
                if token == "}" and state == "key_or_end":
                    stack.pop()
                    index += 1
                    continue
                next_index = _after_string(source, index)
                if next_index is None:
                    return False
                # Decode only the current member name, not the JSON tree.
                # scanstring uses the same Unicode escape semantics as the
                # full JSON decoder, so escaped/literal aliases are identical.
                try:
                    name, decoded_end = json.decoder.scanstring(source, index + 1, True)
                except (ValueError, UnicodeError):
                    return False
                if decoded_end != next_index or name in stack[-1][2]:
                    return False
                stack[-1][2].add(name)
                stack[-1][1] = "colon"
                index = next_index
                continue
            if state == "colon":
                if token != ":":
                    return False
                stack[-1][1] = "value"
                index += 1
                continue
            if state == "value":
                stack[-1][1] = "comma_or_end"
                next_index = begin_value(index)
                if next_index is None:
                    return False
                index = next_index
                continue
            if token == ",":
                stack[-1][1] = "key"
                index += 1
                continue
            if token == "}":
                stack.pop()
                index += 1
                continue
            return False

        if state in ("value_or_end", "value"):
            if token == "]" and state == "value_or_end":
                stack.pop()
                index += 1
                continue
            stack[-1][1] = "comma_or_end"
            next_index = begin_value(index)
            if next_index is None:
                return False
            index = next_index
            continue
        if token == ",":
            stack[-1][1] = "value"
            index += 1
            continue
        if token == "]":
            stack.pop()
            index += 1
            continue
        return False


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    data: dict[str, object] = {}
    for key, value in pairs:
        if key in data:
            raise ValueError("duplicate JSON object name")
        data[key] = value
    return data


def _reject_constant(_value: str) -> None:
    raise ValueError("nonfinite JSON constant")


def bounded_envelope_shape_optin(
    raw: object, *, max_bytes: int = 4096, max_depth: int = 8,
    max_nodes: int = 128,
) -> bool:
    """Fail-closed, non-authorizing envelope SHAPE screening (not installed)."""
    if (type(raw) is not bytes
            or any(type(limit) is not int or limit < 1 for limit in
                   (max_bytes, max_depth, max_nodes))
            or len(raw) > max_bytes):
        return False
    try:
        text = raw.decode("utf-8", errors="strict")
        if not _preparse_shape(text, max_depth=max_depth, max_nodes=max_nodes):
            return False
        value = json.loads(text, object_pairs_hook=_unique_object,
                           parse_constant=_reject_constant)
    except (UnicodeError, ValueError, TypeError, RecursionError):
        return False
    if type(value) is not dict:
        return False
    # The lexical scanner checked cardinality before allocation; verify the
    # parsed structure too and reject numbers that under/overflow to infinity.
    pending = [(value, 1)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if count > max_nodes or depth > max_depth:
            return False
        if type(item) is dict:
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            pending.extend((child, depth + 1) for child in item)
        elif type(item) is float:
            if not math.isfinite(item):
                return False
        elif type(item) not in (str, int, bool, type(None)):
            return False
    return True
