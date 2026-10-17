#!/usr/bin/env python3
"""Opt-in, non-authorizing review of *fictional* raw Git name-status -z bytes.

This standalone script is not wired to the LightUp runtime. It does not invoke
Git or authenticate the claimed source of any input.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
import sys
import unicodedata
from typing import Any

SCHEMA = "lightup.scope1547.synthetic_name_status.v1"
MAX_INPUT = 65536
MAX_STREAM = 32768
MAX_RECORDS = 64
MAX_PATH_BYTES = 1024
_STATUS_SIMPLE = frozenset({"A", "M", "D", "T"})
_STATUS_RENAME = re.compile(r"^[RC](?:0|[1-9][0-9]?|100)$", re.ASCII)
_FLAGS = (
    "authorized", "client_consent", "operator_consent", "grant", "scan",
    "handler_dispatch", "merge", "deploy", "release",
)


class StatusHold(ValueError):
    """Input cannot be accepted as a complete, canonical synthetic stream."""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for name, value in pairs:
        if name in obj:
            raise StatusHold("duplicate JSON field")
        obj[name] = value
    return obj


def _canonical_path(raw: bytes) -> str:
    if not raw or len(raw) > MAX_PATH_BYTES:
        raise StatusHold("path length")
    try:
        path = raw.decode("utf-8", "strict")
    except UnicodeError:
        raise StatusHold("path encoding") from None
    if (
        path != unicodedata.normalize("NFC", path)
        or path.startswith("/")
        or "\\" in path
        or "\uFFFD" in path
        or any(segment in ("", ".", "..") for segment in path.split("/"))
        or any(unicodedata.category(char) in {"Cc", "Cf", "Cs", "Zl", "Zp"} for char in path)
    ):
        raise StatusHold("noncanonical path")
    return path


def review_stream(raw: bytes) -> int:
    """Validate one complete -z stream. Return number of records or raise HOLD.

    This is not a Git implementation, only a review of explicitly synthetic data.
    It never authenticates a repository, commit or permission.
    """
    if not raw or len(raw) > MAX_STREAM or not raw.endswith(b"\0"):
        raise StatusHold("stream size or missing terminator")
    tokens = raw[:-1].split(b"\0")
    if not tokens or len(tokens) > MAX_RECORDS * 3:
        raise StatusHold("stream shape")
    count = 0
    index = 0
    seen: set[str] = set()
    while index < len(tokens):
        try:
            status = tokens[index].decode("ascii", "strict")
        except UnicodeError:
            raise StatusHold("status encoding") from None
        is_rename = _STATUS_RENAME.fullmatch(status) is not None
        if status not in _STATUS_SIMPLE and not is_rename:
            raise StatusHold("unknown or malformed status")
        width = 3 if is_rename else 2
        if index + width > len(tokens):
            raise StatusHold("incomplete record")
        for item in tokens[index + 1:index + width]:
            path = _canonical_path(item)
            alias = path.casefold()
            if alias in seen:
                raise StatusHold("aliased path")
            seen.add(alias)
        index += width
        count += 1
        if count > MAX_RECORDS:
            raise StatusHold("too many records")
    if count == 0:
        raise StatusHold("empty stream")
    return count


def review_packet(payload: bytes) -> int:
    """Return count only for strictly canonical, untrusted, fictional JSON."""
    if not payload or len(payload) > MAX_INPUT or not payload.isascii():
        raise StatusHold("invalid packet")
    try:
        obj = json.loads(payload, object_pairs_hook=_strict_object)
    except (ValueError, UnicodeError, RecursionError):
        raise StatusHold("invalid JSON") from None
    if type(obj) is not dict or set(obj) != {"schema", "name_status_b64"}:
        raise StatusHold("unknown schema fields")
    if obj["schema"] != SCHEMA or type(obj["name_status_b64"]) is not str:
        raise StatusHold("invalid schema")
    if json.dumps(obj, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii") != payload:
        raise StatusHold("noncanonical JSON")
    encoded = obj["name_status_b64"]
    if len(encoded) > ((MAX_STREAM + 2) // 3) * 4 or not encoded.isascii():
        raise StatusHold("oversize base64")
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        raise StatusHold("invalid base64") from None
    if base64.b64encode(decoded).decode("ascii") != encoded:
        raise StatusHold("noncanonical base64")
    return review_stream(decoded)


def receipt(decision: str) -> bytes:
    if decision not in ("HOLD", "REVIEW_ONLY"):
        raise ValueError("decision")
    obj: dict[str, Any] = {
        "schema": SCHEMA, "decision": decision, "not_authorization": True,
    }
    obj.update({key: False for key in _FLAGS})
    return (json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def main() -> int:
    decision = "HOLD"
    try:
        payload = sys.stdin.buffer.read(MAX_INPUT + 1)
        review_packet(payload)
        decision = "REVIEW_ONLY"
    except (StatusHold, OSError, ValueError, TypeError, OverflowError):
        decision = "HOLD"
    try:
        # No untrusted paths or statuses are returned in the receipt.
        sys.stdout.buffer.write(receipt(decision))
        sys.stdout.buffer.flush()
    except (OSError, ValueError):
        return 2
    return 3 if decision == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    sys.exit(main())
