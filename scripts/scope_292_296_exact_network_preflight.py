#!/usr/bin/env python3
"""Opt-in, strictly offline network-configuration preflight for #292/#296.

This is NOT ScopePolicy, customer consent, an execution permit, or a migration.
It must NEVER return an approving exit code, even for canonical input.
Input: a single bounded UTF-8 JSON object on stdin: {"explicit_networks": [...]}
Output: fixed non-sensitive JSON with REVIEW_ONLY/HOLD and always false flags.
"""
from __future__ import annotations

import ipaddress
import json
import sys
from typing import Any

MAX_JSON_BYTES = 16 * 1024
MAX_NETWORKS = 128
MAX_CIDR_CHARACTERS = 256


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject_constant(_: str) -> None:
    raise ValueError("non-finite constant")


def _canonical(value: object) -> bool:
    if type(value) is not str or not value or len(value) > MAX_CIDR_CHARACTERS:
        return False
    if value != value.strip() or "/" not in value:
        return False
    try:
        network = ipaddress.ip_network(value, strict=True)
    except (TypeError, ValueError):
        return False
    return value == str(network)


def _strip_json_structural_whitespace(raw: bytes) -> bytes:
    """Strip only legal whitespace *outside* JSON strings, preserving escapes.

    A parsed CIDR/key that only looks canonical *after* JSON unescaping must
    not be silently admitted as a canonical declaration. The original
    on-wire JSON bytes remain private and are never logged or returned.
    """
    output = bytearray()
    in_string = False
    escaped = False
    for byte in raw:
        if in_string:
            output.append(byte)
            if escaped:
                escaped = False
            elif byte == 0x5C:  # backslash
                escaped = True
            elif byte == 0x22:  # double quote
                in_string = False
        elif byte == 0x22:
            output.append(byte)
            in_string = True
        elif byte not in (0x20, 0x09, 0x0A, 0x0D):  # JSON whitespace
            output.append(byte)
    return bytes(output)


def review(raw: bytes) -> str:
    """Return HOLD or REVIEW_ONLY; never a permission or a live decision."""
    if type(raw) is not bytes or len(raw) > MAX_JSON_BYTES:
        return "HOLD"
    try:
        payload = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError, TypeError, RecursionError):
        return "HOLD"
    if type(payload) is not dict or set(payload) != {"explicit_networks"}:
        return "HOLD"
    networks = payload["explicit_networks"]
    if type(networks) is not list or len(networks) > MAX_NETWORKS:
        return "HOLD"
    # Immutable detached snapshot for the remainder of this review only.
    snapshot = tuple(networks)
    if len(snapshot) > MAX_NETWORKS:
        return "HOLD"
    if not all(_canonical(item) for item in snapshot):
        return "HOLD"
    # JSON escape aliases can convert noncanonical raw tokens into apparently
    # canonical CIDRs or even disguise the sole trusted envelope key.
    # Compare to the exact ASCII canonical JSON envelope after removing only
    # legal structural whitespace. This is only an offline syntax review.
    canonical_wire = json.dumps(
        {"explicit_networks": snapshot}, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    if _strip_json_structural_whitespace(raw) != canonical_wire:
        return "HOLD"
    # Canonical syntax remains review metadata, NOT authorization.
    return "REVIEW_ONLY"


def receipt(disposition: str) -> str:
    """Avoid echoing targets, raw values, parser exceptions or host counts."""
    if type(disposition) is not str or disposition not in ("HOLD", "REVIEW_ONLY"):
        disposition = "HOLD"
    return json.dumps(
        {
            "disposition": disposition,
            "is_grant": False,
            "authorizes_scan": False,
            "authorizes_target_io": False,
            "authorizes_execution": False,
            "authorizes_release": False,
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def _read_bounded_stream(reader: Any) -> bytes:
    """Read until EOF or one byte over budget, even on legitimate short reads.

    A single `read(n)` need not return all available bytes for every supported
    file-like stream. Accepting a valid prefix without the remaining bytes
    would falsely classify an incomplete policy as REVIEW_ONLY. Do not treat
    `None`, text, or an over-returning reader as EOF.
    """
    parts: list[bytes] = []
    remaining = MAX_JSON_BYTES + 1
    while remaining:
        part = reader.read(remaining)
        if type(part) is not bytes or len(part) > remaining:
            raise ValueError("invalid or oversized input chunk")
        if not part:
            break
        parts.append(part)
        remaining -= len(part)
    if not remaining:
        raise ValueError("input byte limit exceeded")
    return b"".join(parts)


def main() -> int:
    try:
        raw = _read_bounded_stream(sys.stdin.buffer)
        result = review(raw)
    except (OSError, ValueError, TypeError, RecursionError):
        result = "HOLD"
    # An incomplete or failed receipt cannot be interpreted as a safe review.
    # All exit codes remain nonzero, including stdout/pipe failures.
    response = receipt(result) + "\n"
    try:
        if sys.stdout.write(response) != len(response):
            return 2
        sys.stdout.flush()
    except (OSError, ValueError):
        return 2
    return 3 if result == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
