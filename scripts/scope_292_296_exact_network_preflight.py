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
    # Canonical syntax remains review metadata, NOT authorization.
    return "REVIEW_ONLY"


def receipt(disposition: str) -> str:
    """Avoid echoing targets, raw values, parser exceptions or host counts."""
    if disposition not in ("HOLD", "REVIEW_ONLY"):
        disposition = "HOLD"
    return json.dumps(
        {
            "disposition": disposition,
            "is_grant": False,
            "authorizes_scan": False,
            "authorizes_execution": False,
            "authorizes_release": False,
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def main() -> int:
    try:
        raw = sys.stdin.buffer.read(MAX_JSON_BYTES + 1)
        result = review(raw)
    except (OSError, ValueError, TypeError, RecursionError):
        result = "HOLD"
    sys.stdout.write(receipt(result) + "\n")
    return 3 if result == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
