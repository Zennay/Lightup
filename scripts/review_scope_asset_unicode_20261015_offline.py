#!/usr/bin/env python3
"""Conservative offline synthetic scope-asset metadata review. NEVER authorizes."""
from __future__ import annotations

import json
import os
import re
import select
import stat
import sys
import time
from typing import Any

MAX_INPUT_BYTES = 8192
MAX_MEMBERS = 32
MAX_NAME_BYTES = 253
INPUT_DEADLINE_SECONDS = 2.0
FIELDS = frozenset({"assets", "excluded_assets", "allowed_capabilities"})
FALSE_FLAGS = {
    "authorization_verified": False,
    "permit_issued": False,
    "dispatch_enabled": False,
    "merge_approved": False,
    "deploy_approved": False,
    "release_approved": False,
}
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z", re.ASCII)
CAPABILITY = re.compile(r"[a-z][a-z0-9]*(?:[-_.][a-z0-9]+)*\Z", re.ASCII)


class ReviewInputError(ValueError):
    """Input is not eligible even for non-authorizing structural review."""


def _reject_constant(_value: str) -> None:
    raise ReviewInputError("non-finite JSON number")


def _object_no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReviewInputError("duplicate JSON key")
        result[key] = value
    return result


def _parse(data: bytes) -> Any:
    if type(data) is not bytes or not 0 < len(data) <= MAX_INPUT_BYTES:
        raise ReviewInputError("invalid input size or type")
    return json.loads(
        data.decode("utf-8", errors="strict"),
        object_pairs_hook=_object_no_duplicate_keys,
        parse_constant=_reject_constant,
    )


def _is_asset_name(value: Any) -> bool:
    if type(value) is not str or not 0 < len(value) <= MAX_NAME_BYTES:
        return False
    # Whitelist only; never a DNS/IDNA resolver, grant or target parser.
    if not value.isascii() or value != value.lower():
        return False
    labels = value.split(".")
    return all(LABEL.fullmatch(label) and not label.startswith("xn--") for label in labels)


def _is_capability_name(value: Any) -> bool:
    return (
        type(value) is str
        and 0 < len(value) <= 96
        and value.isascii()
        and CAPABILITY.fullmatch(value) is not None
    )


def _members(value: Any, *, minimum: int, validator: Any) -> frozenset[str]:
    if type(value) is not list or not minimum <= len(value) <= MAX_MEMBERS:
        raise ReviewInputError("invalid list")
    seen: set[str] = set()
    for member in value:
        if not validator(member) or member in seen:
            raise ReviewInputError("invalid or duplicate member")
        seen.add(member)
    return frozenset(seen)


def inspect_synthetic_claim(claim: Any) -> dict[str, Any]:
    """Review shape only. REVIEW_ONLY never means authorized."""
    if type(claim) is not dict or set(claim) != FIELDS:
        raise ReviewInputError("invalid claim structure")
    assets = _members(claim["assets"], minimum=1, validator=_is_asset_name)
    exclusions = _members(claim["excluded_assets"], minimum=0, validator=_is_asset_name)
    capabilities = _members(
        claim["allowed_capabilities"], minimum=1, validator=_is_capability_name
    )
    if not exclusions.isdisjoint(assets):
        raise ReviewInputError("contradictory exact asset identities")
    return {"status": "REVIEW_ONLY", **FALSE_FLAGS,
            "asset_count": len(assets), "excluded_count": len(exclusions),
            "capability_count": len(capabilities)}


def review_bytes(data: bytes) -> dict[str, Any]:
    try:
        return inspect_synthetic_claim(_parse(data))
    except (ReviewInputError, ValueError, UnicodeError, TypeError, RecursionError,
            OverflowError, MemoryError):
        return {"status": "HOLD", **FALSE_FLAGS}


def _read_local_stdin() -> bytes:
    mode = os.fstat(0).st_mode
    if not (stat.S_ISREG(mode) or stat.S_ISFIFO(mode)):
        raise ReviewInputError("stdin must be a local file or pipe")
    data = bytearray()
    deadline = time.monotonic() + INPUT_DEADLINE_SECONDS
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ReviewInputError("stdin timeout")
        readable, _, _ = select.select([0], [], [], remaining)
        if not readable:
            raise ReviewInputError("stdin timeout")
        chunk = os.read(0, MAX_INPUT_BYTES + 1 - len(data))
        if not chunk:
            return bytes(data)
        data.extend(chunk)
        if len(data) > MAX_INPUT_BYTES:
            raise ReviewInputError("stdin over size")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args != ["--stdin-json"]:
        receipt = {"status": "HOLD", **FALSE_FLAGS}
    else:
        try:
            receipt = review_bytes(_read_local_stdin())
        except (ReviewInputError, OSError, ValueError):
            receipt = {"status": "HOLD", **FALSE_FLAGS}
    sys.stdout.write(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n")
    return 3 if receipt["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
