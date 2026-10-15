"""Offline, non-authorizing review of untrusted direct-grant provenance claims.

Issue #777. This review is NOT a proof of customer consent, an authorization
grant, a dispatch gate, or an installed production component. Synthetic data only.
"""
from __future__ import annotations

import json
import sys
import unicodedata

MAX_INPUT_BYTES = 4096
MAX_VALUE_BYTES = 128
AUTHORITY_FLAGS = (
    "authorization_verified", "permit_issued", "dispatch_enabled",
    "merge_approved", "deploy_approved", "release_approved",
)


def _receipt(status: str) -> dict[str, str | bool]:
    # No identifiers or raw data are ever returned (including on error).
    return {"status": status, **dict.fromkeys(AUTHORITY_FLAGS, False)}


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject_constant(_token: str) -> None:
    raise ValueError("nonfinite JSON")


def _canonical_claim(value: object) -> bool:
    if type(value) is not str or not value or value != value.strip():
        return False
    try:
        if len(value.encode("utf-8")) > MAX_VALUE_BYTES:
            return False
    except UnicodeEncodeError:
        return False
    # A string with invisible or control characters is not reviewable.
    return all(unicodedata.category(ch) not in ("Cc", "Cf", "Cs") for ch in value)


def review_bytes(data: bytes) -> dict[str, str | bool]:
    """Classify a bounded untrusted JSON claim; always deny authority.

    REVIEW_ONLY means lexical consistency *only*, never an authenticated fact.
    All malformed payloads have one indistinguishable HOLD receipt.
    """
    if type(data) is not bytes or not (1 <= len(data) <= MAX_INPUT_BYTES):
        return _receipt("HOLD")
    if data.startswith(b"\xef\xbb\xbf"):
        return _receipt("HOLD")
    try:
        parsed = json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
        )
        if type(parsed) is not dict or set(parsed) != {"approved_by", "reference"}:
            return _receipt("HOLD")
        if not all(_canonical_claim(parsed[key]) for key in ("approved_by", "reference")):
            return _receipt("HOLD")
    except (ValueError, UnicodeError, RecursionError, OverflowError, TypeError):
        return _receipt("HOLD")
    return _receipt("REVIEW_ONLY")


def main() -> int:
    if len(sys.argv) != 1:
        return 2
    try:
        data = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        receipt = review_bytes(data)
        sys.stdout.write(json.dumps(receipt, separators=(",", ":"), sort_keys=True) + "\n")
        sys.stdout.flush()
    except (OSError, BrokenPipeError, ValueError):
        return 2
    return 3 if receipt["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
