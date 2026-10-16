"""Opt-in *fictional-only* copy-review CLI, never an authorization interface.

Read a single bounded canonical ASCII JSON envelope from stdin and emit only
constant-size, non-authorizing ASCII JSON. No paths, network, database, logging,
real credentials, real targets or active handlers.
Exit 2: REVIEW_ONLY (requires human review); 3: HOLD/errors. Never exit 0.
"""
from __future__ import annotations

import json
import sys

from .fictional_packet_copy_1503 import (
    CopyReview,
    _reject_constant,
    _reject_duplicates,
    compare_fictional_packet_fanout,
)

_INPUT_LIMIT = 8192
_KEYS = ("schema", "original", "copies")
_SCHEMA = "lightup-fictional-cli-v1"
_HOLD = b'{"status":"HOLD","authorized":false,"consent_verified":false,"dispatch_allowed":false,"release_allowed":false}\n'


def _parse_request(payload: bytes) -> CopyReview:
    if type(payload) is not bytes or not 1 <= len(payload) <= _INPUT_LIMIT:
        return CopyReview("HOLD")
    try:
        decoded = payload.decode("ascii")
        request = json.loads(
            decoded, object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
        )
        if type(request) is not dict or tuple(request) != _KEYS:
            return CopyReview("HOLD")
        if type(request["schema"]) is not str or request["schema"] != _SCHEMA:
            return CopyReview("HOLD")
        if type(request["original"]) is not str:
            return CopyReview("HOLD")
        copies = request["copies"]
        if (
            type(copies) is not list
            or not 1 <= len(copies) <= 16
            or any(type(x) is not str for x in copies)
        ):
            return CopyReview("HOLD")
        canonical = json.dumps(
            request, separators=(",", ":"), ensure_ascii=True, sort_keys=False,
            allow_nan=False,
        ).encode("ascii")
        if payload != canonical:
            return CopyReview("HOLD")
        original = request["original"].encode("ascii")
        received = tuple(part.encode("ascii") for part in copies)
        return compare_fictional_packet_fanout(original, received)
    except (ValueError, TypeError, UnicodeError, OverflowError, RecursionError):
        return CopyReview("HOLD")


def _render(review: CopyReview) -> bytes:
    """Only a canonical internal result can reach the success renderer."""
    if (
        type(review) is not CopyReview
        or review.authorized is not False
        or review.consent_verified is not False
        or review.dispatch_allowed is not False
        or review.release_allowed is not False
    ):
        return _HOLD
    if review.status != "REVIEW_ONLY":
        return _HOLD
    digest = review.sha256
    if (
        type(digest) is not str
        or len(digest) != 64
        or any(ch not in "0123456789abcdef" for ch in digest)
    ):
        return _HOLD
    return (
        b'{"status":"REVIEW_ONLY","sha256":"' + digest.encode("ascii")
        + b'","authorized":false,"consent_verified":false,"dispatch_allowed":false,'
        + b'"release_allowed":false}\n'
    )


def main() -> int:
    """Read stdin exactly once, never output untrusted text or success exit 0."""
    try:
        if len(sys.argv) != 1:
            rendered = _HOLD
        else:
            payload = sys.stdin.buffer.read(_INPUT_LIMIT + 1)
            rendered = _render(_parse_request(payload))
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        rendered = _HOLD
    try:
        written = sys.stdout.buffer.write(rendered)
        if type(written) is not int or written != len(rendered):
            return 3
        sys.stdout.buffer.flush()
    except (BrokenPipeError, OSError, ValueError):
        return 3
    return 2 if rendered != _HOLD else 3


if __name__ == "__main__":
    raise SystemExit(main())
