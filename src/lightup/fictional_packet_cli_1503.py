"""Opt-in *fictional-only* copy-review CLI, never an authorization interface.

Read a single bounded canonical ASCII JSON envelope from stdin and emit only
constant-size, non-authorizing ASCII JSON. No paths, network, database, logging,
real credentials, real targets or active handlers.
Exit 2: REVIEW_ONLY (requires human review); 3: HOLD/errors. Never exit 0.
"""
from __future__ import annotations

import json
import re
import sys

from .fictional_packet_copy_1503 import (
    CopyReview,
    _reject_constant,
    _reject_duplicates,
    _is_canonical_fictional_packet,
    compare_fictional_packet_fanout,
    compare_fictional_packet_fanout_pinned,
)

_INPUT_LIMIT = 8192
_KEYS = ("schema", "original", "copies")
_SCHEMA = "lightup-fictional-cli-v1"
_PINNED_SCHEMA = "lightup-fictional-cli-pinned-v1"
_PINNED_KEYS = ("schema", "original", "copies", "expected_sha256")
_HOLD = b'{"status":"HOLD","authorized":false,"consent_verified":false,"dispatch_allowed":false,"release_allowed":false}\n'



def build_fictional_cli_envelope(
    original: bytes, copies: tuple[bytes, ...],
) -> bytes | None:
    """Produce exact canonical *fictional* CLI stdin bytes, never permission.

    All recipients must be independently canonical reserved-fictional packets.
    Different but valid copies are allowed so the verifier can surface HOLD.
    Invalid caller types or values yield None, with no file/network effects.
    """
    if (
        type(copies) is not tuple
        or not 1 <= len(copies) <= 16
        or not _is_canonical_fictional_packet(original)
        or any(not _is_canonical_fictional_packet(part) for part in copies)
    ):
        return None
    try:
        payload = json.dumps(
            {
                "schema": _SCHEMA,
                "original": original.decode("ascii"),
                "copies": [part.decode("ascii") for part in copies],
            },
            ensure_ascii=True, separators=(",", ":"), sort_keys=False,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
        return None
    return payload if len(payload) <= _INPUT_LIMIT else None



def build_fictional_pinned_cli_envelope(
    original: bytes, copies: tuple[bytes, ...], expected_sha256: str,
) -> bytes | None:
    """Produce a strictly canonical synthetic stdin envelope with a digest pin.

    The pin must come from a separately verified source outside this function.
    Merely generating a digest here or passing a caller-controlled digest does
    not establish provenance, authenticity, consent or permission.
    """
    if (
        type(expected_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", expected_sha256, re.ASCII) is None
    ):
        return None
    raw = build_fictional_cli_envelope(original, copies)
    if raw is None:
        return None
    try:
        record = json.loads(raw.decode("ascii"))
        record["schema"] = _PINNED_SCHEMA
        record["expected_sha256"] = expected_sha256
        encoded = json.dumps(
            record, ensure_ascii=True, separators=(",", ":"), sort_keys=False,
            allow_nan=False,
        ).encode("ascii")
    except (ValueError, TypeError, UnicodeError, OverflowError, RecursionError):
        return None
    return encoded if len(encoded) <= _INPUT_LIMIT else None


def _parse_request(payload: bytes, *, pinned_only: bool = False) -> CopyReview:
    """Parse strict synthetic schema; pinned-only mode refuses legacy v1.

    pinned_only is an internal exact built-in bool, not a user-supplied flag.
    The default preserves v1 tests and backwards compatibility.
    """
    if type(pinned_only) is not bool:
        return CopyReview("HOLD")
    if type(payload) is not bytes or not 1 <= len(payload) <= _INPUT_LIMIT:
        return CopyReview("HOLD")
    try:
        decoded = payload.decode("ascii")
        request = json.loads(
            decoded, object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
        )
        if type(request) is not dict:
            return CopyReview("HOLD")
        schema = request.get("schema")
        if type(schema) is not str:
            return CopyReview("HOLD")
        if schema == _SCHEMA:
            if pinned_only or tuple(request) != _KEYS:
                return CopyReview("HOLD")
        elif schema == _PINNED_SCHEMA:
            if (
                tuple(request) != _PINNED_KEYS
                or type(request["expected_sha256"]) is not str
            ):
                return CopyReview("HOLD")
        else:
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
        if schema == _PINNED_SCHEMA:
            return compare_fictional_packet_fanout_pinned(
                original, received, request["expected_sha256"],
            )
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
    if type(review.status) is not str or review.status != "REVIEW_ONLY":
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



def _read_bounded_stdin(stream: object) -> bytes | None:
    """Collect the *entire* finite byte stream, never silently accept a prefix.

    Binary readers can legally return fewer bytes than requested. Read until
    genuine bytes EOF, refusing non-bytes chunks, oversized input and any
    trailing data (including content delivered after a valid JSON prefix).
    The maximum retained size is 8192 bytes, and every read asks at most
    remaining capacity + 1 bytes. The method has no filesystem/network APIs.
    """
    collected = bytearray()
    while True:
        part = stream.read(_INPUT_LIMIT - len(collected) + 1)
        if type(part) is not bytes:
            return None
        if part == b"":
            return bytes(collected)
        if len(part) > _INPUT_LIMIT - len(collected):
            return None
        collected.extend(part)


def _run_cli(*, pinned_only: bool) -> int:
    """One bounded stdin transaction; never return success exit 0."""
    if type(pinned_only) is not bool:
        pinned_only = True
    try:
        if len(sys.argv) != 1:
            rendered = _HOLD
        else:
            payload = _read_bounded_stdin(sys.stdin.buffer)
            rendered = _render(
                _parse_request(payload, pinned_only=pinned_only)
            )
    except (OSError, ValueError, TypeError, AttributeError, UnicodeError, RecursionError):
        rendered = _HOLD
    try:
        written = sys.stdout.buffer.write(rendered)
        if type(written) is not int or written != len(rendered):
            return 3
        sys.stdout.buffer.flush()
    except (BrokenPipeError, OSError, ValueError, AttributeError, TypeError):
        return 3
    return 2 if rendered != _HOLD else 3


def main() -> int:
    """Legacy-compatible fictional-only CLI (unpinned and pinned review)."""
    return _run_cli(pinned_only=False)


def main_pinned() -> int:
    """Pinned-only fictional review: explicitly reject schema downgrade to v1."""
    return _run_cli(pinned_only=True)


if __name__ == "__main__":
    raise SystemExit(main())
