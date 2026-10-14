"""Offline HOLD-only review of *untrusted* scope proof claims.

This program never authenticates a GitHub run, runner, installed ingress,
consent, or human release decision. A coherent JSON claim is still NOT proof.
No network, disk, subprocess, application imports or authorization side effects.
"""
from __future__ import annotations

import json
import os
import re
import select
import stat
import sys
import time
from typing import Any

MAX_STDIN_BYTES = 16 * 1024
READ_DEADLINE_SECONDS = 2.0
READ_CHUNK_BYTES = 4096
INPUT_SCHEMA = "lightup.scope.self_asserted_proof.v1"
OUTPUT_SCHEMA = "lightup.scope.untrusted_proof_hold.v1"
HEAD_PATTERN = re.compile(r"[0-9a-f]{40}\Z")
LANES = frozenset({
    "hosted_python_311",
    "hosted_python_314",
    "registered_vps",
    "installed_ingress",
})
RESULTS = frozenset({"pass", "fail", "queued", "cancelled", "unknown"})
FALSE_FLAGS = {
    "authorized": False,
    "permit": False,
    "dispatch": False,
    "merge": False,
    "deploy": False,
    "release": False,
}


class RejectedClaim(ValueError):
    """An untrusted claim bundle violates its closed-world input contract."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise RejectedClaim("duplicate JSON property")
        obj[key] = value
    return obj


def _reject_nonfinite(value: str) -> None:
    raise RejectedClaim("nonfinite JSON value")


def _is_sha(value: object) -> bool:
    return type(value) is str and HEAD_PATTERN.fullmatch(value) is not None


def _validate(value: object) -> tuple[bool, int]:
    if type(value) is not dict or set(value) != {"schema", "head", "claims"}:
        raise RejectedClaim("unexpected top-level keys")
    if value["schema"] != INPUT_SCHEMA or type(value["schema"]) is not str:
        raise RejectedClaim("invalid input schema")
    head = value["head"]
    if not _is_sha(head):
        raise RejectedClaim("invalid exact lowercase commit SHA")
    claims = value["claims"]
    if type(claims) is not list or len(claims) != len(LANES):
        raise RejectedClaim("four distinct lanes required")
    seen: set[str] = set()
    passing = 0
    for claim in claims:
        if type(claim) is not dict or set(claim) != {"lane", "head", "result"}:
            raise RejectedClaim("unexpected claim fields")
        lane = claim["lane"]
        result = claim["result"]
        if type(lane) is not str or lane not in LANES or lane in seen:
            raise RejectedClaim("unknown or duplicate lane")
        if not _is_sha(claim["head"]) or claim["head"] != head:
            raise RejectedClaim("cross-head or malformed claim")
        if type(result) is not str or result not in RESULTS:
            raise RejectedClaim("unknown or noncanonical result")
        seen.add(lane)
        passing += int(result == "pass")
    if seen != LANES:
        raise RejectedClaim("incomplete lane coverage")
    return True, passing


def review_bytes(payload: bytes) -> dict[str, Any]:
    """Return privacy-minimal, HOLD-only metadata; never return parsed claims."""
    coherent = False
    passing = 0
    try:
        if type(payload) is not bytes or not 0 < len(payload) <= MAX_STDIN_BYTES:
            raise RejectedClaim("input byte bound")
        parsed = json.loads(
            payload.decode("utf-8", "strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
        coherent, passing = _validate(parsed)
    except (RejectedClaim, ValueError, UnicodeError, TypeError, RecursionError, OverflowError):
        pass
    return {
        "schema": OUTPUT_SCHEMA,
        "status": "HOLD",
        "input_integrity": "COHERENT" if coherent else "REJECTED",
        "unverified_self_asserted_pass_claims": passing if coherent else 0,
        "verified_evidence": False,
        **FALSE_FLAGS,
    }


def _read_bounded_stdin() -> bytes:
    """Read only inherited fd 0; require EOF before a monotonic deadline.

    A partial, stalled, overlong or invalid stream is rejected atomically,
    never interpreted as a successful or complete proof bundle.
    """
    deadline = time.monotonic() + READ_DEADLINE_SECONDS
    parts: list[bytes] = []
    total = 0
    try:
        fd = sys.stdin.fileno()
        if type(fd) is not int or fd != 0:
            return b""
        # fd 0 may have been inherited as a socket, regular file, device,
        # or directory: never read such sources, even if JSON looks valid.
        # Accept only a pipe/FIFO deliberately supplied by the caller.
        if not stat.S_ISFIFO(os.fstat(fd).st_mode):
            return b""
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return b""
            readable, _, _ = select.select([fd], [], [], remaining)
            if not readable:
                return b""
            chunk = os.read(fd, min(READ_CHUNK_BYTES, MAX_STDIN_BYTES + 1 - total))
            if not chunk:
                return b"".join(parts)
            parts.append(chunk)
            total += len(chunk)
            if total > MAX_STDIN_BYTES:
                return b""
    except (OSError, ValueError, TypeError, OverflowError):
        return b""

def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    # Do not touch stdin for invalid argv. Zero ambient file / network access.
    if argv == ["--stdin-json"]:
        payload = _read_bounded_stdin()
    else:
        payload = b""
    result = review_bytes(payload)
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    return 2  # NEVER success; caller-supplied claims cannot grant authority.


if __name__ == "__main__":
    raise SystemExit(main())
