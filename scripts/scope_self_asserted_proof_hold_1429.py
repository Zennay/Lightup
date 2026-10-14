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
from types import MappingProxyType
from typing import Any

MAX_STDIN_BYTES = 16 * 1024
READ_DEADLINE_SECONDS = 2.0
READ_CHUNK_BYTES = 4096
WRITE_DEADLINE_SECONDS = 2.0
MAX_RECEIPT_BYTES = 512
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
# Do not let in-process callers accidentally mutate the permission denial
# dictionary or add/remove release authority fields from a HOLD receipt.
FALSE_FLAGS = MappingProxyType({
    "authorized": False,
    "permit": False,
    "dispatch": False,
    "merge": False,
    "deploy": False,
    "release": False,
})


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

def _is_sealed_hold_receipt(payload: object) -> bool:
    """Require canonical, minimal non-authorizing output before any fd access."""
    if type(payload) is not bytes or not 0 < len(payload) <= MAX_RECEIPT_BYTES:
        return False
    if not payload.endswith(b"\n") or payload.count(b"\n") != 1:
        return False
    try:
        parsed = json.loads(
            payload[:-1].decode("ascii", "strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
        expected_keys = {
            "schema", "status", "input_integrity",
            "unverified_self_asserted_pass_claims", "verified_evidence",
            *FALSE_FLAGS,
        }
        if type(parsed) is not dict or set(parsed) != expected_keys:
            return False
        if type(parsed["schema"]) is not str or parsed["schema"] != OUTPUT_SCHEMA:
            return False
        if type(parsed["status"]) is not str or parsed["status"] != "HOLD":
            return False
        integrity = parsed["input_integrity"]
        if type(integrity) is not str or integrity not in {"COHERENT", "REJECTED"}:
            return False
        count = parsed["unverified_self_asserted_pass_claims"]
        if type(count) is not int or not 0 <= count <= len(LANES):
            return False
        if integrity == "REJECTED" and count != 0:
            return False
        if type(parsed["verified_evidence"]) is not bool or parsed["verified_evidence"] is not False:
            return False
        if any(type(parsed[key]) is not bool or parsed[key] is not False for key in FALSE_FLAGS):
            return False
        canonical = (json.dumps(parsed, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        return payload == canonical
    except (RejectedClaim, ValueError, UnicodeError, TypeError, RecursionError, OverflowError):
        return False


def _emit_hold_receipt(payload: bytes) -> None:
    """Best-effort single bounded receipt to a pipe or terminal only.

    A blocked pipe, inherited socket, on-disk file, missing fd or output
    failure is never a reason to wait indefinitely or return success.
    """
    restore_blocking = False
    fd = -1
    try:
        if not _is_sealed_hold_receipt(payload):
            return
        fd = sys.stdout.fileno()
        if type(fd) is not int or fd != 1:
            return
        mode = os.fstat(fd).st_mode
        # Character devices are not automatically trusted output sinks:
        # only actual TTYs, never arbitrary devices (e.g. /dev/null).
        if not (stat.S_ISFIFO(mode) or (stat.S_ISCHR(mode) and os.isatty(fd))):
            return
        # Child fd1 and parent pipe writers can share an open-file
        # description. Keep the caller's prior blocking state after exit.
        restore_blocking = os.get_blocking(fd)
        if restore_blocking:
            os.set_blocking(fd, False)
        deadline = time.monotonic() + WRITE_DEADLINE_SECONDS
        sent = 0
        while sent < len(payload):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            try:
                written = os.write(fd, payload[sent:])
            except (BlockingIOError, InterruptedError):
                written = 0
            if written > 0:
                sent += written
                continue
            if not select.select([], [fd], [], remaining)[1]:
                return
    except (OSError, ValueError, TypeError, OverflowError, AttributeError):
        return
    finally:
        # `set_blocking` changes O_NONBLOCK on the shared open-file
        # description, not merely the child's descriptor. Restore even on
        # timeout, EPIPE, or a short write. Never toggle originally-NONBLOCK.
        if restore_blocking:
            try:
                os.set_blocking(fd, True)
            except (OSError, ValueError, TypeError, AttributeError):
                pass


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    # Do not touch stdin for invalid argv. Zero ambient file / network access.
    if argv == ["--stdin-json"]:
        payload = _read_bounded_stdin()
    else:
        payload = b""
    result = review_bytes(payload)
    receipt = (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    _emit_hold_receipt(receipt)
    return 2  # NEVER success; caller-supplied claims cannot grant authority.


if __name__ == "__main__":
    raise SystemExit(main())
