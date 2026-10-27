"""Non-authorizing, offline expiry-cohort review of UNTRUSTED UTC window claims.

No client identifiers, targets, risk approvals, resolvers, clocks or credentials are
accepted. This module is intentionally NOT imported by production authorization.
Every exit is nonzero; every authority-related output bit is literally false.
"""
from __future__ import annotations

import json
import os
import re
import select
import stat
import sys
import time
from datetime import datetime, timedelta, timezone

MAX_INPUT_BYTES = 16 * 1024
MAX_INPUT_SECONDS = 2.0
MAX_CLAIMS = 32
UTC_PATTERN = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})T"
    r"([0-9]{2}):([0-9]{2}):([0-9]{2})Z",
    flags=re.ASCII,
)
DENIAL_FLAGS = {
    "authorization_verified": False,
    "permit_issued": False,
    "dispatch_enabled": False,
    "merge_approved": False,
    "deploy_approved": False,
    "release_approved": False,
}


def _reject_constant(_value: str) -> None:
    raise ValueError("invalid JSON constant")


def _parse_int(raw: str) -> int:
    if not re.fullmatch(r"(?:0|[1-9][0-9]{0,3})", raw, flags=re.ASCII):
        raise ValueError("noncanonical JSON integer")
    return int(raw)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _utc(value: object) -> datetime:
    if type(value) is not str:
        raise ValueError("UTC timestamp must be a built-in string")
    match = UTC_PATTERN.fullmatch(value)
    if match is None:
        raise ValueError("noncanonical UTC timestamp")
    year, month, day, hour, minute, second = map(int, match.groups())
    # Explicit construction refuses 24:00:00 even where some Python versions
    # normalize ISO 24:00:00 into a DIFFERENT calendar day.
    return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)


def review(payload: bytes) -> dict[str, object]:
    """Classify claim windows, never confer authorization or release."""
    if type(payload) is not bytes or not 0 < len(payload) <= MAX_INPUT_BYTES:
        raise ValueError("invalid payload size/type")
    doc = json.loads(
        payload.decode("utf-8", errors="strict"),
        object_pairs_hook=_unique_object,
        parse_int=_parse_int,
        parse_float=_reject_constant,
        parse_constant=_reject_constant,
    )
    if type(doc) is not dict or set(doc) != {
        "as_of_utc", "horizon_hours", "windows"
    }:
        raise ValueError("invalid top-level shape")
    as_of = _utc(doc["as_of_utc"])
    hours = doc["horizon_hours"]
    if type(hours) is not int or not 1 <= hours <= 720:
        raise ValueError("invalid horizon")
    windows = doc["windows"]
    if type(windows) is not list or not 1 <= len(windows) <= MAX_CLAIMS:
        raise ValueError("invalid cohort")
    counts = {
        "expired": 0,
        "not_yet_started": 0,
        "current_expiring_within_horizon": 0,
        "current_later": 0,
    }
    horizon = timedelta(hours=hours)
    for claim in windows:
        if type(claim) is not dict or set(claim) != {"valid_from", "valid_until"}:
            raise ValueError("invalid window shape")
        start = _utc(claim["valid_from"])
        end = _utc(claim["valid_until"])
        if end <= start:
            raise ValueError("empty/inverted authorization window")
        if as_of > end:  # Producer's durable validity end is INCLUSIVE.
            counts["expired"] += 1
        elif as_of < start:
            counts["not_yet_started"] += 1
        elif end - as_of <= horizon:
            counts["current_expiring_within_horizon"] += 1
        else:
            counts["current_later"] += 1
    return {"status": "REVIEW_ONLY", **counts, **DENIAL_FLAGS}



def _read_bounded_stdin() -> bytes:
    """Read one local regular-file/FIFO packet from a pinned fd with EOF deadline.

    The original fd0 may be rebound with dup2() between fstat and read. Pin
    its original open-file description, then independently check that fd0
    still points to it before each read and after EOF. No sockets/TTYs.
    """
    fd = sys.stdin.fileno()
    if fd != 0:
        raise ValueError("stdin descriptor is not canonical")
    initial = os.fstat(fd)
    regular = stat.S_ISREG(initial.st_mode)
    if not (stat.S_ISFIFO(initial.st_mode) or regular):
        raise ValueError("stdin must be a local pipe or regular file")
    if regular:
        if not 0 < initial.st_size <= MAX_INPUT_BYTES:
            raise ValueError("invalid regular-file size")
        if os.lseek(fd, 0, os.SEEK_CUR) != 0:
            raise ValueError("nonzero regular-file offset")

    pinned_fd = os.dup(fd)
    try:
        pinned = os.fstat(pinned_fd)
        original_id = (initial.st_dev, initial.st_ino, initial.st_mode)
        if (pinned.st_dev, pinned.st_ino, pinned.st_mode) != original_id:
            raise ValueError("stdin pin mismatch")
        was_blocking = os.get_blocking(pinned_fd)
        try:
            os.set_blocking(pinned_fd, False)
            deadline = time.monotonic() + MAX_INPUT_SECONDS
            chunks = bytearray()
            while len(chunks) <= MAX_INPUT_BYTES:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError("stdin EOF deadline")
                readable, _, _ = select.select([pinned_fd], [], [], remaining)
                if not readable:
                    raise ValueError("stdin EOF deadline")
                before_live = os.fstat(fd)
                before_pinned = os.fstat(pinned_fd)
                if (before_live.st_dev, before_live.st_ino,
                        before_live.st_mode) != original_id or (
                        before_pinned.st_dev, before_pinned.st_ino,
                        before_pinned.st_mode) != original_id:
                    raise ValueError("stdin descriptor identity drift")
                chunk = os.read(
                    pinned_fd, min(4096, MAX_INPUT_BYTES + 1 - len(chunks))
                )
                if not chunk:
                    final_live = os.fstat(fd)
                    final = os.fstat(pinned_fd)
                    if (final_live.st_dev, final_live.st_ino,
                            final_live.st_mode) != original_id or (
                            final.st_dev, final.st_ino,
                            final.st_mode) != original_id:
                        raise ValueError("stdin EOF identity drift")
                    if regular:
                        if (final.st_size, final.st_mtime_ns,
                                final.st_ctime_ns) != (
                                initial.st_size, initial.st_mtime_ns,
                                initial.st_ctime_ns):
                            raise ValueError("regular-file snapshot changed")
                        if (len(chunks) != initial.st_size or
                                os.lseek(pinned_fd, 0, os.SEEK_CUR)
                                != initial.st_size):
                            raise ValueError("incomplete regular-file snapshot")
                    return bytes(chunks)
                chunks.extend(chunk)
            raise ValueError("stdin byte limit")
        finally:
            os.set_blocking(pinned_fd, was_blocking)
    finally:
        os.close(pinned_fd)


def _receipt(status: str) -> dict[str, object]:
    return {"status": status, **DENIAL_FLAGS}




COHORT_FIELDS = (
    "expired",
    "not_yet_started",
    "current_expiring_within_horizon",
    "current_later",
)


def _receipt_is_safe(receipt: object) -> bool:
    """Treat even our own output construction as untrusted until shape-checked.

    Only literal-false flags and bounded count totals can leave this process.
    This prevents an accidental upstream object/status/field change from
    producing an apparently approval-shaped or client-identifying receipt.
    """
    if type(receipt) is not dict:
        return False
    if any(receipt.get(key) is not False for key in DENIAL_FLAGS):
        return False
    status = receipt.get("status")
    if type(status) is not str:
        return False
    expected = {"status", *DENIAL_FLAGS}
    if status == "HOLD":
        return set(receipt) == expected
    if status != "REVIEW_ONLY" or set(receipt) != expected.union(COHORT_FIELDS):
        return False
    counts = [receipt[key] for key in COHORT_FIELDS]
    return (all(type(number) is int and 0 <= number <= MAX_CLAIMS
                for number in counts)
            and 1 <= sum(counts) <= MAX_CLAIMS)


def _emit_receipt(receipt: dict[str, object]) -> bool:
    """One bounded nonblocking write to a local pipe or real terminal only.

    A regular-file/socket/device stdout can silently move claimed authorization
    metadata somewhere unexpected. Refuse those destinations without emitting
    anything. A filled or broken pipe must not hang or dump a traceback.
    """
    if not _receipt_is_safe(receipt):
        return False
    payload = (json.dumps(receipt, separators=(",", ":"), ensure_ascii=True) +
               "\n").encode("ascii")
    if len(payload) > 512:
        return False
    try:
        fd = sys.stdout.fileno()
        if fd != 1:
            return False
        original = os.fstat(fd)
        # A second fstat after validating 'mode' could observe a replacement
        # socket/file and accidentally authorize that NEW object. Validate
        # the exact snapshot which is subsequently compared with the dup.
        mode = original.st_mode
        if not (stat.S_ISFIFO(mode) or
                (stat.S_ISCHR(mode) and os.isatty(fd))):
            return False
        # Pin the checked object. A late dup2(1) must never redirect this
        # receipt to an attacker-supplied socket/file after our fstat check.
        pinned_fd = os.dup(fd)
        try:
            pinned = os.fstat(pinned_fd)
            if (pinned.st_dev, pinned.st_ino, pinned.st_mode) != (
                original.st_dev, original.st_ino, original.st_mode
            ):
                return False
            was_blocking = os.get_blocking(pinned_fd)
            try:
                os.set_blocking(pinned_fd, False)
                current = os.fstat(fd)
                if (current.st_dev, current.st_ino, current.st_mode) != (
                    original.st_dev, original.st_ino, original.st_mode
                ):
                    return False
                return os.write(pinned_fd, payload) == len(payload)
            finally:
                os.set_blocking(pinned_fd, was_blocking)
        finally:
            os.close(pinned_fd)
    except (OSError, ValueError, TypeError):
        return False


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    try:
        if argv:
            raise ValueError("unexpected CLI arguments")
        data = _read_bounded_stdin()
        result = review(data)
        code = 3
    except (ValueError, TypeError, UnicodeError, OverflowError, OSError, RecursionError):
        result = _receipt("HOLD")
        code = 2
    # Fixed-schema aggregate-only output; no client/target/timestamp echoes.
    return code if _emit_receipt(result) else 2


if __name__ == "__main__":
    raise SystemExit(main())
