#!/usr/bin/env python3
"""Offline, non-authorizing review of proposed grant *metadata* amendments.

A REVIEW_ONLY result never verifies consent or grants permission to execute.
No LightUp runtime imports, network I/O, persistence or target interaction.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import re
import select
import stat
import sys
import time
from types import MappingProxyType

MAX_INPUT = 16384
MAX_MEMBERS = 32
IDENTIFIER = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._:-]{0,95}\Z")
SCOPE_ITEM = re.compile(r"[a-z0-9][a-z0-9._:/-]{0,239}\Z")
ROOT_KEYS = frozenset({"schema", "before", "after"})
GRANT_KEYS = frozenset({
    "grant_id", "client_id", "engagement_id", "approved_by", "reference", "assets",
    "excluded_assets", "capabilities", "max_risk", "valid_from",
    "valid_until", "recurring_retest_allowed",
})
DENIAL = MappingProxyType({
    "authorized": False,
    "permit_issued": False,
    "dispatch_enabled": False,
    "merge_approved": False,
    "deploy_approved": False,
    "release_approved": False,
})


class Rejected(ValueError):
    pass


def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for key, value in pairs:
        if key in out:
            raise Rejected("duplicate_key")
        out[key] = value
    return out


def _reject_float(_value: str) -> None:
    raise Rejected("non_integer_number")


def _parse(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_INPUT:
        raise Rejected("input_size")
    try:
        data = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_object,
            parse_float=_reject_float,
            parse_constant=_reject_float,
        )
    except (UnicodeError, ValueError, RecursionError, OverflowError) as exc:
        raise Rejected("invalid_json") from exc
    if type(data) is not dict or set(data) != ROOT_KEYS:
        raise Rejected("root_shape")
    if type(data["schema"]) is not str or data["schema"] != "lightup.grant-amendment-review.v1":
        raise Rejected("schema")
    return data


def _id(value: object) -> str:
    if type(value) is not str or IDENTIFIER.fullmatch(value) is None:
        raise Rejected("identifier")
    return value


def _members(value: object, *, allow_empty: bool = False) -> frozenset[str]:
    if type(value) is not list or len(value) > MAX_MEMBERS or (not value and not allow_empty):
        raise Rejected("member_count")
    seen: set[str] = set()
    for item in value:
        if type(item) is not str or SCOPE_ITEM.fullmatch(item) is None:
            raise Rejected("member")
        if item in seen:
            raise Rejected("duplicate_member")
        seen.add(item)
    return frozenset(seen)


def _instant(value: object) -> datetime:
    if type(value) is not str or len(value) > 35:
        raise Rejected("instant_type")
    # Require explicit UTC rather than silently normalizing an operator's time.
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value):
        raise Rejected("instant_format")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)
    except ValueError as exc:
        raise Rejected("instant_invalid") from exc


def _grant(data: object) -> dict[str, object]:
    if type(data) is not dict or set(data) != GRANT_KEYS:
        raise Rejected("grant_shape")
    result: dict[str, object] = {}
    for key in ("grant_id", "client_id", "engagement_id", "approved_by", "reference"):
        result[key] = _id(data[key])
    result["assets"] = _members(data["assets"])
    result["excluded_assets"] = _members(data["excluded_assets"], allow_empty=True)
    # Empty capabilities mean *unrestricted* in the live ScopeDefinition:
    # never accept them as a narrowing proof.
    result["capabilities"] = _members(data["capabilities"])
    risk = data["max_risk"]
    if type(risk) is not int or risk not in range(0, 5):
        raise Rejected("risk")
    result["max_risk"] = risk
    recurring = data["recurring_retest_allowed"]
    if type(recurring) is not bool:
        raise Rejected("recurring_type")
    result["recurring_retest_allowed"] = recurring
    result["valid_from"] = _instant(data["valid_from"])
    result["valid_until"] = _instant(data["valid_until"])
    if result["valid_from"] >= result["valid_until"]:
        raise Rejected("window")
    return result


def review(raw: bytes) -> tuple[dict[str, object], int]:
    """Return privacy-minimal HOLD or REVIEW_ONLY; never a success exit."""
    status = "HOLD"
    reason = "invalid_input"
    widened: list[str] = []
    try:
        data = _parse(raw)
        before, after = _grant(data["before"]), _grant(data["after"])
        identity = ("grant_id", "client_id", "engagement_id", "approved_by", "reference")
        if any(before[k] != after[k] for k in identity):
            widened.append("identity")
        if not after["assets"].issubset(before["assets"]):
            widened.append("assets")
        if not after["excluded_assets"].issuperset(before["excluded_assets"]):
            widened.append("exclusions")
        if not after["capabilities"].issubset(before["capabilities"]):
            widened.append("capabilities")
        if after["max_risk"] > before["max_risk"]:
            widened.append("risk")
        if after["valid_from"] < before["valid_from"] or after["valid_until"] > before["valid_until"]:
            widened.append("window")
        if after["recurring_retest_allowed"] and not before["recurring_retest_allowed"]:
            widened.append("recurring_retest")
        if widened:
            reason = "possible_widening"
        else:
            status, reason = "REVIEW_ONLY", "structurally_non_widening"
    except (Rejected, KeyError, TypeError):
        pass
    receipt = {
        "schema": "lightup.grant-amendment-review.receipt.v1",
        "status": status,
        "reason": reason,
        "widening_dimensions": sorted(widened),
        **DENIAL,
    }
    return receipt, (3 if status == "REVIEW_ONLY" else 2)


def _bounded_stdin() -> bytes:
    """Read one finite local file/FIFO; refuse changed metadata and stale EOF.

    Make the reader temporarily nonblocking: select() readiness can race with a
    second reader consuming data. Restore the inherited descriptor flag even
    on errors. This is a userland heuristic, not file provenance or sandboxing.
    """
    fd = -1
    switched = False
    original_blocking = False
    output = b""
    try:
        fd = sys.stdin.fileno()
        if fd != 0:
            return b""
        before = os.fstat(fd)
        regular = stat.S_ISREG(before.st_mode)
        if not (regular or stat.S_ISFIFO(before.st_mode)):
            return b""
        if regular and before.st_size > MAX_INPUT:
            return b""
        original_blocking = os.get_blocking(fd)
        deadline = time.monotonic() + 2.0
        chunks = bytearray()
        if original_blocking:
            # Mark as switched *before* the operation, for partial-failure
            # injection where the flag changes but the setter raises.
            switched = True
            os.set_blocking(fd, False)
        while len(chunks) <= MAX_INPUT:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            ready, _, _ = select.select([fd], [], [], remaining)
            if not ready:
                break
            try:
                part = os.read(fd, min(4096, MAX_INPUT + 1 - len(chunks)))
            except BlockingIOError:
                continue
            if not part:
                after = os.fstat(fd)
                identity_before = (before.st_dev, before.st_ino, stat.S_IFMT(before.st_mode))
                identity_after = (after.st_dev, after.st_ino, stat.S_IFMT(after.st_mode))
                if identity_before != identity_after:
                    break
                if regular and (
                    before.st_size != after.st_size
                    or before.st_mtime_ns != after.st_mtime_ns
                    or before.st_ctime_ns != after.st_ctime_ns
                ):
                    break
                output = bytes(chunks)
                break
            chunks.extend(part)
    except (OSError, ValueError, TypeError):
        output = b""
    finally:
        if switched:
            try:
                os.set_blocking(fd, original_blocking)
            except (OSError, ValueError):
                output = b""
        try:
            # A setter can silently fail; never return a reviewed packet if
            # the inherited open-file-description remains unexpectedly changed.
            if os.get_blocking(fd) is not original_blocking:
                output = b""
        except (OSError, ValueError):
            output = b""
    return output


RECEIPT_SCHEMA = "lightup.grant-amendment-review.receipt.v1"
RECEIPT_KEYS = frozenset({
    "schema", "status", "reason", "widening_dimensions", *DENIAL.keys(),
})
WIDENING_KEYS = frozenset({
    "identity", "assets", "exclusions", "capabilities", "risk", "window",
    "recurring_retest",
})
MAX_OUTPUT = 512


def _seal_receipt(receipt: object) -> bytes | None:
    """Refuse forged/malformed receipts *before* examining inherited stdout."""
    if type(receipt) is not dict or set(receipt) != RECEIPT_KEYS:
        return None
    if (type(receipt["schema"]) is not str
            or receipt["schema"] != RECEIPT_SCHEMA):
        return None
    status, reason = receipt["status"], receipt["reason"]
    if type(status) is not str or type(reason) is not str:
        return None
    if (status, reason) not in {
        ("HOLD", "invalid_input"),
        ("HOLD", "possible_widening"),
        ("REVIEW_ONLY", "structurally_non_widening"),
    }:
        return None
    dimensions = receipt["widening_dimensions"]
    if type(dimensions) is not list or any(
        type(v) is not str or v not in WIDENING_KEYS for v in dimensions
    ) or dimensions != sorted(set(dimensions)):
        return None
    if reason == "possible_widening" and not dimensions:
        return None
    if reason != "possible_widening" and dimensions:
        return None
    if any(type(receipt[k]) is not bool or receipt[k] is not False for k in DENIAL):
        return None
    try:
        data = (json.dumps(
            receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        ) + "\n").encode("ascii")
    except (ValueError, TypeError, UnicodeError):
        return None
    return data if len(data) <= MAX_OUTPUT else None


def _emit_receipt(receipt: object) -> bool:
    """Bounded, privacy-sealed local pipe/tty output (no file or socket sink).

    A pipe whose reader never drains must not hang the reviewer. Restoring
    O_NONBLOCK is important: POSIX parent/child can share the pipe's open file
    description. This userland check is NOT a sandbox against concurrent I/O.
    """
    data = _seal_receipt(receipt)
    if data is None:
        return False
    try:
        fd = sys.stdout.fileno()
        if fd != 1:
            return False
        original_sink = os.fstat(fd)
        mode = original_sink.st_mode
        if not (stat.S_ISFIFO(mode) or (stat.S_ISCHR(mode) and os.isatty(fd))):
            return False
        was_blocking = os.get_blocking(fd)
    except (OSError, ValueError, TypeError):
        return False
    deadline = time.monotonic() + 2.0
    switched = False
    success = False
    try:
        if was_blocking:
            # If this switch raises after altering the flag, still restore it.
            switched = True
            os.set_blocking(fd, False)
        offset = 0
        while offset < len(data):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            _, writable, _ = select.select([], [fd], [], remaining)
            if not writable:
                break
            # fd1 could have been replaced by dup2 after the initial local
            # sink check. This second check narrows that redirection window.
            sink = os.fstat(fd)
            if (sink.st_dev, sink.st_ino, stat.S_IFMT(sink.st_mode)) != (
                original_sink.st_dev, original_sink.st_ino,
                stat.S_IFMT(original_sink.st_mode),
            ):
                break
            try:
                count = os.write(fd, data[offset:])
            except BlockingIOError:
                continue
            if count <= 0:
                break
            offset += count
        success = offset == len(data)
    except (OSError, ValueError, TypeError):
        success = False
    finally:
        if switched:
            try:
                os.set_blocking(fd, was_blocking)
            except (OSError, ValueError):
                success = False
        try:
            if os.get_blocking(fd) is not was_blocking:
                success = False
        except (OSError, ValueError):
            success = False
    return success


def main(argv: list[str] | None = None) -> int:
    # Exact closed-world opt-in. argparse echoes unknown arguments (possibly
    # secrets) in stderr, so malformed CLI input must be opaque and must not
    # read stdin, including if an untrusted producer keeps its pipe open.
    arguments = sys.argv[1:] if argv is None else argv
    if type(arguments) is not list or len(arguments) != 1 or (
        type(arguments[0]) is not str or arguments[0] != "--stdin-json"
    ):
        return 2
    receipt, code = review(_bounded_stdin())
    if not _emit_receipt(receipt):
        return 2
    return code


if __name__ == "__main__":
    raise SystemExit(main())
