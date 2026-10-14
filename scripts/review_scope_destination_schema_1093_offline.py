"""Offline untrusted destination-role schema *shape* reviewer for issue #1093.

This opt-in script is NOT a trusted ToolRegistry, registration gate, grant,
authorization, release attestation, or target-capable executor.
"""
from __future__ import annotations

import json
import os
import re
import select
import stat
import sys
import time

MAX_INPUT_BYTES = 4096
READ_DEADLINE_SECONDS = 2.0
WRITE_DEADLINE_SECONDS = 2.0
MAX_RECEIPT_BYTES = 512
MAX_TOOLS = 8
MAX_PARAMETERS = 16
TOOL_ID = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z", re.ASCII)
PARAMETER_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}\Z", re.ASCII)
KINDS = frozenset({"string", "integer", "number", "boolean"})
ROLE_KINDS = {
    "none": KINDS,
    "host": frozenset({"string"}),
    "endpoint": frozenset({"string"}),
    "port": frozenset({"integer"}),
    "port_set": frozenset({"string"}),
}
DENIAL = {
    "authenticated_registry": False,
    "authorization_verified": False,
    "permit_issued": False,
    "dispatch_enabled": False,
    "merge_approved": False,
    "deploy_approved": False,
    "release_approved": False,
}


def _hold() -> dict:
    return dict(status="HOLD", claimed_tool_count=0, claimed_parameter_count=0, **DENIAL)



def _exact_fields(value: object, required: frozenset[str]) -> bool:
    """Use only built-in dict and string keys; no polymorphic field aliases.

    Validate key *identities* before any membership/set/hash operation on
    untrusted keys. This is API-boundary hygiene, not an OS sandbox.
    """
    return (
        type(value) is dict
        and all(type(key) is str for key in value)
        and set(value) == required
    )


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject_constant(_value):
    raise ValueError("nonfinite JSON")


def review_schema(payload: object) -> dict:
    """Review untrusted JSON-compatible claims without granting any authority."""
    if not _exact_fields(payload, frozenset({"tools"})):
        return _hold()
    tools = payload["tools"]
    if type(tools) is not list or not 1 <= len(tools) <= MAX_TOOLS:
        return _hold()
    seen_tools = set()
    count = 0
    for tool in tools:
        if not _exact_fields(tool, frozenset({"tool_id", "parameters"})):
            return _hold()
        tool_id, params = tool["tool_id"], tool["parameters"]
        if (type(tool_id) is not str or not TOOL_ID.fullmatch(tool_id)
                or tool_id in seen_tools):
            return _hold()
        seen_tools.add(tool_id)
        if type(params) is not list or not 1 <= len(params) <= MAX_PARAMETERS:
            return _hold()
        seen_params = set()
        # A tool may describe exactly one complete URL or one host selector,
        # optionally with one split port selector. Never treat a port alone,
        # two hosts, or an endpoint mixed with host/port fields as coherent.
        # This is structural review, NOT scope authority.
        role_counts = {"host": 0, "endpoint": 0, "port": 0,
                       "port_set": 0, "none": 0}
        for param in params:
            if not _exact_fields(
                param, frozenset({"name", "kind", "role", "required"})
            ):
                return _hold()
            name, kind, role = param["name"], param["kind"], param["role"]
            required = param["required"]
            if (type(name) is not str or not PARAMETER_NAME.fullmatch(name)
                    or name in seen_params or type(kind) is not str
                    or kind not in KINDS or type(role) is not str
                    or role not in ROLE_KINDS or kind not in ROLE_KINDS[role]
                    or type(required) is not bool
                    or (role != "none" and required is not True)):
                return _hold()
            seen_params.add(name)
            role_counts[role] += 1
        endpoint_only = (
            role_counts["endpoint"] == 1 and role_counts["host"] == 0
            and role_counts["port"] == 0 and role_counts["port_set"] == 0
        )
        host_with_optional_port = (
            role_counts["host"] == 1 and role_counts["endpoint"] == 0
            and role_counts["port"] + role_counts["port_set"] <= 1
        )
        if not (endpoint_only or host_with_optional_port):
            return _hold()
        count += len(params)
    return dict(status="REVIEW_ONLY", claimed_tool_count=len(tools),
                claimed_parameter_count=count, **DENIAL)


def review_bytes(raw: object) -> dict:
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_INPUT_BYTES:
        return _hold()
    try:
        decoded = raw.decode("utf-8", "strict")
        data = json.loads(decoded, object_pairs_hook=_unique_object,
                          parse_constant=_reject_constant)
    except (UnicodeError, ValueError, TypeError, RecursionError):
        return _hold()
    return review_schema(data)


def _read_private_pipe() -> bytes | None:
    """Read bounded private FIFO data; a failed fd restoration forces HOLD.

    Nonblocking fd0 prevents select/read races with a competing reader.
    Temporary flag changes share POSIX open-file-description state: use a
    private pipe. This is not an OS sandbox or a trusted registry.
    """
    result = None
    changed = False
    original_blocking = False
    try:
        if stat.S_ISFIFO(os.fstat(0).st_mode):
            original_blocking = os.get_blocking(0)
            if original_blocking:
                # A failed switch can still have changed shared fd flags.
                changed = True
                os.set_blocking(0, False)
            deadline = time.monotonic() + READ_DEADLINE_SECONDS
            chunks = []
            size = 0
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                ready, _, _ = select.select([0], [], [], remaining)
                if not ready:
                    break
                try:
                    part = os.read(0, min(1024, MAX_INPUT_BYTES + 1 - size))
                except BlockingIOError:
                    continue
                if not part:
                    result = b"".join(chunks)
                    break
                chunks.append(part)
                size += len(part)
                if size > MAX_INPUT_BYTES:
                    break
    except (OSError, ValueError, OverflowError):
        result = None
    finally:
        if changed:
            try:
                os.set_blocking(0, original_blocking)
            except (OSError, ValueError):
                result = None
    return result


def _seal_receipt(result: object) -> bytes | None:
    """Reject forged output *before* inspecting or writing to stdout."""
    if not _exact_fields(result, frozenset({
        "status", "claimed_tool_count", "claimed_parameter_count", *DENIAL
    })):
        return None
    if any(result[key] is not False for key in DENIAL):
        return None
    status = result["status"]
    count = result["claimed_tool_count"]
    parameters = result["claimed_parameter_count"]
    if type(status) is not str or status not in {"HOLD", "REVIEW_ONLY"}:
        return None
    if type(count) is not int or type(parameters) is not int:
        return None
    if status == "HOLD" and (count != 0 or parameters != 0):
        return None
    if status == "REVIEW_ONLY" and not (
        1 <= count <= MAX_TOOLS and count <= parameters <= count * MAX_PARAMETERS
    ):
        return None
    data = (json.dumps(result, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True) + "\n").encode("ascii")
    return data if len(data) <= MAX_RECEIPT_BYTES else None


def _emit_receipt(result: object) -> bool:
    """Emit only sealed denial receipts; restoration failure is non-success.

    Nonblocking writes are deadline-bounded and original fd1 flags are
    restored when possible. Bytes already written cannot be rolled back.
    """
    data = _seal_receipt(result)
    if data is None:
        return False
    success = False
    changed = False
    original_blocking = False
    try:
        mode = os.fstat(1).st_mode
        if stat.S_ISFIFO(mode) or (stat.S_ISCHR(mode) and os.isatty(1)):
            original_blocking = os.get_blocking(1)
            if original_blocking:
                changed = True
                os.set_blocking(1, False)
            deadline = time.monotonic() + WRITE_DEADLINE_SECONDS
            offset = 0
            while offset < len(data):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                _, ready, _ = select.select([], [1], [], remaining)
                if not ready:
                    break
                try:
                    sent = os.write(1, data[offset:])
                except BlockingIOError:
                    continue
                if sent <= 0:
                    break
                offset += sent
            success = offset == len(data)
    except (OSError, ValueError, OverflowError):
        success = False
    finally:
        if changed:
            try:
                os.set_blocking(1, original_blocking)
            except (OSError, ValueError):
                success = False
    return success


def main(argv=None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args != ["--stdin-json"]:
        result = _hold()
    else:
        result = review_bytes(_read_private_pipe())
    if not _emit_receipt(result):
        return 2
    return 3 if result["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
