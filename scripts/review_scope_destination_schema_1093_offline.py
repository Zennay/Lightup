"""Offline untrusted destination-role schema *shape* reviewer for issue #1093.

This opt-in script is NOT a trusted ToolRegistry, registration gate, grant,
authorization, release attestation, or target-capable executor.
"""
from __future__ import annotations

import json
import re
import sys

MAX_INPUT_BYTES = 4096
MAX_TOOLS = 8
MAX_PARAMETERS = 16
IDENTIFIER = re.compile(r"[a-z][a-z0-9_]{0,63}\Z", re.ASCII)
KINDS = frozenset({"string", "integer", "number", "boolean", "array", "object"})
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
    if type(payload) is not dict or set(payload) != {"tools"}:
        return _hold()
    tools = payload["tools"]
    if type(tools) is not list or not 1 <= len(tools) <= MAX_TOOLS:
        return _hold()
    seen_tools = set()
    count = 0
    for tool in tools:
        if type(tool) is not dict or set(tool) != {"tool_id", "parameters"}:
            return _hold()
        tool_id, params = tool["tool_id"], tool["parameters"]
        if (type(tool_id) is not str or not IDENTIFIER.fullmatch(tool_id)
                or tool_id in seen_tools):
            return _hold()
        seen_tools.add(tool_id)
        if type(params) is not list or not 1 <= len(params) <= MAX_PARAMETERS:
            return _hold()
        seen_params = set()
        destination_roles = 0
        for param in params:
            if type(param) is not dict or set(param) != {"name", "kind", "role"}:
                return _hold()
            name, kind, role = param["name"], param["kind"], param["role"]
            if (type(name) is not str or not IDENTIFIER.fullmatch(name)
                    or name in seen_params or type(kind) is not str
                    or kind not in KINDS or type(role) is not str
                    or role not in ROLE_KINDS or kind not in ROLE_KINDS[role]):
                return _hold()
            seen_params.add(name)
            destination_roles += role != "none"
        if not destination_roles:
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


def main(argv=None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args != ["--stdin-json"]:
        result = _hold()
    else:
        try:
            result = review_bytes(sys.stdin.buffer.read(MAX_INPUT_BYTES + 1))
        except (OSError, ValueError):
            result = _hold()
    print(json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
    return 3 if result["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
