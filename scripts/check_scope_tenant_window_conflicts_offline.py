"""Non-authorizing offline review of lab CIDR/time-window schedule collisions.

Caller-supplied tenant identity, CIDRs and windows are untrusted text, NOT
approval, consent, signed scheduling, a grant or a safe execution window.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import re
import sys

try:
    from scripts.check_scope_tenant_cidr_disjoint_offline import (
        MAX_BYTES, _exact_id, _network, _result, parse_json,
    )
except ModuleNotFoundError:
    from check_scope_tenant_cidr_disjoint_offline import (
        MAX_BYTES, _exact_id, _network, _result, parse_json,
    )

_MAX_WINDOWS = 32
_UTC_LITERAL = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z", re.ASCII)


def _time(value: object) -> datetime:
    # Disallow offsets, fractions, leap-second normalization, Unicode digits,
    # missing timezone, and any type-confused datetime/string subclass.
    if type(value) is not str or _UTC_LITERAL.fullmatch(value) is None:
        raise ValueError("noncanonical UTC time")
    try:
        result = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ValueError("invalid UTC date") from exc
    if result.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise ValueError("noncanonical UTC time")
    return result


def _parsed(document: object):
    if (type(document) is not dict
            or set(document) != {"schema_version", "windows"}
            or type(document.get("schema_version")) is not int
            or document["schema_version"] != 1):
        raise ValueError("invalid root")
    entries = document["windows"]
    if type(entries) is not list or not (1 <= len(entries) <= _MAX_WINDOWS):
        raise ValueError("invalid length")
    seen: set[tuple[str, str]] = set()
    windows = []
    for row in entries:
        if (type(row) is not dict
                or set(row) != {"tenant_id", "scope_id", "cidr", "starts_at", "ends_at"}):
            raise ValueError("invalid record")
        tenant, scope = row["tenant_id"], row["scope_id"]
        if not _exact_id(tenant) or not _exact_id(scope):
            raise ValueError("invalid IDs")
        key = (tenant, scope)
        if key in seen:
            raise ValueError("reused scope")
        seen.add(key)
        net = _network(row["cidr"])
        start, end = _time(row["starts_at"]), _time(row["ends_at"])
        if not start < end or end - start > timedelta(hours=24):
            raise ValueError("invalid time window")
        windows.append((key, net, start, end))
    return windows


def review_window_plan(document: object) -> dict[str, object]:
    """HOLD if overlapping CIDRs have strictly overlapping UTC windows.

    Half-open windows [start,end) touching at a boundary are NOT overlap.
    This is a textual planning review; never returns real authorization.
    """
    try:
        rows = _parsed(document)
    except (ValueError, TypeError, OverflowError):
        return _result("HOLD", "INVALID_WINDOW_PLAN")
    for i, (_, network, start, end) in enumerate(rows):
        for _, other, left, right in rows[:i]:
            if (network.version == other.version and network.overlaps(other)
                    and start < right and left < end):
                return _result("HOLD", "OVERLAPPING_NETWORK_WINDOW")
    return _result("REVIEW_ONLY", "NONCOLLIDING_UNTRUSTED_WINDOWS_ONLY")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args:
        result = _result("HOLD", "CLI_ARGUMENTS_DISALLOWED")
    else:
        try:
            result = review_window_plan(parse_json(sys.stdin.buffer.read(MAX_BYTES + 1)))
        except ValueError:
            result = _result("HOLD", "INVALID_WINDOW_JSON")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 3 if result["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
