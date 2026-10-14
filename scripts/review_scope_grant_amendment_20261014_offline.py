#!/usr/bin/env python3
"""Offline, non-authorizing review of proposed grant *metadata* amendments.

A REVIEW_ONLY result never verifies consent or grants permission to execute.
No LightUp runtime imports, network I/O, persistence or target interaction.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import re
import sys

MAX_INPUT = 16384
MAX_MEMBERS = 32
IDENTIFIER = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._:-]{0,95}\\Z")
SCOPE_ITEM = re.compile(r"[a-z0-9][a-z0-9._:/-]{0,239}\\Z")
ROOT_KEYS = frozenset({"schema", "before", "after"})
GRANT_KEYS = frozenset({
    "grant_id", "client_id", "engagement_id", "reference", "assets",
    "excluded_assets", "capabilities", "max_risk", "valid_from",
    "valid_until", "recurring_retest_allowed",
})
DENIAL = {
    "authorized": False,
    "permit_issued": False,
    "dispatch_enabled": False,
    "merge_approved": False,
    "deploy_approved": False,
    "release_approved": False,
}


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
    if not re.fullmatch(r"\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z", value):
        raise Rejected("instant_format")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)
    except ValueError as exc:
        raise Rejected("instant_invalid") from exc


def _grant(data: object) -> dict[str, object]:
    if type(data) is not dict or set(data) != GRANT_KEYS:
        raise Rejected("grant_shape")
    result: dict[str, object] = {}
    for key in ("grant_id", "client_id", "engagement_id", "reference"):
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
        identity = ("grant_id", "client_id", "engagement_id", "reference")
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline-only grant amendment review; never authorization.")
    parser.add_argument("--stdin-json", action="store_true", required=True)
    args = parser.parse_args(argv)
    assert args.stdin_json is True
    receipt, code = review(sys.stdin.buffer.read(MAX_INPUT + 1))
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
