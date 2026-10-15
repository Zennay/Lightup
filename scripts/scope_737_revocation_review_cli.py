"""Offline JSON v1 revocation cohort CLI — HOLD-only, privacy-minimal.

Run explicitly: python -m scripts.scope_737_revocation_review_cli
Read bounded JSON from stdin; write ONLY non-authorizing static result to
stdout. Never issue grants, reach a network, inspect the filesystem,
query persistence, or load installed runtime handlers.
"""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone

from scripts.scope_737_revocation_batch_triage import review_revocation_batch


_MAX_INPUT_BYTES = 65536
_TOP_KEYS = frozenset(("schema_version", "records"))
_ROW_KEYS = frozenset(("revoked_at", "revoked_by", "revocation_reason"))
_UTC_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
    re.ASCII,
)


def _duplicate_reject(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _constant_reject(value: str) -> None:
    raise ValueError("nonstandard JSON number")


def _convert_time(value: object) -> object:
    """Only unambiguous whole-second UTC Z timestamp becomes a datetime.

    Anything else remains as-is and is flagged noncanonical by the separate
    HOLD-only reviewer. Strict JSON input has no custom Python methods.
    """
    if type(value) is not str or not _UTC_TIMESTAMP.fullmatch(value):
        return value
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return value
    # Python strptime accepts e.g. one-digit components in some formats;
    # the ASCII exact-width regexp has already rejected these.
    return parsed.replace(tzinfo=timezone.utc)


def _hold_invalid(reason: str) -> dict:
    return {
        "schema_version": 1,
        "decision": "HOLD",
        "result": "invalid_input",
        "reason_codes": [reason],
        "class_counts": [],
        "can_authorize": False,
        "can_dispatch": False,
        "can_release": False,
    }


def _review_bytes(raw: object) -> tuple[dict, int]:
    """Non-throwing private review path; raw input never appears in result."""
    if type(raw) is not bytes:
        return _hold_invalid("noncanonical_input_bytes"), 2
    if len(raw) > _MAX_INPUT_BYTES:
        return _hold_invalid("input_too_large"), 2
    try:
        payload = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_duplicate_reject,
            parse_constant=_constant_reject,
        )
    except (UnicodeError, ValueError, TypeError, RecursionError):
        return _hold_invalid("invalid_json"), 2
    if type(payload) is not dict or frozenset(payload.keys()) != _TOP_KEYS:
        return _hold_invalid("invalid_top_schema"), 2
    if type(payload["schema_version"]) is not int or payload["schema_version"] != 1:
        return _hold_invalid("invalid_schema_version"), 2
    rows = payload["records"]
    if type(rows) is not list or not 1 <= len(rows) <= 64:
        return _hold_invalid("invalid_record_count"), 2

    prepared: list[dict] = []
    for item in rows:
        if type(item) is not dict or frozenset(item.keys()) != _ROW_KEYS:
            return _hold_invalid("invalid_record_schema"), 2
        prepared.append(
            {
                "revoked_at": _convert_time(item["revoked_at"]),
                "revoked_by": item["revoked_by"],
                "revocation_reason": item["revocation_reason"],
            }
        )
    outcome = review_revocation_batch(tuple(prepared))
    if outcome.result != "review_only":
        return _hold_invalid("invalid_record_schema"), 2
    return {
        "schema_version": 1,
        "decision": "HOLD",
        "result": "review_only",
        "reason_codes": ["independent_authorization_verification_required"],
        "class_counts": [
            {"classification": name, "count": count}
            for name, count in outcome.class_counts
        ],
        "can_authorize": False,
        "can_dispatch": False,
        "can_release": False,
    }, 0


def main() -> int:
    raw = sys.stdin.buffer.read(_MAX_INPUT_BYTES + 1)
    result, status = _review_bytes(raw)
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
