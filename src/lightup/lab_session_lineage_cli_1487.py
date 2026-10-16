"""Local stdin-only fictional LAB-lineage shape preview (#1487).

This command cannot attest consent or grant permission. It does not open
paths, access a real authorization store, resolve hosts, or call handlers.
Both HOLD and REVIEW_ONLY exit nonzero to prevent 'exit 0 == permission'.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import re
import sys

from .lab_session_lineage_1487 import (
    FictionalLabLineageClaim,
    review_fictional_lab_lineage,
)

_MAX_INPUT_BYTES = 16_384
_UTC_TEXT = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", re.ASCII)
_SCHEMA_NAME = "FICTIONAL-LAB-LINEAGE-V1"
_ENVELOPE_FIELDS = frozenset({"schema", "assessment_time", "claims"})
_CLAIM_FIELDS = frozenset({
    "lab_reference", "operator_id", "session_id", "engagement_id",
    "asset_id", "capability_id", "starts_at", "expires_at", "revoked",
})
_RESPONSE = {
    status: json.dumps({
        "status": status,
        "grants_authority": False,
        "can_issue_permit": False,
        "can_dispatch": False,
        "can_release": False,
        "synthetic_only": True,
    }, sort_keys=True, separators=(",", ":"))
    for status in ("HOLD", "REVIEW_ONLY")
}


def _pairs_without_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON object key")
        result[name] = value
    return result


def _reject_nonjson_constant(value: str) -> None:
    raise ValueError("non-JSON numeric literal")


def _parse_exact_utc(value: object) -> datetime:
    if type(value) is not str or _UTC_TEXT.fullmatch(value) is None:
        raise ValueError("not an exact UTC instant")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def review_synthetic_json(payload: bytes) -> str:
    """Pure bounded JSON-to-shape preflight; output NEVER includes input."""
    if type(payload) is not bytes or not (1 <= len(payload) <= _MAX_INPUT_BYTES):
        return "HOLD"
    try:
        doc = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs_without_duplicates,
            parse_constant=_reject_nonjson_constant,
        )
        if type(doc) is not dict or frozenset(doc) != _ENVELOPE_FIELDS:
            return "HOLD"
        # Explicitly opt into this exact fictional protocol revision. Never
        # silently accept unversioned or production-looking consent packets.
        if type(doc["schema"]) is not str or doc["schema"] != _SCHEMA_NAME:
            return "HOLD"
        records = doc["claims"]
        if type(records) is not list or not (1 <= len(records) <= 64):
            return "HOLD"
        assessment = _parse_exact_utc(doc["assessment_time"])
        claims = []
        for record in records:
            if type(record) is not dict or frozenset(record) != _CLAIM_FIELDS:
                return "HOLD"
            data = dict(record)
            data["starts_at"] = _parse_exact_utc(data["starts_at"])
            data["expires_at"] = _parse_exact_utc(data["expires_at"])
            claims.append(FictionalLabLineageClaim(**data))
        return review_fictional_lab_lineage(tuple(claims), assessment).status
    except (UnicodeError, ValueError, TypeError, OverflowError, AttributeError, RecursionError):
        return "HOLD"


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    status = "HOLD"
    # Do not echo any CLI arguments, invalid JSON, actor or asset identifier.
    if type(args) is list and args == ["--synthetic-only"]:
        try:
            payload = sys.stdin.buffer.read(_MAX_INPUT_BYTES + 1)
            status = review_synthetic_json(payload)
        except (OSError, ValueError, AttributeError):
            status = "HOLD"
    sys.stdout.write(_RESPONSE[status] + "\n")
    # Deliberately NO success code, even when merely shape-reviewable:
    # 2 = HOLD, 3 = REVIEW_ONLY. Neither means operator authorization.
    return 3 if status == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
