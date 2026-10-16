"""Fictional-only, no-authority stdin preview for cross-grant batch review #1493.

NEVER dispatches a tool, scans a target, creates a grant, or verifies consent.
Both exit codes are nonzero. No input identities are printed.
"""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from typing import Any

from .cross_grant_lineage_review_1493 import (
    CrossGrantCandidate,
    review_cross_grant_batch,
)
from .engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from .models import Authorization

SCHEMA = "FICTIONAL-CROSS-GRANT-V1"
MAX_INPUT_BYTES = 65536
_UTC_TEXT = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z", re.ASCII)
_ID_TEXT = re.compile(r"[A-Za-z0-9][A-Za-z0-9@._:/-]{0,127}\Z", re.ASCII)
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z", re.ASCII)
_ACTOR = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?@example\.test\Z", re.ASCII)
_CAPABILITY = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z", re.ASCII)
_BATCH_KEYS = frozenset(("schema", "evaluated_at", "candidates"))
_CLAIM_KEYS = frozenset((
    "legacy", "durable", "asset", "capability_id", "client_id",
    "engagement_id", "requested_risk",
))
_LEGACY_KEYS = frozenset(("owner", "reference", "valid_from", "valid_until"))
_DURABLE_KEYS = frozenset((
    "grant_id", "client_id", "engagement_id", "approved_by", "reference",
    "scope", "valid_from", "valid_until", "recurring_retest_allowed",
))
_SCOPE_KEYS = frozenset((
    "assets", "max_risk", "allowed_capabilities", "excluded_assets",
))


def _deny_json_constant(_: str) -> Any:
    raise ValueError("noncanonical numeric literal")


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON field")
        result[name] = value
    return result


def _object(value: Any, keys: frozenset[str]) -> dict[str, Any]:
    if type(value) is not dict or value.keys() != keys:
        raise ValueError("unknown/missing JSON fields")
    return value


def _text(value: Any) -> str:
    if type(value) is not str or _ID_TEXT.fullmatch(value) is None:
        raise ValueError("noncanonical fictional identifier")
    return value


def _capability(value: Any) -> str:
    if type(value) is not str or _CAPABILITY.fullmatch(value) is None:
        raise ValueError("noncanonical fictional capability")
    return value


def _fictional_asset(value: Any) -> str:
    value = _text(value)
    if (not value.endswith(".example.test")
            or any(_HOST_LABEL.fullmatch(label) is None for label in value.split("."))):
        raise ValueError("nonfictional or noncanonical asset")
    return value


def _utc(value: Any) -> datetime:
    if type(value) is not str or _UTC_TEXT.fullmatch(value) is None:
        raise ValueError("noncanonical UTC timestamp")
    # fromisoformat is a direct datetime parser. Unlike strptime it does not
    # lazily import _strptime/locale during a supposedly hermetic review.
    dt = datetime.fromisoformat(value[:-1] + "+00:00")
    if (dt.tzinfo is not timezone.utc
            or dt.isoformat(timespec="seconds") != value[:-1] + "+00:00"):
        raise ValueError("noncanonical UTC timestamp")
    return dt


def _risk(value: Any) -> RiskLevel:
    if type(value) is not str or value not in RiskLevel.__members__:
        raise ValueError("noncanonical risk")
    return RiskLevel[value]


def _array(value: Any, *, assets: bool, allow_empty: bool = False) -> tuple[str, ...]:
    if type(value) is not list or len(value) > 256 or (not allow_empty and not value):
        raise ValueError("noncanonical list")
    convert = _fictional_asset if assets else _capability
    return tuple(convert(item) for item in value)


def _claim(value: Any) -> CrossGrantCandidate:
    record = _object(value, _CLAIM_KEYS)
    prior = _object(record["legacy"], _LEGACY_KEYS)
    next_grant = _object(record["durable"], _DURABLE_KEYS)
    s = _object(next_grant["scope"], _SCOPE_KEYS)
    owner = _text(prior["owner"])
    approved_by = _text(next_grant["approved_by"])
    reference = _text(prior["reference"])
    durable_reference = _text(next_grant["reference"])
    # Deliberately prohibit production-looking identities even in an inert
    # shape preview. Synthetic labels are unauthenticated and not consent.
    if not (
        _ACTOR.fullmatch(owner)
        and _ACTOR.fullmatch(approved_by)
        and reference.startswith("SYNTH-") and len(reference) > len("SYNTH-")
        and durable_reference.startswith("SYNTH-") and len(durable_reference) > len("SYNTH-")
    ):
        raise ValueError("not canonical fictional provenance")
    recurring = next_grant["recurring_retest_allowed"]
    if type(recurring) is not bool:
        raise ValueError("noncanonical boolean")
    legacy = Authorization(
        owner, reference, _utc(prior["valid_from"]), _utc(prior["valid_until"])
    )
    scope = ScopeDefinition(
        _array(s["assets"], assets=True),
        _risk(s["max_risk"]),
        _array(s["allowed_capabilities"], assets=False, allow_empty=True),
        _array(s["excluded_assets"], assets=True, allow_empty=True),
    )
    durable = AuthorizationGrant(
        _text(next_grant["grant_id"]),
        _text(next_grant["client_id"]),
        _text(next_grant["engagement_id"]),
        approved_by,
        durable_reference,
        scope,
        _utc(next_grant["valid_from"]),
        _utc(next_grant["valid_until"]),
        recurring,
    )
    return CrossGrantCandidate(
        legacy, durable, _fictional_asset(record["asset"]),
        _capability(record["capability_id"]), _text(record["client_id"]),
        _text(record["engagement_id"]), _risk(record["requested_risk"]),
    )


def evaluate_bytes(data: bytes) -> tuple[dict[str, Any], int]:
    """Validate bounded JSON and return a public, privacy-minimal HOLD receipt.

    An ordinary coherent review returns exit 2; malformed input exit 3;
    NEVER exit 0 (neither result is a real execution permission).
    """
    status, reviewed, reason, exit_code = "HOLD", 0, "INVALID_INPUT", 3
    try:
        if type(data) is not bytes or not (1 <= len(data) <= MAX_INPUT_BYTES):
            raise ValueError("missing or oversized input")
        raw = data.decode("utf-8", "strict")
        parsed = json.loads(
            raw, object_pairs_hook=_no_duplicate_keys,
            parse_constant=_deny_json_constant,
            parse_int=_deny_json_constant,
            parse_float=_deny_json_constant,
        )
        root = _object(parsed, _BATCH_KEYS)
        if root["schema"] != SCHEMA or type(root["schema"]) is not str:
            raise ValueError("unsupported schema")
        now = _utc(root["evaluated_at"])
        records = root["candidates"]
        if type(records) is not list or not (1 <= len(records) <= 32):
            raise ValueError("noncanonical batch length")
        candidates = tuple(_claim(x) for x in records)
        review = review_cross_grant_batch(candidates, evaluated_at=now)
        if review.status == "REVIEW_ONLY":
            status, reviewed, reason = "REVIEW_ONLY", review.reviewed, "UNTRUSTED_COHERENCE"
        else:
            status, reason = "HOLD", "COHERENCE_DENIED"
        exit_code = 2
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        pass

    result = {
        "status": status,
        "reason": reason,
        "reviewed": reviewed,
        "authorized": False,
        "consent_verified": False,
        "dispatch_allowed": False,
        "release_allowed": False,
    }
    return result, exit_code


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args != ["--synthetic-only"]:
        result, code = evaluate_bytes(b"")
    else:
        result, code = evaluate_bytes(sys.stdin.buffer.read(MAX_INPUT_BYTES + 1))
    print(json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
