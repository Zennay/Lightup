"""Opt-in fictional-only stdin adapter for #1495. NEVER issues authorization.

Usage: python -m lightup.synthetic_scope_notice_cli_1495 --synthetic-only
All results are nonzero exit codes: REVIEW_ONLY=2, HOLD=3.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import re
import sys

from .synthetic_scope_notice_1495 import ScopeProposal, render_scope_notice

_MAX_JSON_BYTES = 65536
_UTC_STAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z", re.ASCII)
_KEYS = frozenset(("asset", "capability", "risk", "valid_from", "valid_until"))
_INVALID_MESSAGE = (
    "HOLD — NOT AUTHORIZED. Invalid synthetic notice input; no scope "
    "has been verified, approved, scanned or dispatched."
)


def _reject_constant(value: str) -> None:
    raise ValueError("nonfinite JSON")


def _exact_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _utc(value: object) -> datetime:
    if type(value) is not str or _UTC_STAMP.fullmatch(value) is None:
        raise ValueError("noncanonical UTC")
    # Regex forces two-digit fields and no offset/locale ambiguity.
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _parse(raw: bytes) -> tuple[tuple[ScopeProposal, ...], datetime]:
    if not raw or len(raw) > _MAX_JSON_BYTES:
        raise ValueError("invalid size")
    data = json.loads(
        raw.decode("utf-8"),
        parse_constant=_reject_constant,
        object_pairs_hook=_exact_pairs,
    )
    if type(data) is not dict or frozenset(data) != frozenset(("review_at", "proposals")):
        raise ValueError("invalid outer schema")
    rows = data["proposals"]
    if type(rows) is not list or not 1 <= len(rows) <= 32:
        raise ValueError("invalid cohort")
    proposals = []
    for row in rows:
        if type(row) is not dict or frozenset(row) != _KEYS:
            raise ValueError("invalid entry schema")
        proposals.append(ScopeProposal(
            row["asset"], row["capability"], row["risk"],
            _utc(row["valid_from"]), _utc(row["valid_until"]),
        ))
    return tuple(proposals), _utc(data["review_at"])


def _print_notice(notice, *, fmt: str) -> None:
    if fmt == "json":
        # Machine consumers must read the four hard-coded false authority flags,
        # never treat status or exit 2 as consent or dispatch permission.
        print(json.dumps({
            "status": notice.status,
            "notice": notice.text,
            "reviewed": notice.reviewed,
            "elevated_risk": notice.elevated_risk,
            "authorized": False,
            "consent_verified": False,
            "dispatch_allowed": False,
            "release_allowed": False,
        }, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    else:
        print(notice.text)


def _print_invalid(*, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps({
            "status": "HOLD",
            "notice": _INVALID_MESSAGE,
            "reviewed": 0,
            "elevated_risk": False,
            "authorized": False,
            "consent_verified": False,
            "dispatch_allowed": False,
            "release_allowed": False,
        }, sort_keys=True, separators=(",", ":")))
    else:
        print(_INVALID_MESSAGE)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if type(args) is not list or not all(type(arg) is str for arg in args):
        _print_invalid(fmt="text")
        return 3
    # Deliberately finite, order-sensitive grammar: no implicit locale,
    # format, filename, target or execution fallback.
    valid = {
        ("--synthetic-only",): ("en", "text"),
        ("--synthetic-only", "--lang", "en"): ("en", "text"),
        ("--synthetic-only", "--lang", "nl"): ("nl", "text"),
        ("--synthetic-only", "--format", "json"): ("en", "json"),
        ("--synthetic-only", "--lang", "en", "--format", "json"): ("en", "json"),
        ("--synthetic-only", "--lang", "nl", "--format", "json"): ("nl", "json"),
    }
    settings = valid.get(tuple(args))
    if settings is None:
        _print_invalid(fmt="text")
        return 3
    language, fmt = settings
    try:
        raw = sys.stdin.buffer.read(_MAX_JSON_BYTES + 1)
        props, at = _parse(raw)
        notice = render_scope_notice(props, review_at=at, language=language)
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        _print_invalid(fmt=fmt)
        return 3
    _print_notice(notice, fmt=fmt)
    return 2 if notice.status == "REVIEW_ONLY" else 3


if __name__ == "__main__":
    sys.exit(main())
