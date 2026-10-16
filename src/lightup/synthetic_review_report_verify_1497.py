"""Offline-only strict import of the own fictional review output contract (#1497).

A valid wire envelope is NOT signed, a trusted source, privacy approval, or
authorization. This verifier only checks that bytes are exactly canonical
output-shaped JSON and emits a fresh inert verdict without echoing input.
"""
from __future__ import annotations

from dataclasses import asdict
import json

from .synthetic_review_disclosure_1497 import (
    DisclosureVerdict,
    _CONTRACT,
    _HOLD_NOTICE,
    _REVIEW_NOTICE,
    _MAX_NOTES,
    _hold,
)

_MAX_WIRE_BYTES = 4096
_EXPECTED_KEYS = frozenset({
    "contract", "status", "notice", "reviewed_notes", "authorized",
    "consent_verified", "dispatch_allowed", "release_allowed",
})
_FALSE_KEYS = ("authorized", "consent_verified", "dispatch_allowed", "release_allowed")


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    record: dict[str, object] = {}
    for key, value in pairs:
        if key in record:
            raise ValueError("ambiguous fictional review report")
        record[key] = value
    return record


def _reject_nonfinite(_: str) -> None:
    raise ValueError("nonfinite fictional review report")


def review_fictional_report_bytes(raw: object) -> DisclosureVerdict:
    """Validate byte-for-byte V1 standalone format with optional ONE final LF.

    This intentionally does not authenticate a report or revalidate underlying
    scope notes: its only outputs remain synthetic REVIEW_ONLY and generic HOLD.
    No I/O is performed, input is not modified or returned, and no grant can
    be issued by this function.
    """
    if type(raw) is not bytes or not (1 <= len(raw) <= _MAX_WIRE_BYTES):
        return _hold()
    try:
        decoded = raw.decode("ascii", "strict")
        value = json.loads(
            decoded,
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeError, ValueError, TypeError, OverflowError, RecursionError):
        return _hold()

    if type(value) is not dict or value.keys() != _EXPECTED_KEYS:
        return _hold()
    if type(value["contract"]) is not str or value["contract"] != _CONTRACT:
        return _hold()
    if any(type(value[key]) is not bool or value[key] is not False for key in _FALSE_KEYS):
        return _hold()
    if type(value["status"]) is not str or type(value["notice"]) is not str:
        return _hold()
    if type(value["reviewed_notes"]) is not int:
        return _hold()

    status = value["status"]
    count = value["reviewed_notes"]
    if status == "HOLD":
        if count != 0 or value["notice"] != _HOLD_NOTICE:
            return _hold()
    elif status == "REVIEW_ONLY":
        if not (1 <= count <= _MAX_NOTES) or value["notice"] != _REVIEW_NOTICE:
            return _hold()
    else:
        return _hold()

    verdict = DisclosureVerdict(status, value["notice"], count)
    canonical = json.dumps(
        asdict(verdict), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    # The actual emitting CLI uses print() (one trailing LF). Accept only
    # precise canonical ASCII bytes, with either zero or exactly one final LF.
    if raw != canonical and raw != canonical + b"\n":
        return _hold()
    return verdict
