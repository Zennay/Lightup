#!/usr/bin/env python3
"""Strict, unwired, synthetic-only #649 provenance shape review.

This is *never* an issuance decision, real consent, a grant, or target authority.
It imports no LightUp production modules and accesses no network or database.
"""
from __future__ import annotations

import json
import os
import sys
import unicodedata
from dataclasses import dataclass
from enum import Enum

SCHEMA = "lightup.scope649.provenance.synthetic.v1"
MAX_STDIN = 16384
MAX_ITEMS = 32
MAX_TEXT = 128


class ReviewStatus(Enum):
    HOLD = "HOLD"
    REVIEW_ONLY = "REVIEW_ONLY"

    def __bool__(self) -> bool:
        return False


@dataclass(frozen=True, slots=True)
class ReviewReceipt:
    status: ReviewStatus
    authorization_verified: bool = False
    consent_verified: bool = False
    permit_issued: bool = False
    dispatch_allowed: bool = False
    execution_enabled: bool = False
    merge_approved: bool = False
    release_approved: bool = False

    def __init_subclass__(cls, **kwargs: object) -> None:
        """Do not let a subclass override the non-authorizing receipt guard."""
        raise TypeError("synthetic review receipts are sealed")

    def __post_init__(self) -> None:
        """A review receipt cannot be forged into an apparent authority claim.

        This is a local invariant, not a defense against code deliberately
        bypassing frozen dataclasses via object.__setattr__.
        """
        if type(self.status) is not ReviewStatus:
            raise ValueError("review status must be the exact non-authorizing enum")
        for name in (
            "authorization_verified", "consent_verified", "permit_issued",
            "dispatch_allowed", "execution_enabled", "merge_approved",
            "release_approved",
        ):
            if getattr(self, name) is not False:
                raise ValueError("synthetic review receipts cannot claim authority")

    def __bool__(self) -> bool:
        return False


def _clean_text(value: object) -> bool:
    """Pure exact-builtin check; never call a foreign object's methods."""
    if type(value) is not str or not 1 <= len(value) <= MAX_TEXT:
        return False
    if not value.strip() or value != value.strip():
        return False
    if unicodedata.normalize("NFC", value) != value:
        return False
    # For fictional review notes, do not accept bidi overrides or controls.
    for char in value:
        category = unicodedata.category(char)
        if category in {"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"}:
            return False
        codepoint = ord(char)
        # NFC does not reject internal no-break/ideographic spaces or
        # default-ignorable combining and variation-selector characters.
        # Preserve only the ordinary ASCII interior word separator.
        if category == "Zs" and char != " ":
            return False
        if (codepoint == 0x034F or
                0xFE00 <= codepoint <= 0xFE0F or
                0xE0100 <= codepoint <= 0xE01EF):
            return False
    return True


def _has_exact_keys(value: object, expected: frozenset[str]) -> bool:
    """Validate keys *before* hashing/looking up against trusted names.

    Even an exact built-in dict can contain hostile key objects whose __eq__
    runs on collisions during set equality. Only then compare builtin str keys.
    """
    if type(value) is not dict or len(value) != len(expected):
        return False
    if not all(type(key) is str for key in value):
        return False
    return set(value) == expected


_ROOT_KEYS = frozenset({"schema", "synthetic_only", "items"})
_ENTRY_KEYS = frozenset({"approved_by", "reference"})


def review_batch(value: object) -> ReviewReceipt:
    """Review exact synthetic data shapes. All failures yield HOLD atomically."""
    hold = ReviewReceipt(ReviewStatus.HOLD)
    if not _has_exact_keys(value, _ROOT_KEYS):
        return hold
    if type(value["schema"]) is not str or value["schema"] != SCHEMA:
        return hold
    if value["synthetic_only"] is not True:
        return hold
    items = value["items"]
    if type(items) is not list or not 1 <= len(items) <= MAX_ITEMS:
        return hold
    seen_row_ids: set[int] = set()
    for item in items:
        if id(item) in seen_row_ids:
            return hold  # Reused object is not a distinct fictional review row.
        if not _has_exact_keys(item, _ENTRY_KEYS):
            return hold
        seen_row_ids.add(id(item))
        if not _clean_text(item["approved_by"]) or not _clean_text(item["reference"]):
            return hold
    return ReviewReceipt(ReviewStatus.REVIEW_ONLY)


def _pairs_unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate key")
        result[name] = value
    return result


def parse_and_review(raw: bytes) -> ReviewReceipt:
    """Bounded canonical JSON intake, no reads other than caller-supplied bytes."""
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_STDIN:
        return ReviewReceipt(ReviewStatus.HOLD)
    try:
        content = raw.decode("utf-8", "strict")
        value = json.loads(
            content,
            object_pairs_hook=_pairs_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeError, ValueError, TypeError, RecursionError):
        return ReviewReceipt(ReviewStatus.HOLD)
    return review_batch(value)


_HOLD = (
    b'{"status":"HOLD","authorization_verified":false,"consent_verified":false,'
    b'"permit_issued":false,"dispatch_allowed":false,"execution_enabled":false,'
    b'"merge_approved":false,"release_approved":false}\n'
)
_REVIEW_ONLY = _HOLD.replace(b'"status":"HOLD"', b'"status":"REVIEW_ONLY"')


def main() -> int:
    """StdIn -> one privacy-minimal receipt; even REVIEW_ONLY never returns 0."""
    try:
        incoming = sys.stdin.buffer.read(MAX_STDIN + 1)
        status = parse_and_review(incoming).status
    except (OSError, AttributeError, TypeError, ValueError):
        status = ReviewStatus.HOLD
    receipt = _REVIEW_ONLY if status is ReviewStatus.REVIEW_ONLY else _HOLD
    try:
        written = os.write(1, receipt)
        if type(written) is not int or written != len(receipt):
            return 2
    except (OSError, TypeError, ValueError):
        return 2
    return 3 if status is ReviewStatus.REVIEW_ONLY else 2


if __name__ == "__main__":
    sys.exit(main())
