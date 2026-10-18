"""Offline PRIVATE human note source-revision binding for original Casebook impact rooms.

No identities are authenticated by this review file. Do not interpret reviewer
labels, status stages, hashes, or absence of rows as consent or approval.
"""
from __future__ import annotations

from datetime import date
import hashlib
import json
import re

from prepare import FALSE_FLAGS, Refused, _pairs, _constant, _literal

REVIEW_LIMIT = 262144
STAGES = frozenset({
    "unreviewed", "investigating", "waiting-client",
    "waiting-operator", "escalated", "documented",
})


def _canonical_date(value: str) -> bool:
    if not value:
        return True
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value) is None:
        return False
    try:
        return date.fromisoformat(value).isoformat() == value
    except ValueError:
        return False


def admit_private_review(original: bytes, review: bytes) -> dict:
    """Require complete exact-source and human-only schema consistency."""
    if type(original) is not bytes or type(review) is not bytes or not 2 <= len(review) <= REVIEW_LIMIT:
        raise Refused("review length")
    try:
        source = json.loads(original.decode("utf-8"), object_pairs_hook=_pairs,
                            parse_constant=_constant)
        private = json.loads(review.decode("utf-8"), object_pairs_hook=_pairs,
                             parse_constant=_constant)
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise Refused("review file invalid") from exc
    if type(source) is not dict or type(private) is not dict:
        raise Refused("review source shape")
    if (
        private.get("schema") != "lightup.scope_impact_private_review.v1"
        or private.get("status") != "REVIEW_ONLY"
        or private.get("source_schema") != source.get("schema")
        or private.get("source_sha256") != hashlib.sha256(original).hexdigest()
        or private.get("client_id") != source.get("client_id")
        or private.get("as_of") != source.get("as_of")
        or not all(private.get(flag) is False for flag in FALSE_FLAGS)
    ):
        raise Refused("review from a different source revision")
    rows = private.get("rows")
    if type(rows) is not list or len(rows) > 800:
        raise Refused("review length or shape")
    families = (
        ("requests", "request_id"), ("grants", "grant_id"),
        ("engagements", "engagement_id"), ("risk_approvals", "approval_id"),
    )
    all_ids = set()
    for family, idkey in families:
        for row in source[family]:
            all_ids.add(family + ":" + row[idkey])
    seen = set()
    for row in rows:
        if type(row) is not dict:
            raise Refused("invalid human review row")
        key = row.get("source_key")
        if type(key) is not str or key not in all_ids or key in seen:
            raise Refused("unknown or duplicate human review source")
        seen.add(key)
        stage = row.get("stage")
        reviewer = row.get("reviewer")
        next_action = row.get("next_action")
        due_date = row.get("due_date")
        note = row.get("note")
        if stage not in STAGES or any(type(field) is not str for field in (reviewer, next_action, due_date, note)):
            raise Refused("invalid review fields")
        if len(reviewer) > 80 or len(next_action) > 180 or len(note) > 1000 or len(due_date) > 10:
            raise Refused("review field length")
        if any(ord(c) < 32 and c not in "\t\n\r" for c in (reviewer + next_action + note)):
            raise Refused("control character in review")
        if not _canonical_date(due_date):
            raise Refused("invalid human review due date")
    return private
