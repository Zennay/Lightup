"""Opt-in historical Finding row decoder boundary, not a production read path.

This helper validates one already-selected SQLite row. It intentionally does
not select records, authenticate callers, or replace DomainStore selectors.
"""
from __future__ import annotations

import sqlite3

from .domain import DomainStore, FindingRecord
from .finding_evidence_json_checked_optin_w27 import decode_finding_evidence_checked

_ERROR = "invalid persisted finding evidence integrity"


def checked_finding_from_row(row: sqlite3.Row) -> FindingRecord:
    """Validate persisted evidence before invoking the canonical row mapper.

    Callers must first enforce tenant/engagement authorization and select the
    row through an authorized read. No database writes are performed here.
    """
    if type(row) is not sqlite3.Row:
        raise ValueError(_ERROR)
    try:
        raw = row["evidence_ids_json"]
    except (KeyError, IndexError, TypeError) as exc:
        raise ValueError(_ERROR) from exc
    checked = decode_finding_evidence_checked(raw)
    record = DomainStore._finding_from_row(row)
    if record.evidence_ids != checked:
        raise ValueError(_ERROR)
    return record
