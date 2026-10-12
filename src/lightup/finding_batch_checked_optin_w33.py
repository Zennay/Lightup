"""Opt-in, all-or-nothing historical Finding batch read proof (#856/#886).

This is NOT an authorized selector, canonical DomainStore integration, or a
customer-facing export. The caller must enforce tenant and engagement access
before supplying SQLite rows. No database writes or network access occur.
"""
from __future__ import annotations

import sqlite3

from .finding_evidence_json_checked_optin_w27 import decode_finding_evidence_checked
from .finding_row_checked_optin_w30 import checked_finding_from_row

_ERROR = "invalid persisted finding evidence integrity"
_MAX_ROWS = 256  # Provisional, requires source-owner compatibility review.


def checked_findings_batch(rows: list[sqlite3.Row] | tuple[sqlite3.Row, ...]) -> tuple:
    """Validate *every* row before mapping any; never return a partial batch.

    Only exact list/tuple containers and exact sqlite3.Row values are admitted.
    The original rows, their evidence JSON, and their ordering are unchanged.
    This helper does not select rows or establish tenant authorization.
    """
    if type(rows) not in (list, tuple) or len(rows) > _MAX_ROWS:
        raise ValueError(_ERROR)

    # Snapshot caller-owned lists to prevent cross-pass row replacement.
    batch = tuple(rows)

    # Preflight the entire batch before invoking the existing row mapper.
    for row in batch:
        if type(row) is not sqlite3.Row:
            raise ValueError(_ERROR)
        try:
            raw = row["evidence_ids_json"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ValueError(_ERROR) from exc
        decode_finding_evidence_checked(raw)

    # tuple() is built only after every mapping and integrity comparison passes.
    return tuple(checked_finding_from_row(row) for row in batch)
