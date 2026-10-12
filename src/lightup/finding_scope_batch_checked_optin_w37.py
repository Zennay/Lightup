"""Optional, uninstalled scope-integrity check for selected Finding rows.

Does not authenticate, authorize, select, scan, write, or perform remediation.
Only call after an independently authorized tenant/engagement selector.
"""
from __future__ import annotations

import sqlite3
from .domain import FindingRecord
from .finding_batch_checked_optin_w33 import checked_findings_batch
from .finding_evidence_json_checked_optin_w27 import decode_finding_evidence_checked

_ERROR = "invalid persisted finding evidence integrity"


def checked_scope_findings_batch(
    rows: list[sqlite3.Row] | tuple[sqlite3.Row, ...],
    *, expected_client_id: str, expected_engagement_id: str,
) -> tuple[FindingRecord, ...]:
    """Reject mixed-client or mixed-engagement results before returning a batch."""
    if (type(expected_client_id) is not str or not expected_client_id.strip()
            or type(expected_engagement_id) is not str
            or not expected_engagement_id.strip()):
        raise ValueError(_ERROR)
    if type(rows) not in (list, tuple) or len(rows) > 256:
        raise ValueError(_ERROR)
    snapshot = tuple(rows)
    for row in snapshot:
        if type(row) is not sqlite3.Row:
            raise ValueError(_ERROR)
        keys = row.keys()
        if any(sum(name.casefold() == key for name in keys) != 1
               for key in ("client_id", "engagement_id", "evidence_ids_json")):
            raise ValueError(_ERROR)
        if (type(row["client_id"]) is not str or row["client_id"] != expected_client_id
                or type(row["engagement_id"]) is not str
                or row["engagement_id"] != expected_engagement_id):
            raise ValueError(_ERROR)
        decode_finding_evidence_checked(row["evidence_ids_json"])
    try:
        records = checked_findings_batch(snapshot)
    except (ValueError, TypeError, KeyError, IndexError, AttributeError, sqlite3.Error) as exc:
        raise ValueError(_ERROR) from exc
    if type(records) is not tuple or len(records) != len(snapshot):
        raise ValueError(_ERROR)
    for record in records:
        if (type(record) is not FindingRecord
                or record.client_id != expected_client_id
                or record.engagement_id != expected_engagement_id):
            raise ValueError(_ERROR)
    return records
