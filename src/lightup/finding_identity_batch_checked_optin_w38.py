"""Opt-in post-selection Finding identity/evidence/tenant integrity (#856/#886).

Pure read-side defense in depth for already authenticated, authorized, selected
SQLite rows. Not a selector, authorization mechanism, or installed entrypoint.
Does not perform writes, network operations, scanning, or remediation.
"""
from __future__ import annotations

import sqlite3

from .domain import FindingRecord
from .finding_batch_checked_optin_w33 import checked_findings_batch
from .finding_evidence_json_checked_optin_w27 import decode_finding_evidence_checked

_ERROR = "invalid persisted finding evidence integrity"
_MAX_ROWS = 256  # Provisional historical-compatibility limit; not production policy.
_FIELDS = (
    "finding_id", "client_id", "engagement_id", "title", "severity", "asset",
    "impact", "remediation", "retest_status", "evidence_ids_json", "created_at",
)


def checked_identity_findings_batch(
    rows: list[sqlite3.Row] | tuple[sqlite3.Row, ...],
    *, expected_client_id: str, expected_engagement_id: str,
) -> tuple[FindingRecord, ...]:
    """Fail closed on mixed scope, ambiguous projections, or mis-mapped rows.

    Validation is all-or-nothing: no record escapes until every row and mapped
    FindingRecord has passed. The caller must have selected authorized rows.
    """
    if (type(expected_client_id) is not str or not expected_client_id.strip()
            or type(expected_engagement_id) is not str
            or not expected_engagement_id.strip()):
        raise ValueError(_ERROR)
    if type(rows) not in (list, tuple) or len(rows) > _MAX_ROWS:
        raise ValueError(_ERROR)
    snapshot = tuple(rows)
    decoded = []
    seen_ids = set()
    for row in snapshot:
        if type(row) is not sqlite3.Row:
            raise ValueError(_ERROR)
        names = row.keys()
        if any(sum(name.casefold() == field for name in names) != 1 for field in _FIELDS):
            raise ValueError(_ERROR)
        fid = row["finding_id"]
        if type(fid) is not str or not fid.strip() or fid in seen_ids:
            raise ValueError(_ERROR)
        seen_ids.add(fid)
        if (type(row["client_id"]) is not str
                or row["client_id"] != expected_client_id
                or type(row["engagement_id"]) is not str
                or row["engagement_id"] != expected_engagement_id):
            raise ValueError(_ERROR)
        decoded.append(decode_finding_evidence_checked(row["evidence_ids_json"]))

    try:
        mapped = checked_findings_batch(snapshot)
    except (ValueError, TypeError, KeyError, IndexError, AttributeError, sqlite3.Error) as exc:
        raise ValueError(_ERROR) from exc
    if type(mapped) is not tuple or len(mapped) != len(snapshot):
        raise ValueError(_ERROR)
    for row, expected_evidence, record in zip(snapshot, decoded, mapped):
        if type(record) is not FindingRecord:
            raise ValueError(_ERROR)
        for field in ("finding_id", "client_id", "engagement_id", "title", "asset",
                      "impact", "remediation", "created_at"):
            if type(row[field]) is not str or getattr(record, field) != row[field]:
                raise ValueError(_ERROR)
        if (record.client_id != expected_client_id
                or record.engagement_id != expected_engagement_id
                or getattr(record.severity, "value", None) != row["severity"]
                or getattr(record.retest_status, "value", None) != row["retest_status"]
                or record.evidence_ids != expected_evidence):
            raise ValueError(_ERROR)
    return mapped
