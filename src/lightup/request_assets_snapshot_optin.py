"""Optional atomic-snapshot assessment request reads for issue #877.

Deliberately uninstalled read-only references. Never grants target authority.
The live DomainStore get/list selectors and all grant/approval flows remain
unchanged and cannot be considered fixed by using this module in tests.
"""
from __future__ import annotations

from .domain import AccessContext, AssessmentRequestRecord, DomainStore
from .request_assets_shape_optin import checked_requested_assets_json


def _from_vetted_snapshot(row) -> AssessmentRequestRecord:
    """Validate durable asset JSON before projecting this SAME SQLite row."""
    canonical_assets = checked_requested_assets_json(row["requested_assets_json"])
    record = DomainStore._request_from_row(row)
    if record.requested_assets != canonical_assets:
        raise ValueError("persisted request asset projection changed")
    return record


def checked_get_assessment_request(
    store: DomainStore, context: AccessContext, request_id: str,
) -> AssessmentRequestRecord:
    """Read exact record with tenant-check first and validation on same row."""
    if type(request_id) is not str or not request_id:
        raise ValueError("assessment request id must be canonical")
    with store._connect() as connection:
        row = connection.execute(
            "SELECT * FROM assessment_requests WHERE request_id=?", (request_id,)
        ).fetchone()
        if row is None:
            raise KeyError("unknown assessment request")
        # Reject other-client reads before examining possibly corrupt assets.
        context.resolve_client(row["client_id"], "get_assessment_request")
        return _from_vetted_snapshot(row)


def checked_list_assessment_requests(
    store: DomainStore, context: AccessContext, client_id: str | None = None,
) -> list[AssessmentRequestRecord]:
    """All-or-nothing snapshot validation of all visible request rows."""
    with store._connect() as connection:
        if context.is_operator and client_id is None:
            rows = connection.execute(
                "SELECT * FROM assessment_requests ORDER BY created_at DESC"
            ).fetchall()
        else:
            scoped = context.resolve_client(client_id, "list_assessment_requests")
            rows = connection.execute(
                "SELECT * FROM assessment_requests WHERE client_id=? "
                "ORDER BY created_at DESC", (scoped,)
            ).fetchall()
        # Deliberately validate the full visible batch before projecting ANY
        # returned record: malformed later rows cannot partially succeed.
        for row in rows:
            checked_requested_assets_json(row["requested_assets_json"])
        return [_from_vetted_snapshot(row) for row in rows]
