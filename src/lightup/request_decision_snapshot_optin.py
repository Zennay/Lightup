"""Issue #880: uninstalled, read-only, tenant-gated SQLite snapshot selectors.

Only illustrates how to check decision provenance before exposing rows.
Does NOT amend DomainStore, authorize engagements, or create grants.
"""
from __future__ import annotations

from .domain import AccessContext, AssessmentRequestRecord, DomainStore
from .request_decision_provenance_optin import checked_request_decision_provenance


def _checked_row(row) -> AssessmentRequestRecord:
    # Same row is projected and validated; never select it a second time.
    return checked_request_decision_provenance(DomainStore._request_from_row(row))


def checked_get_decision_request(
    store: DomainStore, context: AccessContext, request_id: str,
) -> AssessmentRequestRecord:
    """Check tenant identity before touching a decision provenance payload."""
    if type(request_id) is not str or not request_id:
        raise ValueError("request id must be canonical")
    with store._connect() as connection:
        row = connection.execute(
            "SELECT * FROM assessment_requests WHERE request_id=?", (request_id,)
        ).fetchone()
        if row is None:
            raise KeyError("unknown assessment request")
        context.resolve_client(row["client_id"], "get_assessment_request")
        return _checked_row(row)


def checked_list_decision_requests(
    store: DomainStore, context: AccessContext, client_id: str | None = None,
) -> list[AssessmentRequestRecord]:
    """Refuse a complete visible batch on ANY bad decision provenance."""
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
        # The caller sees nothing when a later row fails admission.
        return [_checked_row(row) for row in rows]
