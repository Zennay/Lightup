"""Opt-in, read-only assessment-request decision provenance validator (#880).

Not installed in DomainStore, default web, grant issuance, or dispatch.
Validates coherence only; passing does NOT itself authorize any action.
"""
from __future__ import annotations

from datetime import datetime

from .domain import AssessmentRequestRecord, RequestStatus


def checked_request_decision_provenance(
    record: AssessmentRequestRecord,
) -> AssessmentRequestRecord:
    """Fail closed on malformed status/decision tuple without changing record."""
    if type(record) is not AssessmentRequestRecord:
        raise TypeError("request provenance requires canonical record")
    if type(record.status) is not RequestStatus:
        raise ValueError("request decision status invalid")

    actor, instant = record.decided_by, record.decided_at
    if record.status in (RequestStatus.SUBMITTED, RequestStatus.UNDER_REVIEW):
        if actor is not None or instant is not None:
            raise ValueError("open request carries unexpected decision provenance")
        return record

    if record.status not in (RequestStatus.APPROVED, RequestStatus.REJECTED):
        raise ValueError("request decision status invalid")
    if type(actor) is not str or not actor or not actor.strip():
        raise ValueError("decided request lacks canonical actor")
    if type(instant) is not str or not instant or not instant.strip():
        raise ValueError("decided request lacks canonical time")
    try:
        when = datetime.fromisoformat(instant)
        if when.tzinfo is None or when.utcoffset() is None:
            raise ValueError("naive decision instant")
    except (TypeError, ValueError, OverflowError):
        raise ValueError("decided request has invalid decision instant") from None
    return record
