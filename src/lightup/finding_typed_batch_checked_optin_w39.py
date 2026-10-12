"""Opt-in typed postcondition; caller must authorize selection independently."""
from __future__ import annotations

from .domain import FindingRecord
from .models import Severity, RetestStatus
from .finding_identity_batch_checked_optin_w38 import checked_identity_findings_batch

_ERROR = "invalid persisted finding evidence integrity"
_FIELDS = ("finding_id", "client_id", "engagement_id", "title", "asset", "impact", "remediation", "created_at")


def checked_typed_findings_batch(rows, *, expected_client_id, expected_engagement_id):
    mapped = checked_identity_findings_batch(rows, expected_client_id=expected_client_id, expected_engagement_id=expected_engagement_id)
    for record in mapped:
        if type(record) is not FindingRecord:
            raise ValueError(_ERROR)
        if any(type(getattr(record, name)) is not str for name in _FIELDS):
            raise ValueError(_ERROR)
        if type(record.severity) is not Severity or type(record.retest_status) is not RetestStatus:
            raise ValueError(_ERROR)
        if type(record.evidence_ids) is not tuple or any(type(ref) is not str for ref in record.evidence_ids):
            raise ValueError(_ERROR)
    return mapped
