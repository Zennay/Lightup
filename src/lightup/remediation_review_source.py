"""Read-only, opt-in DomainStore adapter for remediation review queues.

This is a consumer of an already-authenticated AccessContext and the existing
DomainStore tenant/engagement read guards. It is not an authentication system,
evidence verifier, or a target/remediation/retest dispatcher.
"""
from __future__ import annotations

import json

from .domain import AccessContext, DomainStore
from .remediation_review_queue import (
    RemediationReviewQueue,
    build_remediation_review_queue,
)


def read_remediation_review_queue(
    store: DomainStore,
    context: AccessContext,
    *,
    engagement_id: str,
) -> RemediationReviewQueue:
    """Read a single tenant/engagement and build a non-authorizing advisory.

    A trusted application entrypoint MUST authenticate the identity and build
    the AccessContext; instantiating one in user code does not establish consent.
    The existing DomainStore verifies tenant access to the engagement.
    """
    if type(store) is not DomainStore or type(context) is not AccessContext:
        raise ValueError("invalid remediation review read context")
    if (type(engagement_id) is not str
            or not 1 <= len(engagement_id) <= 128
            or engagement_id != engagement_id.strip()
            or not engagement_id.isascii()
            or not engagement_id.isprintable()):
        raise ValueError("invalid remediation review engagement selector")

    # DomainStore.get_engagement performs access-context tenant validation.
    # There is no operator-global-list route: the caller must select exactly
    # one engagement, even when a privileged operator uses this helper.
    engagement = store.get_engagement(context, engagement_id)
    try:
        rows = store.list_findings(context, engagement_id=engagement.engagement_id)
        if len(rows) > 128:
            raise ValueError("too many remediation review findings")
        # Legacy DomainStore reads can coerce JSON objects into tuples of
        # their keys, silently laundering corrupt evidence into valid-looking
        # strings. Reconcile the *raw* per-engagement JSON to every decoded
        # FindingRecord before returning anything. Read-only and bounded.
        raw_by_id: dict[str, tuple[str, ...]] = {}
        with store._connect() as connection:
            persisted = connection.execute(
                "SELECT finding_id, evidence_ids_json FROM findings "
                "WHERE engagement_id=?", (engagement.engagement_id,),
            )
            for persisted_row in persisted:
                if len(raw_by_id) >= 128:
                    raise ValueError("too many persisted remediation findings")
                raw = persisted_row["evidence_ids_json"]
                if type(raw) is not str or len(raw) > 16384:
                    raise ValueError("invalid persisted evidence JSON")
                decoded = json.loads(raw)
                if type(decoded) is not list or len(decoded) > 64:
                    raise ValueError("invalid persisted evidence array")
                if any(type(item) is not str for item in decoded):
                    raise ValueError("invalid persisted evidence member")
                finding_key = persisted_row["finding_id"]
                if type(finding_key) is not str or finding_key in raw_by_id:
                    raise ValueError("invalid persisted finding identity")
                raw_by_id[finding_key] = tuple(decoded)
        if len(raw_by_id) != len(rows):
            raise ValueError("remediation review selected row drift")
        for row in rows:
            if raw_by_id.get(row.finding_id) != row.evidence_ids:
                raise ValueError("remediation review evidence lineage drift")
        # Re-check every persisted finding's claimed tenant and engagement.
        # A corrupt or cross-tenant row must not produce even a summary.
        return build_remediation_review_queue(
            tuple(rows),
            client_id=engagement.client_id,
            engagement_id=engagement.engagement_id,
        )
    except (ValueError, TypeError, UnicodeError) as exc:
        # DomainStore's legacy decoder currently leaks JSONDecodeError/TypeError
        # on corrupt evidence JSON. This adapter normalizes read-side failures,
        # without modifying the source-owned decoder or touching the row.
        raise ValueError("remediation evidence read integrity invalid") from None
