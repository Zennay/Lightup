"""Read-only tenant-scoped snapshot adapter for evidence/remediation advisory.

Opt-in consumer of a separately authenticated AccessContext. Never exposes a
global-finding reader, issues permissions or executes remediation/retests.
"""
from __future__ import annotations

import json

from .domain import AccessContext, DomainStore
from .remediation_review_queue import (
    MAX_EVIDENCE_IDS,
    MAX_FINDINGS,
    RemediationReviewQueue,
    build_remediation_review_queue,
)

MAX_EVIDENCE_JSON_CHARS = 16384


def read_remediation_review_queue(
    store: DomainStore,
    context: AccessContext,
    *,
    engagement_id: str,
) -> RemediationReviewQueue:
    """Read one engagement's findings from a single SQLite read snapshot.

    A trusted application MUST first authenticate the caller and construct
    AccessContext from trusted session data. These structural checks and the
    returned digest are NOT authorization or evidence-verification proofs.
    """
    if type(store) is not DomainStore or type(context) is not AccessContext:
        raise ValueError("invalid remediation review read context")
    if (
        type(engagement_id) is not str
        or not 1 <= len(engagement_id) <= 128
        or engagement_id != engagement_id.strip()
        or not engagement_id.isascii()
        or not engagement_id.isprintable()
    ):
        raise ValueError("invalid remediation review engagement selector")

    # Preserve DomainStore's tenant access contract and its independent
    # TenantIsolationError / KeyError distinctions for unauthorized or
    # nonexistent engagements. No operator-global-list fallback.
    engagement = store.get_engagement(context, engagement_id)

    try:
        with store._connect() as connection:
            # DomainStore._connect uses SQLite autocommit; explicit BEGIN
            # pins the engagement, raw evidence and finding data to ONE
            # consistent read transaction, instead of separate reads.
            connection.execute("BEGIN")
            try:
                scoped = connection.execute(
                    "SELECT engagement_id, client_id FROM engagements "
                    "WHERE engagement_id=?", (engagement_id,),
                ).fetchone()
                if (
                    scoped is None
                    or scoped["engagement_id"] != engagement.engagement_id
                    or scoped["client_id"] != engagement.client_id
                ):
                    raise ValueError("remediation review engagement snapshot drift")

                # Request MAX+1 rows so oversized engagements fail before
                # decoding arbitrary amounts of source-controlled evidence.
                rows = connection.execute(
                    "SELECT * FROM findings WHERE engagement_id=? "
                    "ORDER BY created_at DESC LIMIT ?",
                    (engagement_id, MAX_FINDINGS + 1),
                ).fetchall()
                if len(rows) > MAX_FINDINGS:
                    raise ValueError("too many remediation review findings")

                findings = []
                for row in rows:
                    if (
                        type(row["client_id"]) is not str
                        or row["client_id"] != engagement.client_id
                        or row["engagement_id"] != engagement_id
                    ):
                        raise ValueError("remediation review finding scope mismatch")

                    # DomainStore's legacy decoder coerces JSON objects to
                    # a tuple of keys. Refuse that ambiguity *before* using
                    # the source-owned row constructor.
                    raw = row["evidence_ids_json"]
                    if type(raw) is not str or len(raw) > MAX_EVIDENCE_JSON_CHARS:
                        raise ValueError("invalid persisted evidence JSON")
                    decoded = json.loads(raw)
                    if type(decoded) is not list or len(decoded) > MAX_EVIDENCE_IDS:
                        raise ValueError("invalid persisted evidence array")
                    if any(type(item) is not str for item in decoded):
                        raise ValueError("invalid persisted evidence member")

                    finding = DomainStore._finding_from_row(row)
                    if tuple(decoded) != finding.evidence_ids:
                        raise ValueError("remediation review evidence lineage drift")
                    findings.append(finding)

                result = build_remediation_review_queue(
                    tuple(findings),
                    client_id=engagement.client_id,
                    engagement_id=engagement_id,
                )
            finally:
                # Explicit read-only teardown: neither successful review nor
                # rejected legacy data leaves a SQLite transaction open.
                connection.execute("ROLLBACK")
        return result
    except (ValueError, TypeError, UnicodeError, OverflowError):
        # Generic error: do not echo corrupt stored evidence or SQLite fields.
        # Retain the actual domain tenant-denial exception above this block.
        raise ValueError("remediation evidence read integrity invalid") from None
