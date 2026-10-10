"""Read-only tenant-scoped snapshot adapter for evidence/remediation advisory.

Opt-in consumer of a separately authenticated AccessContext. Never exposes a
global-finding reader, issues permissions or executes remediation/retests.
"""
from __future__ import annotations

import json
import sqlite3

from .domain import AccessContext, DomainStore, Role, TenantIsolationError
from .remediation_review_queue import (
    MAX_EVIDENCE_IDS,
    MAX_FINDINGS,
    MAX_ID,
    MAX_TEXT,
    RemediationReviewQueue,
    build_remediation_review_queue,
)

MAX_EVIDENCE_JSON_CHARS = 16384

# SQLite can store far more than the caller's size budget in a TEXT/BLOB cell.
# A SELECT * would materialize it *before* Python validation and allow large
# database fields to exhaust worker memory. Project each known column to a
# max+1 prefix: oversize data stays detectably invalid, never silently valid.
# All identifiers and lengths below are static trusted constants.
_BOUNDED_ENGAGEMENT_SELECT = f"""
SELECT
    substr(engagement_id, 1, {MAX_ID + 1}) AS engagement_id,
    substr(client_id, 1, {MAX_ID + 1}) AS client_id
FROM engagements WHERE engagement_id=?
"""

_BOUNDED_FINDING_SELECT = f"""
SELECT
    substr(finding_id, 1, {MAX_ID + 1}) AS finding_id,
    substr(client_id, 1, {MAX_ID + 1}) AS client_id,
    substr(engagement_id, 1, {MAX_ID + 1}) AS engagement_id,
    substr(title, 1, {MAX_TEXT + 1}) AS title,
    substr(severity, 1, {MAX_ID + 1}) AS severity,
    substr(asset, 1, {MAX_TEXT + 1}) AS asset,
    substr(impact, 1, {MAX_TEXT + 1}) AS impact,
    substr(remediation, 1, {MAX_TEXT + 1}) AS remediation,
    substr(retest_status, 1, {MAX_ID + 1}) AS retest_status,
    substr(evidence_ids_json, 1, {MAX_EVIDENCE_JSON_CHARS + 1}) AS evidence_ids_json,
    substr(created_at, 1, {MAX_TEXT + 1}) AS created_at
FROM findings WHERE engagement_id=?
LIMIT ?
"""


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
    # DomainStore.AccessContext allows arbitrary runtime field types because
    # its source owner intentionally has a minimal constructor. This optional
    # reader must not silently treat a string role as a client role, accept an
    # empty subject, or pass a polymorphic client identifier into scope checks.
    # Canonical structure is not session authentication: the caller MUST still
    # derive the context from its trusted session/revocation authority.
    user = context.user_id
    client = context.client_id
    if (
        type(context.role) is not Role
        or type(user) is not str
        or not 1 <= len(user) <= MAX_ID
        or user != user.strip()
        or not user.isprintable()
        or (context.role is Role.OPERATOR and client is not None)
        or (context.role is not Role.OPERATOR and (
            type(client) is not str
            or not 1 <= len(client) <= MAX_ID
            or client != client.strip()
            or not client.isascii()
            or not client.isprintable()
        ))
    ):
        raise ValueError("invalid remediation review read context")

    try:
        with store._connect() as connection:
            # An extra defense on this disposable connection: even if a later
            # consumer accidentally adds SQL writes to this advisory path,
            # SQLite itself refuses them. This does not grant any authority.
            connection.execute("PRAGMA query_only=ON")
            # DomainStore._connect runs SQLite in autocommit; pin the *tenant
            # admission* and all source records to one version at the first
            # SELECT. A trusted caller must construct context from an
            # authenticated session; the context itself is not a grant.
            connection.execute("BEGIN")
            try:
                # The engagement's tenant ID can be malformed/oversized too.
                # Project only MAX+1 so Python never allocates arbitrary
                # persistent client metadata before validating admission.
                scoped = connection.execute(
                    _BOUNDED_ENGAGEMENT_SELECT, (engagement_id,),
                ).fetchone()
                if scoped is None:
                    # Client identities must not discover whether an opaque
                    # engagement ID exists for another tenant. Both unknown
                    # and known-but-inaccessible IDs are one denial surface.
                    if context.role is not Role.OPERATOR:
                        raise TenantIsolationError(
                            "remediation review tenant scope denied"
                        ) from None
                    raise ValueError("remediation review engagement not found")
                if (
                    type(scoped["engagement_id"]) is not str
                    or scoped["engagement_id"] != engagement_id
                    or type(scoped["client_id"]) is not str
                    or not 1 <= len(scoped["client_id"]) <= MAX_ID
                    or scoped["client_id"] != scoped["client_id"].strip()
                    or not scoped["client_id"].isascii()
                    or not scoped["client_id"].isprintable()
                ):
                    raise ValueError("invalid remediation engagement identity")
                # Exactly the same AccessContext tenant admission primitive
                # used by DomainStore.get_engagement, now on this snapshot.
                try:
                    context.resolve_client(
                        scoped["client_id"], "read_remediation_review_queue"
                    )
                except TenantIsolationError:
                    raise TenantIsolationError(
                        "remediation review tenant scope denied"
                    ) from None
                client_id = scoped["client_id"]

                # Request MAX+1 rows so oversized engagements fail before
                # decoding arbitrary amounts of source-controlled evidence.
                # Do not sort by the unbounded persisted created_at column:
                # all <=128 rows are sorted by advisory priority in the
                # builder; >128 rows are denied regardless of read order.
                # SQL ORDER BY created_at would sort maliciously huge source
                # values before our per-column projection/size checks.
                rows = connection.execute(
                    _BOUNDED_FINDING_SELECT,
                    (engagement_id, MAX_FINDINGS + 1),
                ).fetchall()
                if len(rows) > MAX_FINDINGS:
                    raise ValueError("too many remediation review findings")

                findings = []
                for row in rows:
                    if (
                        type(row["client_id"]) is not str
                        or row["client_id"] != client_id
                        or row["engagement_id"] != engagement_id
                    ):
                        raise ValueError("remediation review finding scope mismatch")

                    # DomainStore's legacy decoder coerces JSON objects to
                    # a tuple of keys. Refuse that ambiguity *before* using
                    # the source-owned row constructor.
                    raw = row["evidence_ids_json"]
                    if type(raw) is not str or len(raw) > MAX_EVIDENCE_JSON_CHARS:
                        raise ValueError("invalid persisted evidence JSON")
                    # Legacy evidence is always a top-level JSON array; reject
                    # scalars/objects before invoking a general JSON decoder.
                    # Python's JSON parser may raise RecursionError on deeply
                    # nested malformed input; normalize it below, never leak a
                    # Python stack or raw evidence through this read-only API.
                    if not raw.lstrip().startswith("["):
                        raise ValueError("invalid persisted evidence envelope")
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
                    client_id=client_id,
                    engagement_id=engagement_id,
                )
            finally:
                # Explicit read-only teardown: neither successful review nor
                # rejected legacy data leaves a SQLite transaction open.
                connection.execute("ROLLBACK")
        return result
    except TenantIsolationError:
        # Preserve the authorization-denial *type*, not its sensitive text.
        raise
    except (ValueError, TypeError, UnicodeError, OverflowError, RecursionError, sqlite3.DatabaseError) as exc:
        if type(exc) is ValueError and str(exc) == "remediation review engagement not found":
            raise ValueError("remediation review engagement not found") from None
        # Generic data failure: do not echo corrupt stored evidence/identities.
        raise ValueError("remediation evidence read integrity invalid") from None
