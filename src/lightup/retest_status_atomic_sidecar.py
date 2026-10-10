"""Opt-in atomic synthetic Finding retest-status metadata transition.

This sidecar is deliberately NOT wired into any user-facing or target executor
path. It repairs the ordering demonstrated by evidence-remediation issue #893
without editing the active DomainStore/decoder owner's source.

A successful metadata update NEVER means a remediation is verified or a retest
was performed. This helper cannot authenticate its caller: an external trusted
session and human authorization layer is mandatory before any integration.
"""

from __future__ import annotations

import json

from .domain import AccessContext, DomainStore, FindingRecord, Role, RoleError
from .models import RetestStatus

_MAX_EVIDENCE_JSON_BYTES = 16384
_MAX_EVIDENCE_IDS = 128
_MAX_EVIDENCE_ID_BYTES = 256
_IMMUTABLE_FINDING_COLUMNS = (
    "finding_id", "client_id", "engagement_id", "title", "severity",
    "asset", "impact", "remediation", "evidence_ids_json", "created_at",
)


def _checked_evidence_json(raw: str) -> tuple[str, ...]:
    """Validate persisted evidence as a bounded list; never repair legacy data."""
    if type(raw) is not str:
        raise ValueError("finding evidence is invalid")
    try:
        raw_size = len(raw.encode("utf-8"))
    except UnicodeError:
        raise ValueError("finding evidence is invalid") from None
    if raw_size > _MAX_EVIDENCE_JSON_BYTES:
        raise ValueError("finding evidence is invalid")
    try:
        values = json.loads(raw)
    except (ValueError, TypeError, RecursionError):
        raise ValueError("finding evidence is invalid") from None
    if type(values) is not list or len(values) > _MAX_EVIDENCE_IDS:
        raise ValueError("finding evidence is invalid")
    seen: set[str] = set()
    for item in values:
        if (
            type(item) is not str
            or not item
            or item != item.strip()
            or not item.isprintable()
            or len(item.encode("utf-8", errors="replace")) > _MAX_EVIDENCE_ID_BYTES
            or item in seen
        ):
            raise ValueError("finding evidence is invalid")
        seen.add(item)
    return tuple(values)


def atomic_retest_status_metadata(
    store: DomainStore,
    ctx: AccessContext,
    finding_id: str,
    status: RetestStatus,
) -> FindingRecord:
    """Atomically update existing *synthetic* retest-status metadata.

    Guard, read, canonical persisted-evidence decode and write occur under one
    SQLite BEGIN IMMEDIATE transaction. Any failure rolls back both fields.
    This is not an evidence verifier, an authorization gate or a test runner.

    It is intentionally separate from DomainStore.set_retest_status(); the
    source owner must integrate and security-review any actual production fix.
    """
    if type(store) is not DomainStore:
        raise TypeError("canonical DomainStore required")
    if (
        type(ctx) is not AccessContext
        or type(ctx.role) is not Role
        or ctx.role is not Role.OPERATOR
        or ctx.client_id is not None
        or type(ctx.user_id) is not str
        or not 0 < len(ctx.user_id) <= 128
        or not ctx.user_id.isprintable()
    ):
        raise RoleError("operator context required")
    if (
        type(finding_id) is not str
        or not 0 < len(finding_id) <= 128
        or not finding_id.isprintable()
    ):
        raise ValueError("invalid finding id")
    if type(status) is not RetestStatus:
        raise TypeError("canonical retest status required")
    # FIXED/REGRESSION are *outcomes*, not metadata. A helper without any
    # independent retest verifier must never mint either claim.
    if status not in (RetestStatus.NOT_TESTED, RetestStatus.FIX_PENDING):
        raise ValueError("independent retest evidence required for outcome status")

    with store._connect() as connection:
        try:
            # Serialize cross-process writers before checking durable evidence.
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT f.* FROM findings AS f JOIN engagements AS e "
                "ON e.engagement_id=f.engagement_id AND e.client_id=f.client_id "
                "WHERE f.finding_id=?",
                (finding_id,),
            ).fetchone()
            if row is None:
                raise KeyError("finding unavailable")
            checked = _checked_evidence_json(row["evidence_ids_json"])
            previous = DomainStore._finding_from_row(row)
            if previous.evidence_ids != checked:
                raise ValueError("finding evidence is invalid")
            changes_before = connection.total_changes
            updated = connection.execute(
                "UPDATE findings SET retest_status=? "
                "WHERE finding_id=? AND client_id=? AND engagement_id=? "
                "AND retest_status=? AND evidence_ids_json=?",
                (
                    status.value,
                    finding_id,
                    previous.client_id,
                    previous.engagement_id,
                    previous.retest_status.value,
                    row["evidence_ids_json"],
                ),
            ).rowcount
            if updated != 1:
                raise ValueError("finding status changed")
            # SQLite total_changes includes trigger-induced changes to *other*
            # rows that a row-local after-image comparison cannot detect.
            if connection.total_changes - changes_before != 1:
                raise ValueError("unexpected retest transaction write")
            after = connection.execute(
                "SELECT * FROM findings WHERE finding_id=?", (finding_id,)
            ).fetchone()
            if after is None or any(
                after[column] != row[column]
                for column in _IMMUTABLE_FINDING_COLUMNS
            ):
                # Even a row-local SQLite trigger may not silently change
                # tenant, identity, remediation text or raw evidence bytes.
                raise ValueError("finding changed during retest metadata update")
            result = DomainStore._finding_from_row(after)
            # The record is reconstructed *before* committing any mutation.
            if result.evidence_ids != checked or result.retest_status is not status:
                raise ValueError("finding evidence is invalid")
            connection.commit()
            return result
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
