"""Non-authorizing, offline review of *real* LightUp lab dispatch envelopes.

This is a syntactic, disposable-lab HUMAN REVIEW hint only. This module never
instantiates a ToolExecutor, calls a handler, issues a grant, authenticates the
operator, checks real lab network isolation, or enables active execution.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import sqlite3
from typing import Any

from .ai.orchestration import RunContext, ToolCall, ToolDefinition
from .engagements import AssessmentMode, RiskLevel
from .execution_policy import InteractionKind
from .lab_approval_candidate_ledger import (
    CandidateHeld, LabApprovalCandidateLedger,
)


def _receipt(looks_consistent: bool) -> dict[str, object]:
    return {
        "status": "REVIEW_ONLY" if looks_consistent else "HOLD",
        "authorization_verified": False,
        "permit_issued": False,
        "execution_enabled": False,
        "merge_approved": False,
        "release_approved": False,
    }


def _id(value: Any) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= 128
        and all(0x21 <= ord(char) <= 0x7e for char in value)
        and not any(char in "*?%" for char in value)
    )


def _utc(value: Any) -> bool:
    return (
        type(value) is datetime
        and type(value.tzinfo) is timezone
        and value.utcoffset() == timedelta(0)
    )


def review_lab_candidate_dispatch(
    ledger: LabApprovalCandidateLedger,
    context: RunContext,
    call: ToolCall,
    definition: ToolDefinition,
) -> dict[str, object]:
    """Consistent offline preview of one lab candidate, never authority.

    A standalone call owns one SQLite read snapshot. A caller already holding
    a transaction (e.g. the separate atomic batch reviewer) keeps ownership:
    no nested BEGIN, no committing or rolling back their transaction. Any
    cross-connection write observed during a standalone review forces HOLD.
    """
    # Validate exact outer types before any attribute/property access.
    if (
        type(ledger) is not LabApprovalCandidateLedger
        or type(context) is not RunContext
        or type(call) is not ToolCall
        or type(definition) is not ToolDefinition
    ):
        return _receipt(False)
    db = getattr(ledger, "_db", None)
    if type(db) is not sqlite3.Connection:
        return _receipt(False)
    try:
        if db.in_transaction:
            # Batch reviewer owns a cross-item SQLite snapshot. This still
            # cannot authenticate operator identity or confer execution.
            return _review_inside_snapshot(ledger, context, call, definition)
    except sqlite3.Error:
        return _receipt(False)

    began = False
    rollback_ok = True
    outcome = _receipt(False)
    first_version = None
    try:
        first_version = db.execute("PRAGMA data_version").fetchone()[0]
        if type(first_version) is not int:
            return _receipt(False)
        db.execute("BEGIN")
        began = True
        outcome = _review_inside_snapshot(ledger, context, call, definition)
    except sqlite3.Error:
        outcome = _receipt(False)
    finally:
        if began:
            try:
                db.rollback()
            except sqlite3.Error:
                rollback_ok = False
    if not rollback_ok or first_version is None:
        return _receipt(False)
    try:
        last_version = db.execute("PRAGMA data_version").fetchone()[0]
    except sqlite3.Error:
        return _receipt(False)
    if type(last_version) is not int or first_version != last_version:
        return _receipt(False)
    return outcome


def _review_inside_snapshot(
    ledger: LabApprovalCandidateLedger,
    context: RunContext,
    call: ToolCall,
    definition: ToolDefinition,
) -> dict[str, object]:
    """Compare a genuine LightUp envelope inside an existing read snapshot.

    REVIEW_ONLY never grants authorization. A stored candidate cannot substitute
    for a trusted human operator, approved target, dispatch policy or network
    confinement. Every malformed or inconsistent envelope yields HOLD and
    five permanently false authority bits.
    """
    # Reject substituted outer model types BEFORE accessing their attributes.
    if (
        type(ledger) is not LabApprovalCandidateLedger
        or type(context) is not RunContext
        or type(call) is not ToolCall
        or type(definition) is not ToolDefinition
    ):
        return _receipt(False)
    try:
        if not all(_id(value) for value in (
            context.run_id, context.client_id, context.engagement_id,
            call.asset, call.tool_id, definition.tool_id,
            definition.capability_id,
        )):
            return _receipt(False)
        if (
            context.mode is not AssessmentMode.LAB_AUTONOMOUS
            or context.is_lab is not True
            or context.authorization is not None
            or context.approved_risk is not RiskLevel.DESTRUCTIVE_LAB_ONLY
            or definition.interaction is not InteractionKind.LAB_ACTIVE
            or definition.min_risk is not RiskLevel.DESTRUCTIVE_LAB_ONLY
            or call.tool_id != definition.tool_id
            or type(call.arguments) is not tuple
            or bool(call.arguments)
            or type(definition.parameters) is not tuple
            or bool(definition.parameters)
            or not _utc(context.created_at)
        ):
            return _receipt(False)
        now = datetime.now(timezone.utc)
        if context.created_at > now:
            return _receipt(False)
        receipt = ledger.review(context.run_id, client_id=context.client_id)
        if receipt.get("status") != "REVIEW_ONLY":
            return _receipt(False)
        candidate = ledger.inspect(context.run_id, client_id=context.client_id)
        if candidate is None:
            return _receipt(False)
        if not (
            candidate.client_id == context.client_id
            and candidate.run_id == context.run_id
            and candidate.engagement_id == context.engagement_id
            and candidate.asset == call.asset
            and candidate.tool_id == call.tool_id
            and candidate.capability_id == definition.capability_id
            and candidate.revoked_at is None
            and candidate.approved_at <= context.created_at <= now
            and now < candidate.expires_at
        ):
            return _receipt(False)
        return _receipt(True)
    except (CandidateHeld, ValueError, TypeError, OverflowError):
        return _receipt(False)
