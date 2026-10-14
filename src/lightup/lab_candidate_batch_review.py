"""Bounded atomic batch review of local, non-authorizing LightUp lab candidates.

A package containing ONE inconsistent or ambiguous synthetic request is
entirely HOLD. No target/network/tool execution, permit or verified consent.
"""
from __future__ import annotations

from dataclasses import dataclass
import sqlite3

from .ai.orchestration import RunContext, ToolCall, ToolDefinition
from .lab_approval_candidate_ledger import LabApprovalCandidateLedger
from .lab_candidate_dispatch_review import review_lab_candidate_dispatch


@dataclass(frozen=True)
class LabCandidateReviewItem:
    context: RunContext
    call: ToolCall
    definition: ToolDefinition


def _result(reviewable: int) -> dict[str, object]:
    return {
        "status": "REVIEW_ONLY" if reviewable > 0 else "HOLD",
        "reviewable_items": reviewable,
        "authorization_verified": False,
        "permit_issued": False,
        "execution_enabled": False,
        "merge_approved": False,
        "release_approved": False,
    }


def _review_rows(
    ledger: LabApprovalCandidateLedger,
    items: tuple[LabCandidateReviewItem, ...],
) -> dict[str, object]:
    """Inspect every envelope inside a single, existing SQLite snapshot."""
    seen_runs: set[tuple[str, str]] = set()
    seen_assets: set[str] = set()
    for item in items:
        if type(item) is not LabCandidateReviewItem:
            return _result(0)
        receipt = review_lab_candidate_dispatch(
            ledger, item.context, item.call, item.definition,
        )
        if receipt.get("status") != "REVIEW_ONLY":
            return _result(0)
        # Exact outer model identity is checked by the single reviewer.
        context = item.context
        call = item.call
        run_key = (context.client_id, context.run_id)
        if run_key in seen_runs:
            return _result(0)
        seen_runs.add(run_key)
        # Risk-5 candidate packets must not silently duplicate a declared
        # lab target across independent runs, even under one tenant. A human
        # can review distinct packets separately; none authorizes execution.
        # Casefold catches obvious ASCII aliases, NOT real asset ownership.
        asset_key = call.asset.casefold()
        if asset_key in seen_assets:
            return _result(0)
        seen_assets.add(asset_key)
    return _result(len(items))


def review_lab_candidate_batch(
    ledger: LabApprovalCandidateLedger,
    items: tuple[LabCandidateReviewItem, ...],
) -> dict[str, object]:
    """Single-snapshot synthetic batch review, never an execution permit.

    Fail closed if the SQLite connection is already owned by a caller
    transaction, if the read transaction fails, or if another connection
    changes the database during review. No caller-owned transaction is
    committed/rolled back; this function opens and ends only its own.
    """
    if (
        type(ledger) is not LabApprovalCandidateLedger
        or type(items) is not tuple
        or not 1 <= len(items) <= 32
    ):
        return _result(0)
    db = getattr(ledger, "_db", None)
    if type(db) is not sqlite3.Connection:
        return _result(0)
    try:
        if db.in_transaction:
            return _result(0)
    except sqlite3.Error:
        return _result(0)

    opened = False
    rollback_ok = True
    outcome = _result(0)
    before = None
    try:
        # data_version detects commits by OTHER connections. It cannot
        # authenticate an operator or prevent changes after our return.
        before = db.execute("PRAGMA data_version").fetchone()[0]
        if type(before) is not int:
            return _result(0)
        db.execute("BEGIN")
        opened = True
        outcome = _review_rows(ledger, items)
    except sqlite3.Error:
        outcome = _result(0)
    finally:
        if opened:
            try:
                db.rollback()  # release ONLY our read transaction
            except sqlite3.Error:
                rollback_ok = False

    if not rollback_ok or before is None:
        return _result(0)
    try:
        after = db.execute("PRAGMA data_version").fetchone()[0]
    except sqlite3.Error:
        return _result(0)
    return outcome if type(after) is int and before == after else _result(0)
