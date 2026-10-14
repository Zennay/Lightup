"""Bounded atomic batch review of local, non-authorizing LightUp lab candidates.

A package containing ONE inconsistent or ambiguous synthetic request is
entirely HOLD. No target/network/tool execution, permit or verified consent.
"""
from __future__ import annotations

from dataclasses import dataclass

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


def review_lab_candidate_batch(
    ledger: LabApprovalCandidateLedger,
    items: tuple[LabCandidateReviewItem, ...],
) -> dict[str, object]:
    """Review at most 32 true model envelopes with all-or-none reporting.

    This code never dispatches a tool and never approves anything. Review
    results represent only locally declared synthetic candidate consistency.
    """
    if (
        type(ledger) is not LabApprovalCandidateLedger
        or type(items) is not tuple
        or not 1 <= len(items) <= 32
    ):
        return _result(0)
    seen_runs: set[tuple[str, str]] = set()
    asset_owners: dict[str, str] = {}
    for item in items:
        if type(item) is not LabCandidateReviewItem:
            return _result(0)
        receipt = review_lab_candidate_dispatch(
            ledger, item.context, item.call, item.definition,
        )
        if receipt.get("status") != "REVIEW_ONLY":
            return _result(0)
        # Outer model exact types are already verified by the single reviewer.
        context = item.context
        call = item.call
        run_key = (context.client_id, context.run_id)
        if run_key in seen_runs:
            return _result(0)
        seen_runs.add(run_key)
        # An untrusted multi-tenant packet must not silently represent the
        # same declared synthetic lab asset as two customers. Casefold avoids
        # the most obvious string-identity alias, but proves no DNS/ownership.
        asset_key = call.asset.casefold()
        prior = asset_owners.get(asset_key)
        if prior is not None and prior != context.client_id:
            return _result(0)
        asset_owners[asset_key] = context.client_id
    return _result(len(items))
