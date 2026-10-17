"""Fail-closed browser controls for LightUp's opt-in guarded web application.

These constraints narrow the existing web session workflow. They are NOT a
replacement for the domain-level immutable request/grant binding required by
issue #177, or authentic independent client/operator consent at use.
"""

from __future__ import annotations

from ..domain import AccessContext, ApprovalStatus, DomainStore, RequestStatus, Role
from ..engagements import AssessmentMode, RiskLevel
from .app import AuthState, Response, _e

MAX_REQUEST_ASSETS = 128


def approval_blockers(store: DomainStore, auth: AuthState, request) -> tuple[str, ...]:
    """Reasons an operator may not mark a stored client request approved.

    A CURRENT client user record is an extra provenance check, not historic
    signed consent. No result from this helper permits a grant or a scan.
    """
    ctx = auth.context
    if type(ctx) is not AccessContext or ctx.role is not Role.OPERATOR:
        return ("A real operator session is required",)

    problems: list[str] = []
    if type(request.status) is not RequestStatus or request.status not in (
        RequestStatus.SUBMITTED, RequestStatus.UNDER_REVIEW
    ):
        problems.append("Request is no longer open for review")
    if request.requested_mode is not AssessmentMode.AUTHORIZED_ASSESSMENT:
        problems.append("Request mode is not authorized-assessment")
    if type(request.requested_risk) is not RiskLevel or not (
        RiskLevel.PASSIVE <= request.requested_risk <= RiskLevel.ELEVATED
    ):
        problems.append("Requested risk is not within the client review range")
    assets = request.requested_assets
    if (
        type(assets) is not tuple
        or not 1 <= len(assets) <= MAX_REQUEST_ASSETS
        or any(type(a) is not str or not 0 < len(a.strip()) <= 1024 for a in assets)
        or len({a.strip().casefold() for a in assets}) != len(assets)
    ):
        problems.append("Requested assets have an invalid or ambiguous shape")

    if (
        type(request.requested_by) is not str
        or not request.requested_by
        or request.requested_by == ctx.user_id
    ):
        problems.append("Request cannot be reviewed by its submitting account")
    try:
        user_ctx = store.context_for_user(request.requested_by)
    except (KeyError, ValueError, TypeError):
        problems.append("Submitting account is missing or malformed")
    else:
        if (
            type(user_ctx) is not AccessContext
            or type(user_ctx.role) is not Role
            or user_ctx.role not in (Role.CLIENT_ADMIN, Role.CLIENT_MEMBER)
            or user_ctx.client_id != request.client_id
        ):
            problems.append("Submitting account is not a client of this tenant")

    try:
        client = store.get_client(ctx, request.client_id)
    except (KeyError, ValueError, TypeError):
        problems.append("Request client is missing or invalid")
    else:
        if client.status != "active":
            problems.append("Client account is not active")
    return tuple(problems)


def lock_grant_form(markup: str, *, expected: int) -> str | None:
    """Hide the inherited unsafe grant issuance form on client detail pages.

    Fail closed on a changed template, rather than leaving a clickable form.
    The actual POST remains independently blocked by the web handler.
    """
    import re

    pattern = re.compile(
        r"<details><summary>Record authorization grant</summary>"
        r"<form\b[^>]*>.*?</form></details>",
        re.DOTALL,
    )
    replacement = (
        '<div class="card"><span class="badge lock">Grant issuance locked</span>'
        '<p class="meta">This application cannot issue grants until a durable '
        'approved-client-request binding exists in the domain, with separate '
        'verified consent and live revocation. Review stored records in the '
        'authorization desk; this notice does not change database state.</p></div>'
    )
    changed, count = pattern.subn(replacement, markup)
    if count != expected:
        return None
    # The inherited badge is not an independent consent statement, even if a
    # grant time window currently overlaps the clock.
    changed = changed.replace(
        'Authorization current</span>',
        'Grant time-current (consent unverified)</span>',
    ).replace(
        'No current authorization</span>',
        'No time-current grant record</span>',
    ).replace(
        '<summary>Authorization details</summary>',
        '<summary>Recorded grant details (not execution authority)</summary>',
    )
    return changed


def hide_unsafe_approval_buttons(
    markup: str, store: DomainStore, auth: AuthState
) -> str | None:
    """Replace only the inherited Approve form for invalid provenance.

    Reject remains available to safely close invalid historical requests.
    The POST authorization check below is authoritative even if the UI
    changes; fail closed if the inherited HTML form no longer matches.
    """
    records = store.list_assessment_requests(auth.context)
    for request in records:
        if request.status not in (RequestStatus.SUBMITTED, RequestStatus.UNDER_REVIEW):
            continue
        reasons = approval_blockers(store, auth, request)
        if not reasons:
            continue
        action = '/assessments/requests/' + _e(request.request_id) + '/decision'
        open_form = '<form class="inline" method="post" action="' + action + '">'
        start = markup.find(open_form)
        # Parent renders BOTH Approve and Reject forms with the SAME action
        # URL. The first is the approval action; the second must remain so an
        # operator can safely reject a forged historical request.
        if start < 0 or markup.count(open_form) != 2:
            return None
        end_marker = '<button>Approve</button></form>'
        end = markup.find(end_marker, start)
        # Do not replace beyond the next form or card: HTML template drift
        # must never accidentally replace unrelated actions.
        next_form = markup.find('<form', start + len(open_form))
        if end < 0 or (next_form >= 0 and next_form < end):
            return None
        end += len(end_marker)
        markup = (
            markup[:start]
            + '<span class="badge lock">Approval locked: '
            + _e("; ".join(reasons))
            + '</span> '
            + markup[end:]
        )
    return markup


def workflow_denied(message: str = "Action requires verified authorization") -> Response:
    return Response(
        '<h1>Authorization boundary</h1><p class="meta">' + _e(message) + '</p>',
        status="423 Locked",
    )


def elevation_blockers(store: DomainStore, auth: AuthState, record) -> tuple[str, ...]:
    """Protect an administrative risk-elevation review from fabricated origin."""
    ctx = auth.context
    if type(ctx) is not AccessContext or ctx.role is not Role.OPERATOR:
        return ("A real operator session is required",)
    problems: list[str] = []
    if record.status is not ApprovalStatus.PENDING:
        problems.append("Risk elevation is already decided")
    if record.decided_by is not None or record.decided_at is not None:
        problems.append("Pending risk elevation has inconsistent decision metadata")
    if (
        type(record.requested_risk) is not RiskLevel
        or not (RiskLevel.PASSIVE <= record.requested_risk <= RiskLevel.ELEVATED)
    ):
        problems.append("Risk is outside the bounded client risk range")
    if (
        type(record.justification) is not str or
        not 0 < len(record.justification.strip()) <= 4096
    ):
        problems.append("Risk elevation has an invalid justification")
    if record.requested_by == ctx.user_id:
        problems.append("An operator cannot decide their own risk request")
    try:
        requester = store.context_for_user(record.requested_by)
        engagement = store.get_engagement(ctx, record.engagement_id)
    except (KeyError, ValueError, TypeError):
        problems.append("Risk elevation requester/engagement provenance is missing")
    else:
        if (
            type(requester) is not AccessContext
            or type(requester.role) is not Role
            or requester.role not in (Role.CLIENT_ADMIN, Role.CLIENT_MEMBER)
            or requester.client_id != record.client_id
            or engagement.client_id != record.client_id
        ):
            problems.append("Risk elevation requester is not from this client")
    return tuple(problems)


def hide_unsafe_elevation_buttons(
    markup: str, store: DomainStore, auth: AuthState
) -> str | None:
    """Render dangerous risk-elevation actions as locked, not actionable."""
    approvals = [
        a for a in store.list_risk_approvals(auth.context)
        if a.status is ApprovalStatus.PENDING
    ]
    for approval in approvals:
        reasons = elevation_blockers(store, auth, approval)
        if not reasons:
            continue
        action = '/assessments/elevations/' + _e(approval.approval_id) + '/decision'
        open_form = '<form class="inline" method="post" action="' + action + '">'
        start = markup.find(open_form)
        if start < 0 or markup.count(open_form) != 2:
            return None
        end_marker = '<button>Approve elevation</button></form>'
        end = markup.find(end_marker, start)
        second_form = markup.find('<form', start + len(open_form))
        if end < 0 or (second_form >= 0 and second_form < end):
            return None
        end += len(end_marker)
        locked = (
            '<span class="badge lock">Risk elevation approval locked: '
            + _e("; ".join(reasons)) + '</span> '
        )
        markup = markup[:start] + locked + markup[end:]
        # The domain forbids self-decision even when it is a denial. Hide the
        # second form for the same actor instead of offering a dead-end button.
        if approval.requested_by == auth.context.user_id:
            remaining = markup.find(open_form)
            if remaining < 0:
                return None
            close = markup.find('</form>', remaining)
            if close < 0:
                return None
            markup = (
                markup[:remaining]
                + '<span class="badge lock">Self-decision prohibited</span>'
                + markup[close + len('</form>'):]
            )
    return markup
