"""Read-only operator authorization desk for the guarded LightUp web variant.

This surface reports *observed* database state.  Neither an approved request,
a recorded grant, nor an account role shown here is proof of authentic dual-
party consent or authority for active scanning.  No route in this module
issues permits, grants, approvals, revocations or tool executions.
"""

from __future__ import annotations

from datetime import datetime, timezone

from ..domain import AccessContext, DomainStore, Role
from .app import AuthState, Response, _e, _page


def _origin_label(store: DomainStore, requested_by: str, client_id: str) -> str:
    """Inspect current account lineage without claiming historical consent."""
    try:
        account = store.context_for_user(requested_by)
    except (KeyError, TypeError, ValueError):
        return "Unknown requester account — review"
    if type(account) is not AccessContext or type(account.role) is not Role:
        return "Malformed requester identity — review"
    if account.role is Role.OPERATOR:
        return "Operator account — review request provenance"
    if account.role in (Role.CLIENT_ADMIN, Role.CLIENT_MEMBER) and account.client_id == client_id:
        return "Matching client account (current role only)"
    return "Account/tenant mismatch — review"


def render_authorization_desk(
    store: DomainStore,
    auth: AuthState,
    *,
    client_id: str | None = None,
    max_rows: int = 60,
) -> Response:
    """Render an operator-only, no-write authorization and lineage overview.

    The operator account requirement is checked *again* here in addition to
    the route's dispatcher access label.  The complete data comes from the
    existing DomainStore authorization-aware read methods, never from client
    supplied parameters.  Grant data is displayed as an *unverified record*.
    """
    ctx = auth.context
    if type(ctx) is not AccessContext or ctx.role is not Role.OPERATOR:
        return Response("<h1>Operator access required</h1>", status="403 Forbidden")

    # Bound HTML output; an overflow is visible and is never silently treated
    # as complete. The store remains read-only throughout.
    max_rows = min(100, max(1, max_rows))
    if client_id is None:
        clients = store.list_clients(ctx)
        requests = store.list_assessment_requests(ctx)
        engagements = store.list_engagements(ctx)
    else:
        # A named-client view still authenticates as the operator; it does not
        # synthesize a client session or consult user-provided role claims.
        clients = [store.get_client(ctx, client_id)]
        requests = store.list_assessment_requests(ctx, client_id)
        engagements = store.list_engagements(ctx, client_id)
    client_map = {c.client_id: c for c in clients}
    snapshot = datetime.now(timezone.utc)
    pending_count = sum(
        req.status.value in {"submitted", "under_review"} for req in requests
    )
    request_cards = []
    for request in requests[:max_rows]:
        origin = _origin_label(store, request.requested_by, request.client_id)
        client = client_map.get(request.client_id)
        client_name = client.name if client else "Unknown client — review"
        client_link = (
            '<a href="/authorization-desk/clients/' + _e(request.client_id) +
            '">' + _e(client_name) + '</a>'
        )
        requested_assets = ", ".join(request.requested_assets[:8])
        if len(request.requested_assets) > 8:
            requested_assets += " … (additional assets omitted)"
        request_cards.append(
            '<div class="card">'
            '<div class="row"><strong>' + client_link + '</strong>'
            '<span class="badge warn">' + _e(request.status.value) + '</span></div>'
            '<p class="meta">Request: ' + _e(request.request_id)
            + '<br>Requested mode: ' + _e(request.requested_mode.value)
            + ' · risk level ' + _e(int(request.requested_risk))
            + '<br>Assets: ' + _e(requested_assets or "—")
            + '<br>Current account provenance: ' + _e(origin)
            + '</p><p class="meta">Review of a request is not client consent '
            'and does not authorize execution.</p></div>'
        )

    engagement_cards = []
    for engagement in engagements[:max_rows]:
        client = client_map.get(engagement.client_id)
        label = "No current grant record"
        badge = "warn"
        try:
            grant = store.get_current_grant(ctx, engagement.engagement_id, snapshot)
        except (ValueError, TypeError, OverflowError):
            label = "Grant record cannot be safely interpreted — review"
            grant = None
        if grant is not None:
            if (
                grant.client_id != engagement.client_id
                or grant.engagement_id != engagement.engagement_id
            ):
                label = "Grant/engagement identity mismatch — review"
            else:
                label = "Time-current grant record — not execution authority"
                badge = "lock"
        engagement_cards.append(
            '<div class="card"><div class="row"><strong>'
            + _e(client.name if client else "Unknown client — review")
            + ': ' + _e(engagement.name)
            + '</strong><span class="badge ' + badge + '">Review only</span></div>'
            '<p class="meta">Lifecycle: ' + _e(engagement.status.value)
            + '<br>Grant observation: ' + _e(label)
            + '</p><p class="meta">Grant issuance and live authorization '
            'require independent verified consent and at-use revocation checks.'
            '</p></div>'
        )

    overflow = ""
    if len(requests) > max_rows or len(engagements) > max_rows:
        overflow = (
            '<div class="card"><strong>Partial view</strong>'
            '<p class="meta">Only the latest '
            + str(max_rows)
            + ' requests and engagements per section are shown. '
            'This page is not a complete audit or an authorization decision.</p></div>'
        )
    client_links = "".join(
        '<a href="/authorization-desk/clients/' + _e(client.client_id)
        + '">' + _e(client.name) + '</a> · '
        for client in clients[:max_rows]
    )
    selected_name = clients[0].name if client_id is not None else None
    body = (
        '<h1>Authorization desk' +
        (' — ' + _e(selected_name) if selected_name else '') + '</h1>'
        '<p class="sub">Read-only triage of assessment requests, account lineage '
        'and stored grant records. Never an execution or consent certificate.</p>'
        '<div class="card"><div class="row">'
        '<span class="badge lock">Active execution locked</span>'
        '<span class="badge lock">Dual-party consent not verified</span>'
        '<span class="badge lock">Release not approved</span></div>'
        '<p class="meta">A recorded approval or time-current grant is not sufficient '
        'to activate tools. An independently authenticated client, operator, '
        'live revocation check and release gates remain mandatory.</p></div>'
        '<div class="grid">'
        '<div class="card"><div class="kpi">' + str(len(clients)) +
        '</div><div class="kpi-label">Clients</div></div>'
        '<div class="card"><div class="kpi">' + str(pending_count) +
        '</div><div class="kpi-label">Requests awaiting review</div></div>'
        '<div class="card"><div class="kpi">' + str(len(engagements)) +
        '</div><div class="kpi-label">Engagements</div></div></div>'
        '<p><a href="/assessments">Open operator assessment review</a>'
        ' · <a href="/clients">Client records</a>'
        ' · <a href="/authorization-desk">All clients</a>'
        ' · <a href="/">Overview</a></p>'
        + (('<div class="card"><strong>Choose client</strong><p class="meta">'
             + client_links + '</p></div>') if client_id is None else '')
        + overflow
        + '<h2>Client assessment requests</h2>'
        + ("".join(request_cards) or '<p class="empty">No requests recorded.</p>')
        + '<h2>Engagement grant records</h2>'
        + ("".join(engagement_cards) or '<p class="empty">No engagements recorded.</p>')
        + '<p class="meta">Read-only snapshot at ' + _e(snapshot.isoformat())
        + '. Current account roles may differ from their roles when a request '
        'was first submitted. This view does not infer approved scope or '
        'actual authorization from record coexistence.</p>'
    )
    return Response(_page("LightUp — Authorization desk", "assessments", body, auth))
