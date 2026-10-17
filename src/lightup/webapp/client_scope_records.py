"""Tenant-isolated client transparency view of stored scope/grant records.

Stored grant data does not establish authentic signed consent, at-use
revocation, or execution authority. Never expose cross-tenant/corrupt rows.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from ..domain import AccessContext, DomainStore, Role
from .app import AuthState, Response, _e, _page

MAX_ENGAGEMENTS = 32
MAX_GRANTS = 48
MAX_ASSETS = 32


def _client_context(auth: AuthState, client_id: str) -> AccessContext | None:
    ctx = auth.context
    if type(ctx) is not AccessContext or type(ctx.role) is not Role:
        return None
    if ctx.role is not Role.OPERATOR and ctx.client_id != client_id:
        return None
    return ctx


def _grant_record(grant: Any, client_id: str, engagement_id: str,
                  now: datetime) -> dict[str, Any] | None:
    """Return only well-formed records whose persisted tenant linkage agrees."""
    try:
        if (
            type(grant.client_id) is not str or grant.client_id != client_id
            or type(grant.engagement_id) is not str
            or grant.engagement_id != engagement_id
        ):
            return None
        scope = grant.scope
        assets = scope.assets
        exclusions = scope.excluded_assets
        if (
            type(assets) is not tuple or type(exclusions) is not tuple
            or len(assets) == 0 or len(assets) > 256
            or len(exclusions) > 256
            or any(type(item) is not str or
                   not 0 < len(item.strip()) <= 1024
                   for item in (*assets, *exclusions))
        ):
            return None
        risk = int(scope.max_risk)
        if not 0 <= risk <= 4:
            return None
        start, end = grant.valid_from, grant.valid_until
        if (
            type(start) is not datetime or type(end) is not datetime
            or start.tzinfo is None or end.tzinfo is None
            or start.utcoffset() is None or end.utcoffset() is None
            or start >= end
        ):
            return None
        if now < start:
            window = "Recorded window starts later"
        elif now > end:
            window = "Recorded window expired"
        else:
            window = "Recorded window includes current UTC time"
        return {
            "window_observation": window,
            "starts_at": start.isoformat(),
            "ends_at": end.isoformat(),
            "max_risk_recorded": risk,
            "assets": list(assets[:MAX_ASSETS]),
            "assets_truncated": len(assets) > MAX_ASSETS,
            "excluded_assets": list(exclusions[:MAX_ASSETS]),
            "excluded_assets_truncated": len(exclusions) > MAX_ASSETS,
            "scope_binding_verified": False,
            "client_consent_verified": False,
            "execution_authorized": False,
        }
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None


def client_scope_snapshot(
    store: DomainStore, auth: AuthState, client_id: str,
) -> dict[str, Any] | None:
    """Use real session context + explicit tenant checks for every visible row."""
    ctx = _client_context(auth, client_id)
    if ctx is None:
        return None
    try:
        client = store.get_client(ctx, client_id)
        engagements = store.list_engagements(ctx, client_id)
    except (KeyError, TypeError, ValueError, OverflowError):
        return None
    now = datetime.now(timezone.utc)
    visible: list[dict[str, Any]] = []
    withheld = 0
    partial = len(engagements) > MAX_ENGAGEMENTS
    for engagement in engagements[:MAX_ENGAGEMENTS]:
        # DomainStore's existing join is not a substitute for validating
        # each grant's persisted client+engagement identity (issue #829).
        if engagement.client_id != client_id:
            withheld += 1
            continue
        try:
            grants = store.list_authorization_grants(ctx, engagement.engagement_id)
        except (KeyError, TypeError, ValueError, OverflowError):
            withheld += 1
            continue
        partial = partial or len(grants) > MAX_GRANTS
        recorded = []
        for grant in grants[:MAX_GRANTS]:
            value = _grant_record(grant, client_id, engagement.engagement_id, now)
            if value is None:
                withheld += 1
            else:
                recorded.append(value)
        visible.append({
            "engagement_id": engagement.engagement_id,
            "engagement_name": engagement.name,
            "engagement_state": engagement.status.value,
            "grant_records": recorded,
        })
    return {
        "schema": "lightup.client-scope-records.v1",
        "disposition": "RECORD_ONLY",
        "client_id": client_id,
        "client_name": client.name,
        "observed_at": now.isoformat(),
        "partial": partial,
        "withheld_inconsistent_records": withheld,
        "engagements": visible,
        "request_binding_verified": False,
        "client_consent_verified": False,
        "operator_consent_verified": False,
        "revocation_checked_at_use": False,
        "execution_authorized": False,
        "release_approved": False,
        "notice": (
            "This view reports stored scope records only. Their existence "
            "or current time window does not prove client consent, approved "
            "request linkage, current revocation status or scanning permission."
        ),
    }


def _not_available_json() -> Response:
    return Response('{"error":"scope records unavailable"}',
                    "404 Not Found", "application/json; charset=utf-8")


def client_scope_json(
    store: DomainStore, auth: AuthState, client_id: str,
) -> Response:
    snapshot = client_scope_snapshot(store, auth, client_id)
    if snapshot is None:
        return _not_available_json()
    value = json.dumps(snapshot, ensure_ascii=True, separators=(",", ":"))
    if len(value.encode("utf-8")) > 128 * 1024:
        return Response('{"error":"scope view too large"}',
                        "413 Payload Too Large", "application/json; charset=utf-8")
    return Response(value, content_type="application/json; charset=utf-8")


def client_scope_page(
    store: DomainStore, auth: AuthState, client_id: str,
) -> Response:
    snapshot = client_scope_snapshot(store, auth, client_id)
    if snapshot is None:
        return Response("<h1>Scope records unavailable</h1>", "404 Not Found")
    cards = []
    for engagement in snapshot["engagements"]:
        grants = []
        for grant in engagement["grant_records"]:
            assets = "".join("<li>" + _e(asset) + "</li>"
                             for asset in grant["assets"])
            exclusions = "".join("<li>" + _e(asset) + "</li>"
                                 for asset in grant["excluded_assets"])
            grants.append(
                '<div class="card"><span class="badge warn">'
                'Recorded scope — not authorization</span>'
                '<p><strong>Window:</strong> ' + _e(grant["window_observation"])
                + '<br><strong>Recorded start:</strong> ' + _e(grant["starts_at"])
                + '<br><strong>Recorded end:</strong> ' + _e(grant["ends_at"])
                + '<br><strong>Risk ceiling in record:</strong> '
                + _e(grant["max_risk_recorded"]) + '</p>'
                '<details><summary>Recorded assets and exclusions</summary>'
                '<p>Recorded assets:</p><ul>' + assets + '</ul>'
                '<p>Excluded assets:</p><ul>'
                + (exclusions or '<li>None recorded</li>') + '</ul>'
                + ('<p class="meta">Asset lists truncated</p>'
                   if grant["assets_truncated"] or
                      grant["excluded_assets_truncated"] else "")
                + '</details></div>'
            )
        cards.append(
            '<div class="card"><strong>' + _e(engagement["engagement_name"])
            + '</strong><p class="meta">Engagement state: '
            + _e(engagement["engagement_state"]) + '</p>'
            + ("".join(grants)
               or '<p class="empty">No readable scope records.</p>')
            + '</div>'
        )
    body = (
        '<h1>Recorded assessment scope</h1>'
        '<p class="sub">Transparency for ' + _e(snapshot["client_name"])
        + ': what the database records, not what testing is authorized.</p>'
        '<div class="card"><span class="badge lock">Active testing locked</span>'
        '<p class="meta">A recorded grant, time window or approval does not '
        'establish verified client/operator consent or a right to run tools. '
        'The independent request binding and at-use revocation gates '
        'are not met by this page.</p></div>'
        '<p><a href="/portal/' + _e(client_id)
        + '">Back to portal</a> · '
        '<a href="/api/v1/portal/' + _e(client_id)
        + '/scope-records">Read-only JSON status</a></p>'
        + ('<p class="meta">Some records were withheld because their tenant '
           'lineage or shape could not be trusted.</p>'
           if snapshot["withheld_inconsistent_records"] else "")
        + ('<p class="meta">Partial view: additional records omitted.</p>'
           if snapshot["partial"] else "")
        + ("".join(cards) or '<p class="empty">No engagements recorded.</p>')
    )
    return Response(_page("LightUp — Recorded scope", "portal", body, auth,
                          portal_client=client_id))
