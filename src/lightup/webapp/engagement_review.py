"""Non-authorizing engagement/grant review for the guarded operator portal.

Read *existing* request and grant records without writing or trying to repair
them. In particular, textual overlap is NOT persisted request-to-grant binding,
client/operator consent, or permission to run any tool.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

from ..domain import AccessContext, DomainStore, Role
from ..engagements import AssessmentMode
from .app import AuthState, Response, _e, _page

MAX_ITEMS = 40
MAX_ASSETS = 24


def _operator(auth: AuthState) -> bool:
    ctx = auth.context
    return type(ctx) is AccessContext and ctx.role is Role.OPERATOR


def _safe_identity(value: object) -> bool:
    return (type(value) is str and re.fullmatch(r"[A-Za-z0-9-]{1,80}", value) is not None)


def _assessment_candidates(grant: Any, requests: list[Any]) -> list[str]:
    """Text-only possible counterparts, not proof of real authorization."""
    try:
        assets = grant.scope.assets
        if (
            type(assets) is not tuple or not 0 < len(assets) <= 256
            or any(type(asset) is not str or not asset.strip() for asset in assets)
        ):
            return []
        grant_assets = set(assets)
        if len(grant_assets) != len(assets):
            return []
        matches = []
        for request in requests:
            if (
                request.client_id != grant.client_id
                or request.status.value != "approved"
                or request.requested_mode is not AssessmentMode.AUTHORIZED_ASSESSMENT
                or not isinstance(request.requested_assets, tuple)
                or not isinstance(request.requested_risk, int)
                or not grant_assets.issubset(set(request.requested_assets))
                or int(grant.scope.max_risk) > int(request.requested_risk)
            ):
                continue
            if _safe_identity(request.request_id):
                matches.append(request.request_id)
            if len(matches) >= 12:
                break
        return matches
    except (AttributeError, TypeError, ValueError, OverflowError):
        return []


def _window(grant: Any, now: datetime) -> str:
    try:
        start = grant.valid_from
        end = grant.valid_until
        if (
            type(start) is not datetime or type(end) is not datetime
            or start.tzinfo is None or end.tzinfo is None
            or start.utcoffset() is None or end.utcoffset() is None
            or start >= end
        ):
            return "Invalid authorization window — review"
        if now < start:
            return "Recorded window has not started"
        if now > end:
            return "Recorded window has expired"
        return "Recorded time window currently overlaps UTC — NOT permission"
    except (AttributeError, TypeError, ValueError, OverflowError):
        return "Unreadable time window — review"


def engagement_snapshot(
    store: DomainStore, auth: AuthState, engagement_id: str,
    *, limit: int = MAX_ITEMS,
) -> dict[str, Any] | None:
    """Read a bounded operator snapshot; no branch can return true authority."""
    if not _operator(auth):
        return None
    ctx = auth.context
    bound = max(1, min(MAX_ITEMS, limit))
    try:
        engagement = store.get_engagement(ctx, engagement_id)
        client = store.get_client(ctx, engagement.client_id)
        records = store.list_authorization_grants(ctx, engagement_id)
        requests = store.list_assessment_requests(ctx, engagement.client_id)
    except (KeyError, TypeError, ValueError, OverflowError):
        # Database corruption/unknown lineage is never transformed into
        # a trustworthy partial certificate.
        return None

    now = datetime.now(timezone.utc)
    rows: list[dict[str, Any]] = []
    for grant in records[:bound]:
        try:
            assets = grant.scope.assets
            if type(assets) is not tuple:
                raise ValueError("malformed asset scope")
            safe_assets = (
                len(assets) <= 256
                and all(type(a) is str and 0 < len(a) <= 1024 for a in assets)
            )
            lineage_ok = (
                grant.client_id == engagement.client_id
                and grant.engagement_id == engagement.engagement_id
            )
            risk = int(grant.scope.max_risk)
            if not 0 <= risk <= 5 or not safe_assets:
                raise ValueError("malformed risk or assets")
            candidates = _assessment_candidates(grant, requests) if lineage_ok else []
            record = {
                "grant_id": str(grant.grant_id)[:128],
                "lineage": (
                    "Recorded client/engagement IDs agree"
                    if lineage_ok else
                    "Client or engagement lineage mismatch — review"
                ),
                "window": _window(grant, now),
                "risk": risk,
                "assets": list(assets[:MAX_ASSETS]),
                "assets_truncated": len(assets) > MAX_ASSETS,
                "request_candidates": candidates,
                "request_binding": "NOT VERIFIED — no immutable request link",
                "consent_verified": False,
                "authorized": False,
            }
        except (AttributeError, TypeError, ValueError, OverflowError):
            record = {
                "grant_id": "Unreadable grant record",
                "lineage": "Malformed grant — review",
                "window": "Unavailable",
                "risk": None,
                "assets": [],
                "assets_truncated": False,
                "request_candidates": [],
                "request_binding": "NOT VERIFIED",
                "consent_verified": False,
                "authorized": False,
            }
        rows.append(record)
    requests_summary = []
    for request in requests[:bound]:
        try:
            requests_summary.append({
                "request_id": str(request.request_id)[:128],
                "status": request.status.value,
                "requested_risk": int(request.requested_risk),
                "mode": request.requested_mode.value,
                "client_id_matches": request.client_id == engagement.client_id,
            })
        except (AttributeError, TypeError, ValueError, OverflowError):
            requests_summary.append({
                "request_id": "Unreadable request",
                "status": "unavailable",
                "requested_risk": None,
                "mode": "unknown",
                "client_id_matches": False,
            })
    return {
        "schema": "lightup.operator-engagement-review.v1",
        "disposition": "REVIEW_ONLY",
        "engagement_id": engagement.engagement_id,
        "engagement_name": engagement.name,
        "engagement_status": engagement.status.value,
        "client_id": client.client_id,
        "client_name": client.name,
        "observed_at": now.isoformat(),
        "grant_count": len(records),
        "request_count": len(requests),
        "partial": len(records) > bound or len(requests) > bound,
        "grants": rows,
        "requests": requests_summary,
        "request_binding_verified": False,
        "client_consent_verified": False,
        "operator_consent_verified": False,
        "revocation_checked_at_use": False,
        "execution_authorized": False,
        "release_approved": False,
        "notice": (
            "Database grant records and possible request counterparts are only "
            "observations. Text overlap is not immutable grant/request binding, "
            "authenticated client consent, live revocation or execution authority."
        ),
    }


def engagement_review_page(
    store: DomainStore, auth: AuthState, engagement_id: str,
) -> Response:
    if not _operator(auth):
        return Response("<h1>Operator access required</h1>", "403 Forbidden")
    snap = engagement_snapshot(store, auth, engagement_id)
    if snap is None:
        return Response("<h1>Engagement review unavailable</h1>",
                        "404 Not Found")
    grant_cards = []
    for grant in snap["grants"]:
        candidate_links = "".join(
            '<li><a href="/authorization-desk/requests/' + _e(request_id) +
            '">' + _e(request_id) + '</a></li>'
            for request_id in grant["request_candidates"]
        ) or "<li>No textually matching approved request in this snapshot</li>"
        assets = "".join(
            "<li>" + _e(asset) + "</li>" for asset in grant["assets"]
        ) or "<li>No readable asset list</li>"
        grant_cards.append(
            '<div class="card"><span class="badge lock">NOT AUTHORIZED</span>'
            '<p><strong>Record:</strong> ' + _e(grant["grant_id"])
            + '<br><strong>Lineage:</strong> ' + _e(grant["lineage"])
            + '<br><strong>Time:</strong> ' + _e(grant["window"])
            + '<br><strong>Recorded risk:</strong> ' + _e(grant["risk"])
            + '</p><details><summary>Recorded assets</summary><ul>'
            + assets + '</ul>'
            + ('<p class="meta">Additional assets omitted</p>'
               if grant["assets_truncated"] else "")
            + '</details><details><summary>Potential request counterparts '
            '(not binding)</summary><ul>' + candidate_links + '</ul>'
            '<p class="meta">These are only exact textual overlaps. '
            'No immutable request ID is bound to this grant.</p></details></div>'
        )
    request_cards = "".join(
        '<div class="card"><a href="/authorization-desk/requests/' +
        _e(req["request_id"]) + '">' + _e(req["request_id"]) + '</a>'
        '<p class="meta">Status: ' + _e(req["status"]) +
        ' · Mode: ' + _e(req["mode"]) +
        ' · Risk: ' + _e(req["requested_risk"]) + '</p></div>'
        for req in snap["requests"]
    ) or '<p class="empty">No stored requests for this client.</p>'
    body = (
        '<h1>Engagement authorization records</h1><p class="sub">'
        + _e(snap["client_name"]) + " / " + _e(snap["engagement_name"]) +
        '</p><div class="card"><span class="badge lock">'
        'Request → grant binding NOT VERIFIED</span> '
        '<span class="badge lock">Execution locked</span>'
        '<p class="meta">Do not interpret a recorded time window, approved '
        'request or matching asset name as actual client consent or '
        'authorization. The domain-level immutable binding requirement '
        '(issue #177) and at-use revocation gate are not satisfied here.</p></div>'
        '<p><a href="/authorization-desk/clients/' + _e(snap["client_id"])
        + '">Client authorization desk</a> · '
        '<a href="/api/v1/operator/engagements/' + _e(snap["engagement_id"])
        + '/review">Read-only JSON</a></p>'
        + ('<p class="meta">Partial snapshot: record display is limited.</p>'
           if snap["partial"] else "")
        + '<h2>Recorded grants (' + str(snap["grant_count"]) + ')</h2>'
        + ("".join(grant_cards) or '<p class="empty">No recorded grants.</p>')
        + '<h2>Client assessment requests (' + str(snap["request_count"]) + ')</h2>'
        + request_cards
        + '<p class="meta">Snapshot: ' + _e(snap["observed_at"]) + '</p>'
    )
    return Response(_page("LightUp — Engagement review", "assessments",
                          body, auth))


def engagement_review_json(
    store: DomainStore, auth: AuthState, engagement_id: str,
) -> Response:
    if not _operator(auth):
        return Response('{"error":"operator access required"}',
                        "403 Forbidden", "application/json; charset=utf-8")
    snap = engagement_snapshot(store, auth, engagement_id)
    if snap is None:
        return Response('{"error":"engagement review unavailable"}',
                        "404 Not Found", "application/json; charset=utf-8")
    payload = json.dumps(snap, ensure_ascii=True, separators=(",", ":"))
    if len(payload.encode("utf-8")) > 128 * 1024:
        return Response('{"error":"review too large"}',
                        "413 Payload Too Large", "application/json; charset=utf-8")
    return Response(payload, content_type="application/json; charset=utf-8")


def attention_snapshot(
    store: DomainStore, auth: AuthState, *, limit: int = 32
) -> dict[str, Any] | None:
    """Bounded read-only work queue of engagement provenance observations.

    Nothing in this index is a release or execution verdict; each engagement
    requires an independent verified client/operator authorization workflow.
    """
    if not _operator(auth):
        return None
    bound = max(1, min(MAX_ITEMS, limit))
    try:
        engagements = store.list_engagements(auth.context)
    except (KeyError, TypeError, ValueError, OverflowError):
        return None
    records = []
    for engagement in engagements[:bound]:
        if not _safe_identity(engagement.engagement_id):
            # A damaged stored identity must never turn into a navigable link.
            return None
        detail = engagement_snapshot(store, auth, engagement.engagement_id)
        if detail is None:
            records.append({
                "engagement_id": engagement.engagement_id,
                "client_name": "Unknown",
                "engagement_name": "Unavailable",
                "grant_count": None,
                "follow_up": ["Engagement records cannot be read safely"],
                "review_url": (
                    "/authorization-desk/engagements/" + engagement.engagement_id
                ),
            })
            continue
        follow_up = []
        if detail["grant_count"] == 0:
            follow_up.append("No grant records stored")
        for grant in detail["grants"]:
            if grant["lineage"] != "Recorded client/engagement IDs agree":
                follow_up.append("Incoherent persisted client/engagement lineage")
            if grant["window"] != (
                "Recorded time window currently overlaps UTC — NOT permission"
            ):
                follow_up.append("Grant period missing, invalid or not current")
            if not grant["request_candidates"]:
                follow_up.append("No approved same-client textual request counterpart")
        if detail["partial"]:
            follow_up.append("Partial record view — further records not inspected")
        # The domain currently has no persisted immutable request-to-grant
        # binding; even a textual counterpart never removes this requirement.
        follow_up.append("Immutable approved-request/grant binding not verified")
        follow_up.append("Separate consent and at-use revocation not verified")
        records.append({
            "engagement_id": engagement.engagement_id,
            "client_name": detail["client_name"],
            "engagement_name": detail["engagement_name"],
            "grant_count": detail["grant_count"],
            "follow_up": sorted(set(follow_up)),
            "review_url": (
                "/authorization-desk/engagements/" + engagement.engagement_id
            ),
        })
    return {
        "schema": "lightup.operator-engagement-attention.v1",
        "disposition": "REVIEW_ONLY",
        "engagement_total": len(engagements),
        "partial": len(engagements) > bound,
        "items": records,
        "request_binding_verified": False,
        "client_consent_verified": False,
        "operator_consent_verified": False,
        "revocation_checked_at_use": False,
        "execution_authorized": False,
        "release_approved": False,
        "notice": (
            "The attention queue groups stored records for human follow-up. "
            "No item is approved for target interaction."
        ),
    }


def engagement_attention_page(store: DomainStore, auth: AuthState) -> Response:
    if not _operator(auth):
        return Response("<h1>Operator access required</h1>", "403 Forbidden")
    snapshot = attention_snapshot(store, auth)
    if snapshot is None:
        return Response("<h1>Engagement worklist unavailable</h1>",
                        "503 Service Unavailable")
    cards = []
    for item in snapshot["items"]:
        follow_ups = "".join(
            "<li>" + _e(reason) + "</li>"
            for reason in item["follow_up"]
        )
        cards.append(
            '<div class="card"><div class="row"><strong>' +
            _e(item["client_name"]) + " — " +
            _e(item["engagement_name"]) +
            '</strong><span class="badge lock">Review required</span></div>'
            '<p class="meta">Recorded grants: ' +
            _e(item["grant_count"]) + '</p><ul>' +
            follow_ups + '</ul><a href="' +
            _e(item["review_url"]) + '">Open engagement dossier →</a></div>'
        )
    body = (
        '<h1>Engagement follow-up inbox</h1>'
        '<p class="sub">Human-readable next actions from existing records; '
        'never a permissions, consent or scanning dashboard.</p>'
        '<div class="card"><span class="badge lock">Execution locked</span>'
        '<p class="meta">The permanent request → grant binding, separate '
        'client/operator consent and live revocation check remain required '
        'outside this view.</p></div>'
        '<p><a href="/authorization-desk">Authorization desk</a> · '
        '<a href="/api/v1/operator/engagements/attention">Read-only JSON</a></p>'
        + ('<p class="meta">Partial view; additional engagements omitted.</p>'
           if snapshot["partial"] else "")
        + ("".join(cards) or '<p class="empty">No engagements recorded.</p>')
    )
    return Response(_page("LightUp — Engagement worklist", "assessments",
                          body, auth))


def engagement_attention_json(store: DomainStore, auth: AuthState) -> Response:
    if not _operator(auth):
        return Response('{"error":"operator access required"}',
                        "403 Forbidden", "application/json; charset=utf-8")
    snap = attention_snapshot(store, auth)
    if snap is None:
        return Response('{"error":"engagement worklist unavailable"}',
                        "503 Service Unavailable", "application/json; charset=utf-8")
    payload = json.dumps(snap, ensure_ascii=True, separators=(",", ":"))
    if len(payload.encode("utf-8")) > 128 * 1024:
        return Response('{"error":"engagement queue too large"}',
                        "413 Payload Too Large", "application/json; charset=utf-8")
    return Response(payload, content_type="application/json; charset=utf-8")
