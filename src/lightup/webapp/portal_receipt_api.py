"""Authenticated, non-authorizing JSON receipt for client portal integrations.

The receipt is a record of a request, not a proof of authorization.  Keep the
endpoint's output minimal: no tokens, grant references, identity passwords,
notes or unbounded data.  All reads use the existing tenant-isolated store.
"""

from __future__ import annotations

import json
import re

from ..domain import AccessContext, DomainStore, TenantIsolationError
from .app import AuthState, Response


def request_receipt_json(
    store: DomainStore,
    auth: AuthState,
    client_id: str,
    request_id: str,
    *,
    max_assets: int = 80,
) -> Response:
    """Read one tenant-bound request and render a versioned, no-authority JSON.

    The web router must additionally apply its `portal` access level.  This
    function independently rejects mismatched credentials and request lineage.
    """
    ctx = auth.context
    if type(ctx) is not AccessContext:
        return _missing()
    if not ctx.is_operator and ctx.client_id != client_id:
        return _missing()
    # Viewing an operator-selected client is not permission to act as that
    # client: this is a domain-checked read with the original operator context.
    try:
        request = store.get_assessment_request(ctx, request_id)
    except (KeyError, TenantIsolationError, ValueError, TypeError):
        return _missing()
    if (
        request.client_id != client_id
        or not isinstance(request.request_id, str)
        or re.fullmatch(r"[A-Za-z0-9-]{1,80}", request.request_id) is None
    ):
        return _missing()

    limit = min(100, max(1, max_assets))
    items = request.requested_assets[:limit]
    # Malformed stored data must never be transformed into a trust signal.
    if (
        type(request.request_id) is not str
        or type(request.client_id) is not str
        or not isinstance(request.requested_assets, tuple)
        or any(type(asset) is not str for asset in items)
    ):
        return _missing()

    from .request_clarifications import thread_states
    clarification_state = thread_states(
        store, auth, [request.request_id], client_id=client_id,
    ).get(request.request_id, "No question yet")
    payload = {
        "schema": "lightup.portal-request-receipt.v1",
        "disposition": "RECORD_ONLY",
        "request_id": request.request_id,
        "client_id": request.client_id,
        "status": request.status.value,
        "clarification_state": clarification_state,
        "requested_mode": request.requested_mode.value,
        "requested_risk": int(request.requested_risk),
        "submitted_at": request.created_at,
        "decided_at": request.decided_at,
        "requested_assets": list(items),
        "assets_truncated": len(request.requested_assets) > limit,
        "execution_authorized": False,
        "client_consent_verified": False,
        "operator_consent_verified": False,
        "grant_bound": False,
        "release_approved": False,
        "notice": (
            "This JSON is a request-status record, not permission to test "
            "targets. Verified separate consent and at-use revocation are required."
        ),
    }
    # ASCII JSON avoids problematic browser sniffing/encoding and remains
    # machine-readable. No sensitive free-text notes are exported.
    raw = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
    if len(raw) > 128 * 1024:
        return _missing()
    return Response(raw, content_type="application/json; charset=utf-8")


def _missing() -> Response:
    # Missing, cross-tenant and malformed records have the same outward shape.
    return Response(
        '{"error":"receipt not available"}',
        status="404 Not Found",
        content_type="application/json; charset=utf-8",
    )


def request_inbox_json(
    store: DomainStore,
    auth: AuthState,
    client_id: str,
    *,
    max_rows: int = 40,
) -> Response:
    """Bounded client request history for authenticated, tenant-bound UIs.

    No cursor or other user-supplied state can widen tenant scope.  This is a
    read-only snapshot, not a decision, approval or execution authorization.
    """
    ctx = auth.context
    if type(ctx) is not AccessContext:
        return _missing()
    if not ctx.is_operator and ctx.client_id != client_id:
        return _missing()
    try:
        store.get_client(ctx, client_id)
        requests = store.list_assessment_requests(ctx, client_id)
    except (KeyError, TenantIsolationError, ValueError, TypeError):
        return _missing()

    bound = max(1, min(50, max_rows))
    from .request_clarifications import thread_states
    clarification_badges = thread_states(
        store, auth, [req.request_id for req in requests[:bound]],
        client_id=client_id,
    )
    rows = []
    for request in requests[:bound]:
        if (
            request.client_id != client_id
            or type(request.request_id) is not str
            or re.fullmatch(r"[A-Za-z0-9-]{1,80}", request.request_id) is None
            or not isinstance(request.requested_assets, tuple)
        ):
            return _missing()
        rows.append({
            "request_id": request.request_id,
            "status": request.status.value,
            "clarification_state": clarification_badges.get(
                request.request_id, "No question yet"
            ),
            "requested_mode": request.requested_mode.value,
            "requested_risk": int(request.requested_risk),
            "submitted_at": request.created_at,
            "decided_at": request.decided_at,
            "requested_asset_count": len(request.requested_assets),
            "receipt_url": (
                "/api/v1/portal/" + client_id + "/requests/" + request.request_id
            ),
        })
    result = {
        "schema": "lightup.portal-request-index.v1",
        "disposition": "RECORD_ONLY",
        "client_id": client_id,
        "items": rows,
        "has_more": len(requests) > bound,
        "execution_authorized": False,
        "client_consent_verified": False,
        "operator_consent_verified": False,
        "grant_bound": False,
        "release_approved": False,
        "notice": (
            "The request list reflects database records only and does not "
            "establish any approval, client consent or execution permission."
        ),
    }
    raw = json.dumps(result, ensure_ascii=True, separators=(",", ":"))
    if len(raw) > 128 * 1024:
        return _missing()
    return Response(raw, content_type="application/json; charset=utf-8")
