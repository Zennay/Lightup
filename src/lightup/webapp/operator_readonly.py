"""Opt-in client-origin guard for LightUp's web portal.

The existing web shell deliberately allows operators to *view* client portals.
A portal assessment request must, however, originate from an authenticated
client, never from an operator masquerading as one.  This integration subclass
keeps the existing operator review routes and tenant-scoped client routes, and
does not modify their source owners.

This module adds no active capability and is not a consent or release gate.
"""

from __future__ import annotations

import argparse
import re
from ipaddress import ip_address
from wsgiref.simple_server import make_server

from ..domain import AccessContext, DomainStore, Role
from .app import AuthState, LightUpWebApp, Response, _e, _page, _redirect
from .security import WebSecurity

_PORTAL_FORM_HEADING = "<h2>Request an assessment</h2>"
_PORTAL_FORM_END = "</form></div>"
_OPERATOR_READONLY_NOTICE = (
    "<h2>Request an assessment</h2>"
    '<div class="card"><span class="badge lock">Client action only</span>'
    "<p class=\"meta\">You are viewing this client portal as an operator. "
    "Only a signed-in client for this tenant can submit an assessment request. "
    "Use Assessments to review client-submitted requests.</p></div>"
)


class OperatorReadOnlyWebApp(LightUpWebApp):
    """Guard portal writes and expose an operator-only, read-only review desk.

    Authorization boundaries are enforced inside the dispatcher and write
    handler; new GET-only review routes never mutate durable state.
    """

    def __init__(self, store: DomainStore, security: WebSecurity | None = None):
        super().__init__(store, security)
        from .request_clarifications import initialize_clarifications
        initialize_clarifications(store)
        self.routes.append((
            "GET", re.compile(r"^/authorization-desk$"),
            self.authorization_desk, "operator",
        ))
        self.routes.append((
            "POST", re.compile(r"^/operator/requests/(?P<request_id>[\w-]+)/clarifications$"),
            self.operator_post_clarification, "operator",
        ))
        self.routes.append((
            "POST", re.compile(
                r"^/portal/(?P<client_id>[\w-]+)/requests/"
                r"(?P<request_id>[\w-]+)/clarifications$"
            ),
            self.client_post_clarification, "portal",
        ))
        self.routes.append((
            "GET", re.compile(
                r"^/api/v1/operator/requests/(?P<request_id>[\w-]+)/clarifications$"
            ),
            self.operator_clarifications_json, "operator",
        ))
        self.routes.append((
            "GET", re.compile(
                r"^/api/v1/portal/(?P<client_id>[\w-]+)/requests/"
                r"(?P<request_id>[\w-]+)/clarifications$"
            ),
            self.client_clarifications_json, "portal",
        ))
        self.routes.append((
            "GET", re.compile(r"^/portal/(?P<client_id>[\w-]+)/scope-records$"),
            self.portal_scope_records, "portal",
        ))
        self.routes.append((
            "GET", re.compile(r"^/api/v1/portal/(?P<client_id>[\w-]+)/scope-records$"),
            self.portal_scope_records_api, "portal",
        ))
        self.routes.append((
            "GET", re.compile(r"^/authorization-desk/engagements/attention$"),
            self.authorization_engagement_attention, "operator",
        ))
        self.routes.append((
            "GET", re.compile(r"^/api/v1/operator/engagements/attention$"),
            self.authorization_engagement_attention_api, "operator",
        ))
        self.routes.append((
            "GET", re.compile(r"^/authorization-desk/engagements/(?P<engagement_id>[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$"),
            self.authorization_engagement_review, "operator",
        ))
        self.routes.append((
            "GET", re.compile(r"^/api/v1/operator/engagements/(?P<engagement_id>[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})/review$"),
            self.authorization_engagement_review_api, "operator",
        ))
        self.routes.append((
            "GET", re.compile(r"^/api/v1/operator/authorization-queue$"),
            self.operator_queue_api, "operator",
        ))
        self.routes.append((
            "GET", re.compile(r"^/authorization-desk/clients/(?P<client_id>[\w-]+)$"),
            self.authorization_client_desk, "operator",
        ))
        self.routes.append((
            "GET", re.compile(r"^/authorization-desk/queue/(?P<queue>pending|decided)$"),
            self.authorization_queue, "operator",
        ))
        self.routes.append((
            "GET", re.compile(r"^/authorization-desk/requests/(?P<request_id>[\w-]+)$"),
            self.authorization_request_detail, "operator",
        ))
        self.routes.append((
            "GET", re.compile(
                r"^/portal/(?P<client_id>[\w-]+)/requests/(?P<request_id>[\w-]+)$"
            ),
            self.portal_request_receipt, "portal",
        ))
        self.routes.append((
            "GET", re.compile(r"^/api/v1/portal/(?P<client_id>[\w-]+)/requests$"),
            self.portal_request_inbox_api, "portal",
        ))
        self.routes.append((
            "GET", re.compile(
                r"^/api/v1/portal/(?P<client_id>[\w-]+)/requests/"
                r"(?P<request_id>[\w-]+)$"
            ),
            self.portal_request_receipt_api, "portal",
        ))

    def operator_post_clarification(
        self, auth: AuthState, form: dict[str, str], request_id: str
    ) -> Response:
        from .request_clarifications import append_message, ClarificationDenied
        try:
            append_message(
                self.store, auth, request_id, form.get("message", ""),
                as_operator=True,
            )
        except (ClarificationDenied, KeyError, ValueError, TypeError):
            return Response(
                "<h1>Clarification not recorded</h1><p>Verify that this "
                "request is open, your account is valid and your message "
                "meets the length limit.</p>",
                status="409 Conflict",
            )
        return _redirect("/authorization-desk/requests/" + request_id)

    def client_post_clarification(
        self, auth: AuthState, form: dict[str, str],
        client_id: str, request_id: str
    ) -> Response:
        from .request_clarifications import append_message, ClarificationDenied
        ctx = auth.context
        if (
            type(ctx) is not AccessContext
            or ctx.role not in (Role.CLIENT_ADMIN, Role.CLIENT_MEMBER)
            or ctx.client_id != client_id
        ):
            return Response("<h1>Client account required</h1>",
                            status="403 Forbidden")
        try:
            request = self.store.get_assessment_request(ctx, request_id)
            if request.client_id != client_id:
                raise ClarificationDenied("Tenant mismatch")
            append_message(
                self.store, auth, request_id, form.get("message", ""),
                as_operator=False,
            )
        except (ClarificationDenied, KeyError, ValueError, TypeError):
            return Response(
                "<h1>Clarification not recorded</h1><p>Only an open request "
                "with a pending operator question accepts a client reply.</p>",
                status="409 Conflict",
            )
        return _redirect("/portal/" + client_id + "/requests/" + request_id)

    def operator_clarifications_json(
        self, auth: AuthState, form: dict[str, str], request_id: str
    ) -> Response:
        from .request_clarifications import operator_thread_json
        return operator_thread_json(self.store, auth, request_id)

    def client_clarifications_json(
        self, auth: AuthState, form: dict[str, str],
        client_id: str, request_id: str,
    ) -> Response:
        from .request_clarifications import client_thread_json
        return client_thread_json(self.store, auth, client_id, request_id)

    def authorization_desk(self, auth: AuthState, form: dict[str, str]) -> Response:
        from .authorization_desk import render_authorization_desk
        return render_authorization_desk(self.store, auth)

    def portal_scope_records(
        self, auth: AuthState, form: dict[str, str], client_id: str
    ) -> Response:
        from .client_scope_records import client_scope_page
        return client_scope_page(self.store, auth, client_id)

    def portal_scope_records_api(
        self, auth: AuthState, form: dict[str, str], client_id: str
    ) -> Response:
        from .client_scope_records import client_scope_json
        return client_scope_json(self.store, auth, client_id)

    def authorization_engagement_attention(
        self, auth: AuthState, form: dict[str, str]
    ) -> Response:
        from .engagement_review import engagement_attention_page
        return engagement_attention_page(self.store, auth)

    def authorization_engagement_attention_api(
        self, auth: AuthState, form: dict[str, str]
    ) -> Response:
        from .engagement_review import engagement_attention_json
        return engagement_attention_json(self.store, auth)

    def authorization_engagement_review(
        self, auth: AuthState, form: dict[str, str], engagement_id: str
    ) -> Response:
        from .engagement_review import engagement_review_page
        return engagement_review_page(self.store, auth, engagement_id)

    def authorization_engagement_review_api(
        self, auth: AuthState, form: dict[str, str], engagement_id: str
    ) -> Response:
        from .engagement_review import engagement_review_json
        return engagement_review_json(self.store, auth, engagement_id)

    def operator_queue_api(self, auth: AuthState, form: dict[str, str]) -> Response:
        from .authorization_desk import render_operator_queue_json
        return render_operator_queue_json(self.store, auth)

    def authorization_client_desk(
        self, auth: AuthState, form: dict[str, str], client_id: str
    ) -> Response:
        from .authorization_desk import render_authorization_desk
        return render_authorization_desk(self.store, auth, client_id=client_id)

    def authorization_queue(
        self, auth: AuthState, form: dict[str, str], queue: str
    ) -> Response:
        from .authorization_desk import render_authorization_desk
        return render_authorization_desk(self.store, auth, queue=queue)

    def authorization_request_detail(
        self, auth: AuthState, form: dict[str, str], request_id: str
    ) -> Response:
        from .authorization_desk import render_operator_request_detail
        return render_operator_request_detail(self.store, auth, request_id)

    def overview(self, auth: AuthState, form: dict[str, str]) -> Response:
        page = super().overview(auth, form)
        markup = page.body.decode("utf-8")
        marker = "</div></main>"
        offset = markup.rfind(marker)
        if offset < 0:
            return Response("<h1>Overview unavailable</h1>",
                            status="503 Service Unavailable")
        callout = (
            '<div class="card"><strong>Authorization desk</strong>'
            '<p class="meta">Review client requests, account provenance and '
            'stored grant records without activating execution.</p>'
            '<a href="/authorization-desk">Open read-only authorization desk →</a>'
            '</div>'
        )
        return Response(markup[:offset] + callout + markup[offset:],
                        status=page.status)

    def client_detail(self, auth: AuthState, form: dict[str, str],
                      client_id: str) -> Response:
        """Hide grant-creation forms until issue #177 is enforced in the domain."""
        from .authorization_controls import lock_grant_form

        page = super().client_detail(auth, form, client_id)
        ctx = auth.context
        engagements = self.store.list_engagements(ctx, client_id)
        missing = sum(
            self.store.get_current_grant(ctx, eng.engagement_id) is None
            for eng in engagements
        )
        markup = lock_grant_form(page.body.decode("utf-8"), expected=missing)
        if markup is None:
            return Response("<h1>Client details unavailable safely</h1>",
                            status="503 Service Unavailable")
        return Response(markup, status=page.status)

    def record_grant(self, auth: AuthState, form: dict[str, str],
                     engagement_id: str) -> Response:
        """No unbound web-origin grant may be issued through this variant."""
        from .authorization_controls import workflow_denied
        return workflow_denied(
            "Grant creation is locked until a durable approved-request-to-grant "
            "relationship and verified client/operator consent are enforced "
            "inside the domain. A recorded approval alone is not authority."
        )

    def assessments(self, auth: AuthState, form: dict[str, str]) -> Response:
        from .authorization_controls import (
            hide_unsafe_approval_buttons, hide_unsafe_elevation_buttons,
        )

        page = super().assessments(auth, form)
        markup = hide_unsafe_approval_buttons(
            page.body.decode("utf-8"), self.store, auth
        )
        if markup is not None:
            markup = hide_unsafe_elevation_buttons(markup, self.store, auth)
        if markup is None:
            return Response("<h1>Assessment review unavailable safely</h1>",
                            status="503 Service Unavailable")
        banner = (
            '<div class="card"><span class="badge lock">'
            'Execution and grant issuance locked</span>'
            '<p class="meta">Request approvals are administrative records, '
            'not independently authenticated client consent. Grant creation '
            'remains blocked until the request-to-grant domain invariant is '
            'implemented. Requests with suspicious provenance cannot be approved.'
            '</p><a href="/authorization-desk/queue/pending">'
            'Open safeguarded review inbox</a></div>'
        )
        anchor = '<h2>Assessment requests</h2>'
        if markup.count(anchor) != 1:
            return Response("<h1>Assessment review unavailable safely</h1>",
                            status="503 Service Unavailable")
        return Response(markup.replace(anchor, banner + anchor),
                        status=page.status)

    def decide_request(self, auth: AuthState, form: dict[str, str],
                       request_id: str) -> Response:
        """Only current tenant-bound client requests may gain APPROVED status.

        Rejection remains possible for invalid historical requests so they can
        be closed without approving them. Neither action creates a grant.
        """
        from .authorization_controls import approval_blockers, workflow_denied

        ctx = auth.context
        if type(ctx) is not AccessContext or ctx.role is not Role.OPERATOR:
            return workflow_denied("A real operator account is required")
        decision = form.get("decision")
        if decision not in ("approve", "reject"):
            return workflow_denied("An explicit approve or reject is required")
        try:
            request = self.store.get_assessment_request(ctx, request_id)
        except (KeyError, ValueError, TypeError):
            return workflow_denied("The stored request is unavailable")
        if decision == "approve":
            problems = approval_blockers(self.store, auth, request)
            if problems:
                return workflow_denied(
                    "Approval refused: " + "; ".join(problems)
                )
        self.store.review_assessment_request(
            ctx, request_id, approve=(decision == "approve")
        )
        return _redirect("/assessments")

    def decide_elevation(self, auth: AuthState, form: dict[str, str],
                         approval_id: str) -> Response:
        """Only an independently client-originated pending risk request may pass."""
        from .authorization_controls import elevation_blockers, workflow_denied

        ctx = auth.context
        if type(ctx) is not AccessContext or ctx.role is not Role.OPERATOR:
            return workflow_denied("A real operator account is required")
        decision = form.get("decision")
        if decision not in ("approve", "deny"):
            return workflow_denied("An explicit approve or deny is required")
        try:
            stored = next(
                (item for item in self.store.list_risk_approvals(ctx)
                 if item.approval_id == approval_id),
                None,
            )
        except (KeyError, ValueError, TypeError):
            return workflow_denied("The risk elevation record is unavailable")
        if stored is None:
            return workflow_denied("The risk elevation record is unavailable")
        if stored.requested_by == ctx.user_id:
            return workflow_denied("Risk elevations cannot be self-decided")
        if decision == "approve":
            reasons = elevation_blockers(self.store, auth, stored)
            if reasons:
                return workflow_denied(
                    "Risk elevation approval refused: " + "; ".join(reasons)
                )
        # The original domain method separately checks role and prevents
        # self-decision; this opt-in web gate never creates a client grant.
        self.store.decide_risk_elevation(
            ctx, approval_id, approve=(decision == "approve")
        )
        return _redirect("/assessments")

    def _dispatch(self, method: str, path: str, form: dict[str, str],
                  auth: AuthState) -> Response:
        if method == "GET" and (
            path == "/api/v1/operator/authorization-queue"
            or re.fullmatch(r"/api/v1/operator/requests/[\w-]+/clarifications", path)
            or path == "/api/v1/operator/engagements/attention"
            or re.fullmatch(r"/api/v1/operator/engagements/[\w-]+/review", path)
        ):
            if not auth.signed_in or type(auth.context) is not AccessContext:
                return Response(
                    '{"error":"authentication required"}',
                    status="401 Unauthorized",
                    content_type="application/json; charset=utf-8",
                )
            if not auth.is_operator:
                return Response(
                    '{"error":"operator access required"}',
                    status="403 Forbidden",
                    content_type="application/json; charset=utf-8",
                )
        if method == "GET" and path.startswith("/api/v1/portal/"):
            # A machine client must not interpret a redirect to an HTML sign-in
            # page as a successful JSON response. Keep missing and other-tenant
            # resources indistinguishable.
            if not auth.signed_in or type(auth.context) is not AccessContext:
                return Response(
                    '{"error":"authentication required"}',
                    status="401 Unauthorized",
                    content_type="application/json; charset=utf-8",
                )
            if not auth.is_operator:
                matched = re.fullmatch(
                    r"/api/v1/portal/([\w-]+)/(?:requests(?:/[\w-]+(?:/clarifications)?)?|scope-records)", path
                )
                if matched is not None and auth.context.client_id != matched.group(1):
                    return Response(
                        '{"error":"receipt not available"}',
                        status="404 Not Found",
                        content_type="application/json; charset=utf-8",
                    )
        # Reject every future operator-initiated portal POST as well, not only
        # the currently defined /portal/<client>/requests route.
        if method == "POST" and path.startswith("/portal/") and auth.is_operator:
            return Response(
                "<h1>Client authorization required</h1>"
                "<p>Operators can review but cannot submit client requests.</p>",
                status="403 Forbidden",
            )
        return super()._dispatch(method, path, form, auth)

    def portal_submit_request(self, auth: AuthState, form: dict[str, str],
                              client_id: str) -> Response:
        # Do not use _portal_context here: it intentionally synthesizes an
        # operator-as-client context for read-only browsing.
        ctx = auth.context
        if (
            type(ctx) is not AccessContext
            or type(ctx.role) is not Role
            or ctx.role not in (Role.CLIENT_ADMIN, Role.CLIENT_MEMBER)
            or ctx.client_id != client_id
        ):
            return Response("<h1>Client authorization required</h1>",
                            status="403 Forbidden")
        return super().portal_submit_request(auth, form, client_id)

    def portal_request_inbox_api(
        self, auth: AuthState, form: dict[str, str], client_id: str
    ) -> Response:
        from .portal_receipt_api import request_inbox_json
        return request_inbox_json(self.store, auth, client_id)

    def portal_request_receipt_api(
        self, auth: AuthState, form: dict[str, str], client_id: str,
        request_id: str,
    ) -> Response:
        from .portal_receipt_api import request_receipt_json
        return request_receipt_json(self.store, auth, client_id, request_id)

    def portal_request_receipt(
        self, auth: AuthState, form: dict[str, str], client_id: str,
        request_id: str,
    ) -> Response:
        """Tenant-isolated, read-only status receipt; never an approval token."""
        context = self._portal_context(auth, client_id)
        request = self.store.get_assessment_request(context, request_id)
        if request.client_id != client_id:
            return Response("<h1>Forbidden</h1>", status="403 Forbidden")
        stage = request.status.value
        if stage in {"submitted", "under_review"}:
            progress = (
                '<span class="badge warn">Waiting for review</span>'
                '<p class="meta">Request recorded. An operator still needs to '
                'review it; approval and verified consent are separate.</p>'
            )
        elif stage == "approved":
            progress = (
                '<span class="badge warn">Request approved — execution locked</span>'
                '<p class="meta">The administrative request was approved. '
                'This is not an engagement grant or independently verified '
                'client consent and cannot activate target testing.</p>'
            )
        elif stage == "rejected":
            progress = (
                '<span class="badge lock">Request rejected</span>'
                '<p class="meta">The request was not approved. A new client '
                'request is required to propose a different scope.</p>'
            )
        else:
            progress = (
                '<span class="badge lock">Review status unavailable</span>'
                '<p class="meta">No authorization can be inferred from '
                'an unrecognized request state.</p>'
            )
        from .request_clarifications import (
            messages_for_request, render_thread_html, ClarificationDenied,
        )
        try:
            conversation = messages_for_request(
                self.store, auth, request_id, client_id=client_id
            )
            discussion = render_thread_html(
                conversation, auth, operator=auth.is_operator,
                action=(
                    "/operator/requests/" + request_id + "/clarifications"
                    if auth.is_operator else
                    "/portal/" + client_id + "/requests/" + request_id
                    + "/clarifications"
                ),
            )
        except (ClarificationDenied, KeyError, ValueError, TypeError):
            return Response(
                "<h1>Conversation unavailable</h1>",
                status="503 Service Unavailable",
            )
        body = (
            '<h1>Assessment request receipt</h1>'
            '<p class="sub">An acknowledgement of a recorded request, '
            'not a grant or a signed client authorization.</p>'
            '<div class="card"><span class="badge lock">Active testing locked</span>'
            + progress +
            '<p><strong>Request ID:</strong> ' + _e(request.request_id) +
            '<br><strong>Status:</strong> ' + _e(request.status.value) +
            '<br><strong>Requested assets:</strong> ' + _e(
                ", ".join(request.requested_assets)
            ) + '<br><strong>Requested mode:</strong> ' +
            _e(request.requested_mode.value) +
            '<br><strong>Risk level:</strong> ' + _e(int(request.requested_risk)) +
            '<br><strong>Submitted:</strong> ' + _e(request.created_at) +
            '<br><strong>Decision date:</strong> ' +
            _e(request.decided_at or "Not reviewed") +
            '</p><details><summary>Notes</summary><p>' +
            _e(request.notes or "—") + '</p></details></div>'
            '<div class="card"><strong>Authorization is separate</strong>'
            '<p class="meta">An approved request, if any, does not authorize '
            'target contact. Actual client consent, operator approval, '
            'scope/grant checks, live revocation and release approval '
            'are independent gates.</p></div>'
            '<p><a href="/portal/' + _e(client_id) +
            '">Back to client portal</a> · '
            '<a href="/api/v1/portal/' + _e(client_id) +
            '/requests/' + _e(request.request_id) +
            '">View machine-readable JSON status</a> · '
            '<a href="/api/v1/portal/' + _e(client_id)
            + '/requests/' + _e(request_id)
            + '/clarifications">View discussion JSON</a></p>'
            + discussion
        )
        return Response(_page("LightUp — Request receipt", "portal", body, auth,
                              portal_client=client_id))

    def portal(self, auth: AuthState, form: dict[str, str],
               client_id: str) -> Response:
        page = super().portal(auth, form, client_id)
        markup = page.body.decode("utf-8")
        # Show actionable links to durable request receipts without changing
        # the existing portal's source-owned cards or write handlers.
        view_context = self._portal_context(auth, client_id)
        requests = self.store.list_assessment_requests(view_context)
        from .request_clarifications import thread_states, ClarificationDenied
        try:
            clarification_badges = thread_states(
                self.store, auth,
                [item.request_id for item in requests[:30]], client_id=client_id,
            )
        except (ClarificationDenied, ValueError, TypeError):
            return Response(
                "<h1>Client inbox unavailable</h1>",
                status="503 Service Unavailable",
            )
        links = "".join(
            '<div class="card"><div class="row"><strong>'
            + _e(", ".join(asset[:100] for asset in request.requested_assets[:2])
                 or "Assessment request")
            + '</strong><span class="badge">'
            + _e(request.status.value) + '</span></div>'
            + '<p class="meta">Requested risk ' + _e(int(request.requested_risk))
            + ' · Submitted ' + _e(request.created_at)
            + '</p><p class="meta">Clarifications: '
            + _e(clarification_badges.get(request.request_id, "No question yet"))
            + '</p><a href="/portal/' + _e(client_id)
            + '/requests/' + _e(request.request_id)
            + '">View status and request details →</a></div>'
            for request in requests[:30]
        ) or '<p class="empty">No request receipts.</p>'
        if len(requests) > 30:
            links += '<p class="meta">Only the 30 newest receipts are shown.</p>'
        receipt_section = (
            '<div class="card"><strong>Assessment scope records</strong>'
            '<p class="meta">Review only what is recorded for this client; '
            'stored scope data is not permission to run tests.</p>'
            '<a href="/portal/' + _e(client_id)
            + '/scope-records">View recorded scopes and time windows →</a>'
            '</div>'
            '<h2>Request receipts</h2>'
            '<p class="meta"><a href="/api/v1/portal/' + _e(client_id)
            + '/requests">Machine-readable request history (JSON)</a></p>'
            + links
        )
        offset = markup.find(_PORTAL_FORM_HEADING)
        if offset < 0 or markup.find(_PORTAL_FORM_HEADING, offset + 1) >= 0:
            return Response("<h1>Portal view unavailable</h1>",
                            status="503 Service Unavailable")
        markup = markup[:offset] + receipt_section + markup[offset:]
        if not auth.is_operator:
            return Response(markup, status=page.status)
        start = markup.find(_PORTAL_FORM_HEADING)
        end = markup.find(_PORTAL_FORM_END, start) if start >= 0 else -1
        if start < 0 or end < 0 or markup.find(_PORTAL_FORM_HEADING, start + 1) != -1:
            # A changed parent portal template needs deliberate integration;
            # do not accidentally expose the operator's client-submit form.
            return Response("<h1>Portal view unavailable</h1>",
                            status="503 Service Unavailable")
        end += len(_PORTAL_FORM_END)
        return Response(markup[:start] + _OPERATOR_READONLY_NOTICE + markup[end:],
                        status=page.status)


def create_readonly_app(store: DomainStore,
                        security: WebSecurity | None = None) -> OperatorReadOnlyWebApp:
    """Explicit opt-in factory for existing authenticated WSGI sessions."""
    return OperatorReadOnlyWebApp(store, security)


def create_production_readonly_app(environ=None) -> OperatorReadOnlyWebApp:
    """Opt-in Gunicorn factory preserving the canonical production guards.

    Requires LIGHTUP_PUBLIC_ORIGIN (HTTPS), LIGHTUP_DB (absolute path) and
    the loopback trusted proxy, just like create_production_app.  A caller
    must explicitly select this factory; this module never deploys itself.
    """
    from .production import create_production_app

    configured = create_production_app(environ)
    return create_readonly_app(configured.store, configured.security)


def _loopback(value: str) -> str:
    try:
        if not ip_address(value).is_loopback:
            raise argparse.ArgumentTypeError("host must be a loopback IP address")
    except ValueError:
        raise argparse.ArgumentTypeError("host must be a loopback IP address") from None
    return value


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("port must be an integer") from None
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be within 1..65535")
    return port


def main(argv: list[str] | None = None) -> int:
    """Launch a guarded local web UI; no scanning/active adapters are started."""
    parser = argparse.ArgumentParser(prog="lightup-operator-readonly")
    parser.add_argument("--db", default="lightup.db", help="domain SQLite database")
    parser.add_argument("--host", type=_loopback, default="127.0.0.1")
    parser.add_argument("--port", type=_port, default=8767)
    args = parser.parse_args(argv)
    app = create_readonly_app(DomainStore(args.db))
    with make_server(args.host, args.port, app) as server:
        print(f"LightUp read-only operator portal: http://{args.host}:{server.server_port}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
