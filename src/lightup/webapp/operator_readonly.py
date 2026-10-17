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
from .app import AuthState, LightUpWebApp, Response, _e, _page
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
        self.routes.append((
            "GET", re.compile(r"^/authorization-desk$"),
            self.authorization_desk, "operator",
        ))
        self.routes.append((
            "GET", re.compile(r"^/authorization-desk/clients/(?P<client_id>[\\w-]+)$"),
            self.authorization_client_desk, "operator",
        ))
        self.routes.append((
            "GET", re.compile(
                r"^/portal/(?P<client_id>[\\w-]+)/requests/(?P<request_id>[\\w-]+)$"
            ),
            self.portal_request_receipt, "portal",
        ))
        self.routes.append((
            "GET", re.compile(
                r"^/api/v1/portal/(?P<client_id>[\\w-]+)/requests/"
                r"(?P<request_id>[\\w-]+)$"
            ),
            self.portal_request_receipt_api, "portal",
        ))

    def authorization_desk(self, auth: AuthState, form: dict[str, str]) -> Response:
        from .authorization_desk import render_authorization_desk
        return render_authorization_desk(self.store, auth)

    def authorization_client_desk(
        self, auth: AuthState, form: dict[str, str], client_id: str
    ) -> Response:
        from .authorization_desk import render_authorization_desk
        return render_authorization_desk(self.store, auth, client_id=client_id)

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

    def _dispatch(self, method: str, path: str, form: dict[str, str],
                  auth: AuthState) -> Response:
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
        body = (
            '<h1>Assessment request receipt</h1>'
            '<p class="sub">An acknowledgement of a recorded request, '
            'not a grant or a signed client authorization.</p>'
            '<div class="card"><span class="badge warn">Active testing locked</span>'
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
            '">View machine-readable JSON status</a></p>'
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
        links = "".join(
            '<div class="card"><a href="/portal/' + _e(client_id) +
            '/requests/' + _e(request.request_id) + '">View request ' +
            _e(request.request_id) + '</a><br><span class="meta">Status: ' +
            _e(request.status.value) + '</span></div>'
            for request in requests[:30]
        ) or '<p class="empty">No request receipts.</p>'
        if len(requests) > 30:
            links += '<p class="meta">Only the 30 newest receipts are shown.</p>'
        receipt_section = '<h2>Request receipts</h2>' + links
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
