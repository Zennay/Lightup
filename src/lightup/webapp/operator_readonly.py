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
from ipaddress import ip_address
from wsgiref.simple_server import make_server

from ..domain import AccessContext, DomainStore, Role
from .app import AuthState, LightUpWebApp, Response
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
    """Drop-in WSGI variant that enforces client-origin portal writes.

    Defense in depth: guard portal POSTs at the dispatcher before calling any
    handler, then require an actual tenant-bound client AccessContext again in
    the write handler.  Never construct a synthetic client identity for writes.
    """

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
            or ctx.role not in (Role.CLIENT_ADMIN, Role.CLIENT_MEMBER)
            or ctx.client_id != client_id
        ):
            return Response("<h1>Client authorization required</h1>",
                            status="403 Forbidden")
        return super().portal_submit_request(auth, form, client_id)

    def portal(self, auth: AuthState, form: dict[str, str],
               client_id: str) -> Response:
        page = super().portal(auth, form, client_id)
        if not auth.is_operator:
            return page
        markup = page.body.decode("utf-8")
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
