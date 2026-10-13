"""Explicit opt-in fixed-header privacy seal around an opaque LightUp WSGI app.

This is a synthetic PLAN/LAB-only adapter: it is not mounted by the existing
webapp, CLI, standard production factory or installed ingress. It has no
authority to issue grants or alter routing, sessions, roles, CSRF or target I/O.
"""
from __future__ import annotations

from typing import Callable

from .app import LightUpWebApp
from .opaque_error_wsgi_optin import OpaqueErrorWSGI
from .production_opaque_optin import create_opaque_production_app
from .security import WebSecurity


# These are literal policy-owned headers, NOT copies of upstream header values.
# The fixed error document has no styles, JavaScript, navigation or form.
_PRIVATE_400 = (
    b'<!doctype html><html lang="en"><meta charset="utf-8">'
    b'<title>Request failed</title><body><h1>Request failed</h1></body></html>'
)
_PRIVATE_400_HEADERS = (
    ("Content-Type", "text/html; charset=utf-8"),
    ("Content-Length", str(len(_PRIVATE_400))),
    ("Cache-Control", "no-store"),
    ("Pragma", "no-cache"),
    ("Referrer-Policy", "no-referrer"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Content-Security-Policy",
     "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"),
    ("Strict-Transport-Security", "max-age=31536000"),
)


class FixedHeaderOpaqueProductionWSGI:
    """Replace a 400's body AND headers after upstream checks have finished.

    Require the exact original eager production LightUpWebApp inside the
    already-opted-in OpaqueErrorWSGI. Other statuses are passed through without
    touching the session or authorization behavior. No arbitrary WSGI write()
    or repeated start_response() support is claimed.
    """

    def __init__(self, app: OpaqueErrorWSGI):
        if type(app) is not OpaqueErrorWSGI:
            raise TypeError("expected exact OpaqueErrorWSGI")
        inner = app._app
        if (type(inner) is not LightUpWebApp or
                type(inner.security) is not WebSecurity or
                not inner.security.production):
            raise ValueError("requires genuine production-configured LightUpWebApp")
        self._app = app

    def __call__(self, environ, start_response: Callable):
        captured: dict[str, object] = {}

        def capture(status, headers, exc_info=None):
            if captured or exc_info is not None:
                raise RuntimeError("unsupported repeated/error WSGI response")
            captured["status"] = status
            captured["headers"] = list(headers)

            def no_write(_):
                raise RuntimeError("eager WSGI write() unsupported")
            return no_write

        chunks = self._app(environ, capture)
        if "status" not in captured:
            raise RuntimeError("response missing start_response")
        status = captured["status"]
        if status != "400 Bad Request":
            start_response(status, captured["headers"])
            return chunks

        # Do not reuse an upstream body, Content-Length, CSP, HSTS, cookies,
        # redirect, cache policy, diagnostics or arbitrary extension headers.
        try:
            for _ in chunks:
                pass
        finally:
            close = getattr(chunks, "close", None)
            if callable(close):
                close()

        start_response("400 Bad Request", list(_PRIVATE_400_HEADERS))
        return [_PRIVATE_400]


def create_fixed_header_opaque_production_app(environ=None):
    """Explicit safe-composition entrypoint, never used by default factories."""
    return FixedHeaderOpaqueProductionWSGI(create_opaque_production_app(environ))
