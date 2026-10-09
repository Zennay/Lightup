"""Optional pre-auth WSGI root-mount admission for the LightUp web shell.

The current app routes absolute root paths ("/clients", "/login", ...). A
reverse proxy or WSGI host that supplies a nonempty SCRIPT_NAME introduces a
second, unreviewed path namespace. Refuse it before body/session processing.

This wrapper is opt-in. It does not replace installed proxy normalization,
route/method/cookie guards, or authorization checks in the wrapped app.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping


class RootMountGuard:
    """Accept only a root-mounted WSGI application with canonical metadata."""

    def __init__(self, app: Callable, *, production: bool):
        # Configuration must be explicit: an accidental development default
        # would omit HSTS from production's pre-auth denial responses.
        if type(production) is not bool:
            raise TypeError("production must be a boolean")
        app_security = getattr(app, "security", None)
        configured_production = getattr(app_security, "production", None)
        if configured_production is not None:
            if type(configured_production) is not bool or configured_production != production:
                raise ValueError("root guard production mode must match the wrapped app")
        self.app = app
        self.production = production

    def __call__(self, environ: Mapping, start_response: Callable) -> Iterable[bytes]:
        # WSGI permits an absent SCRIPT_NAME as shorthand for the empty root
        # mount; only an *exact* empty str is otherwise canonical here.
        mount = environ.get("SCRIPT_NAME", "")
        if type(mount) is not str or mount != "":
            body = b"<h1>Bad request</h1>"
            headers = [
                ("Content-Type", "text/html; charset=utf-8"),
                ("Content-Length", str(len(body))),
                ("Cache-Control", "no-store"),
                ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"),
                ("X-Frame-Options", "DENY"),
                ("X-Content-Type-Options", "nosniff"),
                ("Referrer-Policy", "no-referrer"),
            ]
            if self.production:
                headers.append(("Strict-Transport-Security", "max-age=31536000"))
            start_response("400 Bad Request", headers)
            return [body]
        return self.app(environ, start_response)
