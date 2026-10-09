"""Optional pre-auth WSGI Cookie envelope gate for the LightUp session boundary.

This module is intentionally *not* the deployed WSGI entry point. The app and
production-factory owners must explicitly integrate it after review.
"""
from __future__ import annotations

import re
from typing import Callable

from .app import SESSION_COOKIE

# RFC-style token subset; deliberately reject unusual/ambiguous cookie names.
_NAME = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_|~-]+$")
_MISSING = object()
_MAX_COOKIE_BYTES = 8192


def validate_cookie_envelope(environ: dict) -> None:
    """Reject ambiguous session credentials before session lookup or body reads.

    Only an unambiguous semicolon-separated cookie-pair representation is
    accepted. This is conservative: quoted, backslash-escaped or comma-joined
    cookie headers are rejected instead of speculatively reparsed. A proxy must
    also reject multiple Cookie header fields at the wire boundary, since WSGI
    does not preserve how HTTP fields were originally combined.
    """
    raw = environ.get("HTTP_COOKIE", _MISSING)
    if raw is _MISSING:
        return
    if type(raw) is not str:
        raise ValueError("noncanonical cookie envelope")
    try:
        size = len(raw.encode("latin-1"))
    except UnicodeEncodeError as exc:
        raise ValueError("noncanonical cookie characters") from exc
    if size > _MAX_COOKIE_BYTES:
        raise ValueError("oversized cookie envelope")
    if any(ord(char) < 32 or ord(char) == 127 for char in raw):
        raise ValueError("control character in cookie envelope")
    if any(char in raw for char in ('"', "\\", ",")):
        raise ValueError("ambiguous cookie envelope")
    if not raw:
        return

    session_seen = False
    for item in raw.split(";"):
        piece = item.strip(" ")
        if not piece:
            raise ValueError("empty cookie pair")
        name, equals, value = piece.partition("=")
        if not equals or not _NAME.fullmatch(name):
            raise ValueError("invalid cookie pair")
        # Unquoted cookie-octet cannot contain SP. SimpleCookie may tokenize
        # whitespace-delimited pairs differently than a proxy or this loop.
        if " " in value:
            raise ValueError("ambiguous cookie value")
        if name == SESSION_COOKIE:
            if session_seen:
                raise ValueError("duplicate LightUp session credential")
            session_seen = True


class CookieEnvelopeGuard:
    """WSGI wrapper that denies ambiguous cookies before the wrapped app runs."""

    def __init__(self, app: Callable, *, production: bool = False):
        if type(production) is not bool:
            raise ValueError("production flag must be an exact boolean")
        self.app = app
        self.production = production

    def __call__(self, environ, start_response):
        try:
            validate_cookie_envelope(environ)
        except (ValueError, TypeError, AttributeError):
            body = b"Invalid request"
            headers = [
                ("Content-Type", "text/plain; charset=utf-8"),
                ("Content-Length", str(len(body))),
                ("Cache-Control", "no-store"),
                ("X-Content-Type-Options", "nosniff"),
                ("X-Frame-Options", "DENY"),
                ("Content-Security-Policy",
                 "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"),
                ("Referrer-Policy", "no-referrer"),
            ]
            if self.production:
                headers.append(("Strict-Transport-Security", "max-age=31536000"))
            start_response("400 Bad Request", headers)
            return [body]
        return self.app(environ, start_response)


def create_cookie_guarded_production_app(environ=None):
    """Opt-in production factory; does not change the deployed Gunicorn target."""
    from .production import create_production_app

    return CookieEnvelopeGuard(create_production_app(environ), production=True)
