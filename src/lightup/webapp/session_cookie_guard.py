"""Optional pre-auth WSGI Cookie envelope gate for the LightUp session boundary.

This module is intentionally *not* the deployed WSGI entry point. The app and
production-factory owners must explicitly integrate it after review.
"""
from __future__ import annotations

import re
from http.cookies import CookieError, SimpleCookie
from typing import Callable

from .app import SESSION_COOKIE

# RFC-style token subset; deliberately reject unusual/ambiguous cookie names.
_NAME = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_|~-]+$")
# DomainStore.create_session uses secrets.token_urlsafe(32): exactly 43 base64url
# characters, unpadded. This checks representation, not authentication.
# For 32 bytes, the 43rd base64url symbol has two zero padding bits.
_SESSION_TOKEN = re.compile(r"[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]\Z")
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
    session_value = None
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
            # Reject padding, encoded/folded values and noncanonical lengths
            # before any store.session_context lookup. Only the store can
            # decide whether a *well-formed* token authenticates.
            if not _SESSION_TOKEN.fullmatch(value):
                raise ValueError("noncanonical LightUp session token")
            session_seen = True
            session_value = value

    # A cookie may look syntactically harmless but be reinterpreted by the
    # application's SimpleCookie implementation. Demand exact agreement for
    # the only credential used by LightUp; never accept a parser-dependent
    # alternative identity.
    if session_seen:
        jar = SimpleCookie()
        try:
            jar.load(raw)
        except (CookieError, ValueError, TypeError) as exc:
            raise ValueError("session cookie parser disagreement") from exc
        morsel = jar.get(SESSION_COOKIE)
        if morsel is None or morsel.value != session_value:
            raise ValueError("session cookie parser disagreement")


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
