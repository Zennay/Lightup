"""Opt-in, pre-auth WSGI method-token boundary for the LightUp GET/POST UI.

This module deliberately does not alter the live app entrypoint. Production wiring
requires app/ingress owner review and both exact-head CI gates before deployment.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping

_ALLOWED = frozenset({"GET", "POST"})
_MAX_METHOD_BYTES = 32
_TOKEN = frozenset("!#$%&'*+-.^_|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" + chr(96))
_HSTS = ("Strict-Transport-Security", "max-age=31536000")


class MethodRejected(ValueError):
    """A WSGI method failed canonical admission without granting route authority."""

    def __init__(self, status: str):
        super().__init__("unsupported or malformed request method")
        self.status = status


def canonical_request_method(environ: Mapping[str, object]) -> str:
    """Admit only built-in, exact GET or POST WSGI tokens (never casefold).

    Unknown well-formed HTTP method tokens are 405, malformed or polymorphic
    environ values are 400. Missing method is *not* an implicit GET.
    """
    value = environ.get("REQUEST_METHOD")
    if type(value) is not str or not value or len(value) > _MAX_METHOD_BYTES:
        raise MethodRejected("400 Bad Request")
    if any(char not in _TOKEN for char in value):
        raise MethodRejected("400 Bad Request")
    if value not in _ALLOWED:
        raise MethodRejected("405 Method Not Allowed")
    return value


class CanonicalMethodGuard:
    """Reject invalid WSGI methods before the wrapped app reads form/session data."""

    def __init__(self, app: Callable, *, production: bool = False):
        if type(production) is not bool:
            raise ValueError("production must be an exact boolean")
        self.app = app
        self.production = production

    def __call__(self, environ: Mapping[str, object], start_response: Callable) -> Iterable[bytes]:
        try:
            canonical_request_method(environ)
        except MethodRejected as exc:
            body = b"Request rejected"
            headers = [
                ("Content-Type", "text/plain; charset=utf-8"),
                ("Content-Length", str(len(body))),
                ("Cache-Control", "no-store"),
                ("X-Content-Type-Options", "nosniff"),
                ("X-Frame-Options", "DENY"),
                ("Referrer-Policy", "no-referrer"),
                ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"),
            ]
            if exc.status.startswith("405"):
                headers.append(("Allow", "GET, POST"))
            if self.production:
                headers.append(_HSTS)
            start_response(exc.status, headers)
            return [body]
        return self.app(environ, start_response)
