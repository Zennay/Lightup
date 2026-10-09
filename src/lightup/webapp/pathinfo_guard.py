"""Canonical WSGI path-identity boundary for an application entrypoint.

This module is intentionally not wired into the existing app owner source.
The WSGI owner must integrate it at the outer entrypoint, before reads,
session resolution or route dispatch. It is not an authorization grant.
"""
from __future__ import annotations

from typing import Callable, Iterable, Mapping

MAX_PATH_INFO_CHARS = 4096
_ERROR_BODY = b"Invalid request path\n"
_ERROR_HEADERS = (
    ("Content-Type", "text/plain; charset=utf-8"),
    ("Content-Length", str(len(_ERROR_BODY))),
    ("Cache-Control", "no-store"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("X-Frame-Options", "DENY"),
    ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"),
)


class InvalidPathInfo(ValueError):
    """WSGI path metadata cannot safely select a route."""


def canonical_path_info(environ: Mapping[str, object]) -> str:
    """Inspect trusted WSGI metadata with no conversion, decoding or I/O.

    WSGI supplies PATH_INFO as a text string; a zero-length path denotes the
    application root. Strings with control characters, particularly terminal
    LF accepted by Python regex '$', must not acquire a route identity.
    """
    sentinel = object()
    raw = environ.get("PATH_INFO", sentinel)
    if type(raw) is not str:
        raise InvalidPathInfo("PATH_INFO must be a built-in string")
    if len(raw) > MAX_PATH_INFO_CHARS:
        raise InvalidPathInfo("PATH_INFO is too long")
    if raw == "":
        return "/"
    if not raw.startswith("/"):
        raise InvalidPathInfo("PATH_INFO must be absolute")
    if any(ord(char) < 32 or ord(char) == 127 for char in raw):
        raise InvalidPathInfo("PATH_INFO contains a control character")
    return raw


class CanonicalPathInfoGuard:
    """Wrap a WSGI app; reject path ambiguity before delegating downstream.

    Rejecting metadata cannot call or read the wrapped app. This can be
    composed outside the LightUpWebApp when the web source owner integrates it.
    """

    def __init__(self, app: Callable, *, production: bool = False):
        if type(production) is not bool:
            raise TypeError("production must be a built-in boolean")
        self._app = app
        self._production = production

    def __call__(self, environ, start_response) -> Iterable[bytes]:
        try:
            canonical_path_info(environ)
        except InvalidPathInfo:
            headers = list(_ERROR_HEADERS)
            if self._production:
                headers.append(("Strict-Transport-Security", "max-age=31536000"))
            start_response("400 Bad Request", headers)
            return [_ERROR_BODY]
        return self._app(environ, start_response)
