"""Explicit, unmounted fail-closed privacy wrapper for LightUp's stdlib WSGI shell.

This only supports the current eager LightUpWebApp response contract. It is
deliberately NOT installed in the default create_app(), production CLI or ingress.
It does not perform authorization: the wrapped app still owns all guards.
"""
from __future__ import annotations

from typing import Callable

from .app import LightUpWebApp

_OPAQUE_HTML = b"<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Request failed</title><body><h1>Request failed</h1></body></html>"


class OpaqueErrorWSGI:
    """Deny transmission of raw domain exception details in 400 responses.

    LightUpWebApp invokes start_response synchronously and returns an eager
    one-chunk response; this wrapper intentionally refuses arbitrary WSGI apps
    whose streaming/write() semantics may differ. Route, CSRF, session and
    tenant admission remain entirely in the original app.
    """

    def __init__(self, app: LightUpWebApp):
        if type(app) is not LightUpWebApp:
            raise TypeError("opaque error wrapper requires exact LightUpWebApp")
        self._app = app

    def __call__(self, environ, start_response: Callable):
        captured = {}

        def capture(status, headers, exc_info=None):
            if captured:
                raise RuntimeError("unexpected repeated WSGI response start")
            if exc_info is not None:
                raise RuntimeError("unexpected WSGI error-retry start")
            captured["status"] = status
            captured["headers"] = list(headers)

            def unsupported_write(_chunk):
                raise RuntimeError("eager LightUpWebApp must not use WSGI write()")
            return unsupported_write

        chunks = self._app(environ, capture)
        if "status" not in captured:
            raise RuntimeError("LightUpWebApp did not start its response")

        status = captured["status"]
        headers = captured["headers"]
        if status == "400 Bad Request":
            # The validated app yields a one-chunk in-memory response. Do NOT
            # forward the original body or derive the replacement from it.
            try:
                for _ in chunks:
                    pass
            finally:
                close = getattr(chunks, "close", None)
                if callable(close):
                    close()
            headers = [
                (key, value) for key, value in headers
                if key.lower() not in {"content-length", "content-type", "etag"}
            ]
            headers.extend((
                ("Content-Type", "text/html; charset=utf-8"),
                ("Content-Length", str(len(_OPAQUE_HTML))),
            ))
            start_response(status, headers)
            return [_OPAQUE_HTML]

        start_response(status, headers)
        return chunks
