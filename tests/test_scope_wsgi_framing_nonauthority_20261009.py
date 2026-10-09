"""Offline real-WSGI regression: request framing cannot mint scope authority.

This suite exercises the production LightUpWebApp/DomainStore with temporary SQLite.
It never binds a socket, issues an authorization grant, or contacts any target.
"""
from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlencode

from lightup.domain import DomainStore
from lightup.webapp import create_app
from lightup.webapp.security import WebSecurity


class PoisonInput:
    """Reject before session lookup and before touching invalidly framed data."""

    def read(self, *args, **kwargs):
        raise AssertionError("invalid request framing reached wsgi.input")


class WSGIFramingAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tempdir.name) / "lightup.db")
        operator = self.store.bootstrap_operator(
            "framing@lightup.test", "Framing Operator", "operator-password"
        )
        self.ctx = self.store.context_for_user(operator.user_id)
        self.token, self.csrf = self.store.create_session(operator.user_id)

    def tearDown(self):
        self.tempdir.cleanup()

    def request(self, production, *, body=b"", length=None, extra=None, stream=None):
        app = create_app(
            self.store,
            security=(WebSecurity(public_origin="https://lightup.example.test")
                      if production else WebSecurity()),
        )
        environ = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": "/clients",
            "CONTENT_LENGTH": str(len(body)) if length is None else length,
            "CONTENT_TYPE": "application/x-www-form-urlencoded",
            "HTTP_COOKIE": f"lightup_session={self.token}",
            "HTTP_HOST": "lightup.example.test" if production else "localhost",
            "HTTP_ORIGIN": ("https://lightup.example.test"
                            if production else "http://localhost"),
            "wsgi.input": stream if stream is not None else io.BytesIO(body),
        }
        if production:
            environ.update({
                "REMOTE_ADDR": "127.0.0.1",
                "HTTP_X_FORWARDED_PROTO": "https",
            })
        if extra:
            environ.update(extra)
        captured = {}

        def start_response(status, headers):
            captured["status"] = status
            captured["headers"] = dict(headers)

        payload = b"".join(app(environ, start_response))
        return captured["status"], captured["headers"], payload

    def assert_invalid_framing(self, production, label, **kwargs):
        before = len(self.store.list_clients(self.ctx))
        with self.subTest(production=production, case=label):
            with patch.object(self.store, "session_context") as session_lookup:
                status, headers, _ = self.request(
                    production, stream=PoisonInput(), **kwargs
                )
                session_lookup.assert_not_called()
            self.assertTrue(status.startswith(("400 ", "413 ")), status)
            self.assertEqual(headers["Cache-Control"], "no-store")
            self.assertIsNotNone(self.store.session_context(self.token))
            self.assertEqual(len(self.store.list_clients(self.ctx)), before)

    def test_invalid_content_length_is_denied_before_auth_and_io(self):
        # WSGI CONTENT_LENGTH is the server's parsed framing, not a client
        # field. Refuse ambiguous/noncanonical values even with valid CSRF.
        cases = (
            ("missing", ""),
            ("negative", "-1"),
            ("prefixed-plus", "+10"),
            ("leading-space", " 10"),
            ("trailing-space", "10 "),
            ("fraction", "10.0"),
            ("unicode-digit", "\uff11"),
            ("nonstring-integer", 10),
            ("nonstring-boolean", True),
            ("excess", "999999999999"),
            ("too-long-token", "0" * 11),
        )
        for production in (False, True):
            for name, length in cases:
                self.assert_invalid_framing(
                    production, name, length=length,
                )

    def test_transfer_encoding_is_never_a_form_authorization_shortcut(self):
        for production in (False, True):
            for value in ("chunked", "identity", "gzip, chunked", "CHUNKED"):
                self.assert_invalid_framing(
                    production, f"transfer:{value}",
                    length="18", extra={"HTTP_TRANSFER_ENCODING": value},
                )

    def test_conflicting_client_length_hint_cannot_override_wsgi_length(self):
        # The synthetic client hint is deliberately contradictory. Only the
        # canonical WSGI CONTENT_LENGTH can bound body parsing.
        body = urlencode({"csrf": self.csrf, "name": "A"}).encode()
        for production in (False, True):
            with self.subTest(production=production):
                # Valid canonical length admits a normal, operator-authorized
                # request even when an untrusted HTTP_ prefix claims zero.
                name = f"Framing-allowed-{'prod' if production else 'dev'}"
                raw = urlencode({"csrf": self.csrf, "name": name}).encode()
                status, headers, _ = self.request(
                    production, body=raw,
                    extra={"HTTP_CONTENT_LENGTH": "0"},
                )
                self.assertEqual(status, "303 See Other")
                self.assertEqual(headers["Location"], "/clients")
                self.assertTrue(
                    any(c.name == name for c in self.store.list_clients(self.ctx))
                )
                # The forged client hint must not fix a *bad* WSGI framing.
                self.assert_invalid_framing(
                    production, "forged-http-length",
                    length="+10", extra={"HTTP_CONTENT_LENGTH": str(len(body))},
                )

    def test_valid_framing_never_bypasses_role_or_csrf(self):
        for production in (False, True):
            with self.subTest(production=production):
                before = len(self.store.list_clients(self.ctx))
                body = urlencode({"name": "Unapproved"}).encode()
                status, _, _ = self.request(production, body=body)
                self.assertEqual(status, "403 Forbidden")
                self.assertEqual(len(self.store.list_clients(self.ctx)), before)
                self.assertIsNotNone(self.store.session_context(self.token))


if __name__ == "__main__":
    unittest.main()
