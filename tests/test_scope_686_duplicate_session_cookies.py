"""Regression contract for duplicate LightUp session cookie admission (issue #686).

Owns tests only: production web authentication is owned by PR #182.
All state uses a disposable SQLite DB, synthetic identities and sessions.
Source RED cases deliberately remain expectedFailure until the source owner
implements fail-closed admission ahead of DomainStore.session_context().
"""
from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lightup.domain import DomainStore, Role
from lightup.webapp import create_app


class DuplicateSessionCookieAcceptance(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = DomainStore(Path(self.temp.name) / "domain.db")
        self.app = create_app(self.store)
        operator = self.store.bootstrap_operator(
            "scope686-op@lightup.test", "Fictional operator", "fictional-password"
        )
        op_context = self.store.context_for_user(operator.user_id)
        client = self.store.create_client(op_context, "Synthetic tenant")
        member = self.store.create_user(
            op_context, "scope686-client@lightup.test", "Fictional client",
            Role.CLIENT_ADMIN, client.client_id
        )
        self.operator_token, self.operator_csrf = self.store.create_session(operator.user_id)
        self.client_token, self.client_csrf = self.store.create_session(member.user_id)
        self.client_id = client.client_id

    def _auth(self, header: str):
        return self.app._authenticate({"HTTP_COOKIE": header})

    def _wsgi(self, header: str, *, path: str = "/"):
        state = {}
        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": path,
            "CONTENT_LENGTH": "0",
            "wsgi.input": io.BytesIO(b""),
            "HTTP_COOKIE": header,
        }
        chunks = self.app(environ, lambda status, headers: state.update(
            status=status, headers=dict(headers)))
        return state["status"], state["headers"], b"".join(chunks)

    def _assert_ambiguous_denied_prelookup(self, header: str) -> None:
        # Both sessions must remain valid after a failed request; do NOT
        # conflate admission denial with a revoke/logout action.
        with patch.object(self.store, "session_context", wraps=self.store.session_context) as lookup:
            auth = self._auth(header)
            lookup.assert_not_called()
        self.assertFalse(auth.signed_in)
        self.assertIsNotNone(self.store.session_context(self.operator_token))
        self.assertIsNotNone(self.store.session_context(self.client_token))

    def test_no_session_cookie_is_anonymous_without_lookup(self):
        for header in ("", "theme=dark", "lightup_session_extra=not-a-session"):
            with self.subTest(header=header):
                with patch.object(self.store, "session_context") as lookup:
                    self.assertFalse(self._auth(header).signed_in)
                    lookup.assert_not_called()

    def test_single_operator_session_remains_authorized(self):
        for header in (
            f"lightup_session={self.operator_token}",
            f"theme=dark; lightup_session={self.operator_token}; lang=nl",
        ):
            with self.subTest(extra_cookies=("theme" in header)):
                auth = self._auth(header)
                self.assertTrue(auth.signed_in)
                self.assertTrue(auth.is_operator)
                self.assertEqual(auth.csrf, self.operator_csrf)

    def test_single_client_session_retains_tenant(self):
        header = f"pref=compact; lightup_session={self.client_token}"
        auth = self._auth(header)
        self.assertTrue(auth.signed_in)
        self.assertFalse(auth.is_operator)
        self.assertEqual(auth.context.client_id, self.client_id)
        self.assertEqual(auth.csrf, self.client_csrf)

    def test_invalid_single_session_stays_anonymous(self):
        auth = self._auth("theme=dark; lightup_session=not-a-real-session")
        self.assertFalse(auth.signed_in)

    def test_wsgi_operator_single_cookie_control(self):
        status, _, body = self._wsgi(f"lightup_session={self.operator_token}")
        self.assertEqual(status, "200 OK")
        self.assertIn(b"Active testing", body)

    def test_wsgi_client_operator_isolation_control(self):
        status, headers, _ = self._wsgi(
            f"lightup_session={self.client_token}")
        self.assertEqual(status, "403 Forbidden")
        self.assertNotIn("Set-Cookie", headers)

    @unittest.expectedFailure
    def test_red_duplicate_identical_operator_token_prelookup(self):
        token = self.operator_token
        self._assert_ambiguous_denied_prelookup(
            f"lightup_session={token}; lightup_session={token}")

    @unittest.expectedFailure
    def test_red_duplicate_operator_then_client_prelookup(self):
        self._assert_ambiguous_denied_prelookup(
            f"lightup_session={self.operator_token}; lightup_session={self.client_token}")

    @unittest.expectedFailure
    def test_red_duplicate_client_then_operator_prelookup(self):
        self._assert_ambiguous_denied_prelookup(
            f"lightup_session={self.client_token}; lightup_session={self.operator_token}")

    @unittest.expectedFailure
    def test_red_duplicate_surrounded_by_unrelated_cookies(self):
        self._assert_ambiguous_denied_prelookup(
            "theme=dark; lightup_session=" + self.operator_token
            + "; lang=nl; lightup_session=" + self.client_token + "; end=1")

    @unittest.expectedFailure
    def test_red_duplicate_valid_after_invalid_prelookup(self):
        self._assert_ambiguous_denied_prelookup(
            f"lightup_session=invalid; lightup_session={self.operator_token}")

    @unittest.expectedFailure
    def test_red_wsgi_duplicate_must_not_gain_operator_access(self):
        status, headers, _ = self._wsgi(
            f"lightup_session={self.client_token}; lightup_session={self.operator_token}")
        self.assertEqual(status, "303 See Other")
        self.assertEqual(headers.get("Location"), "/login")
        self.assertNotIn("Set-Cookie", headers)
        self.assertIsNotNone(self.store.session_context(self.operator_token))
        self.assertIsNotNone(self.store.session_context(self.client_token))


if __name__ == "__main__":
    unittest.main()
