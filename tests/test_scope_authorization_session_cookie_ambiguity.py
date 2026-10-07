from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lightup.domain import DomainStore, Role
from lightup.webapp import create_app


class SessionCookieAmbiguityTests(unittest.TestCase):
    """Acceptance contract for unambiguous session identity before authorization."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.app = create_app(self.store)

        self.operator_user = self.store.bootstrap_operator(
            "operator@lightup.test", "Operator", "operator-password"
        )
        self.operator = self.store.context_for_user(self.operator_user.user_id)
        self.client = self.store.create_client(self.operator, "Acme BV")
        self.client_user = self.store.create_user(
            self.operator,
            "admin@acme.test",
            "Acme Admin",
            Role.CLIENT_ADMIN,
            self.client.client_id,
        )
        self.store.set_password(
            self.operator, self.client_user.user_id, "client-admin-password"
        )

        self.operator_token, _ = self.store.create_session(self.operator_user.user_id)
        self.client_token, _ = self.store.create_session(self.client_user.user_id)

    def tearDown(self):
        self.tmp.cleanup()

    def request(self, path: str, cookie: str | None):
        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": path,
            "CONTENT_LENGTH": "0",
            "CONTENT_TYPE": "application/x-www-form-urlencoded",
            "wsgi.input": io.BytesIO(b""),
        }
        if cookie is not None:
            environ["HTTP_COOKIE"] = cookie

        captured: dict[str, object] = {}

        def start_response(status, headers):
            captured["status"] = status
            captured["headers"] = headers

        body = b"".join(self.app(environ, start_response)).decode("utf-8")
        return str(captured["status"]), dict(captured["headers"]), body

    def test_single_session_cookie_keeps_existing_operator_authority(self):
        status, _, body = self.request(
            "/",
            f"lightup_session={self.operator_token}",
        )

        self.assertEqual(status, "200 OK")
        self.assertIn("Active testing", body)

    def test_unrelated_cookies_do_not_make_one_session_cookie_ambiguous(self):
        status, _, _ = self.request(
            "/",
            f"theme=dark; lightup_session={self.operator_token}; locale=en",
        )

        self.assertEqual(status, "200 OK")

    def test_session_cookie_name_matching_is_exact(self):
        status, _, _ = self.request(
            "/",
            (
                f"lightup_session_backup={self.client_token}; "
                f"xlightup_session={self.client_token}; "
                f"lightup_session={self.operator_token}"
            ),
        )

        self.assertEqual(status, "200 OK")

    def test_two_different_session_cookies_fail_before_session_resolution(self):
        for raw_cookie in (
            f"lightup_session={self.client_token}; lightup_session={self.operator_token}",
            f"lightup_session={self.operator_token}; lightup_session={self.client_token}",
            f"lightup_session={self.client_token}, lightup_session={self.operator_token}",
            f"lightup_session={self.operator_token}, lightup_session={self.client_token}",
        ):
            with self.subTest(raw_cookie=raw_cookie):
                with patch.object(
                    self.store,
                    "session_context",
                    wraps=self.store.session_context,
                ) as resolve:
                    status, headers, _ = self.request("/", raw_cookie)

                resolve.assert_not_called()
                self.assertEqual(status, "303 See Other")
                self.assertEqual(headers["Location"], "/login")

        self.assertIsNotNone(self.store.session_context(self.operator_token))
        self.assertIsNotNone(self.store.session_context(self.client_token))

    def test_duplicate_identical_session_cookie_is_still_rejected_as_ambiguous(self):
        raw_cookie = (
            f"lightup_session={self.operator_token}; "
            f"lightup_session={self.operator_token}"
        )

        with patch.object(
            self.store,
            "session_context",
            wraps=self.store.session_context,
        ) as resolve:
            status, headers, _ = self.request("/", raw_cookie)

        resolve.assert_not_called()
        self.assertEqual(status, "303 See Other")
        self.assertEqual(headers["Location"], "/login")
        self.assertIsNotNone(self.store.session_context(self.operator_token))


if __name__ == "__main__":
    unittest.main()
