"""Real offline WSGI acceptance: Accept-Language has zero authorization authority.

Issue #1112. Independent of the pure-predicate reference PR #1113.
No external requests or live targets: the WSGI app and database run in-process.
"""
from __future__ import annotations

import io
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lightup.domain import DomainStore, Role
from lightup.webapp import create_app


LANGUAGES = (
    None,
    "en-US,en;q=0.9",
    "nl-NL,nl;q=0.9",
    "fr-FR;q=1.0,*;q=0",
    "*",
    "",
    "en-US, nl-NL;q=0.3, *;q=0.1",
    "admin",
    "../portal/other",
    "en\r\nCookie: lightup_session=forged",
    "en\r\nX-Forwarded-User: operator",
    "en\x00operator",
    "e" * 8192,
)


class AcceptLanguageRealWSGINonAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = DomainStore(Path(self.temp.name) / "lightup.db")
        self.app = create_app(self.store)
        self.operator_user = self.store.bootstrap_operator(
            "operator@language.invalid", "Operator", "operator-password"
        )
        self.operator_context = self.store.context_for_user(self.operator_user.user_id)
        self.client = self.store.create_client(self.operator_context, "Synthetic tenant A")
        self.other_client = self.store.create_client(
            self.operator_context, "Synthetic tenant B"
        )
        self.client_user = self.store.create_user(
            self.operator_context, "client@language.invalid", "Client",
            Role.CLIENT_ADMIN, self.client.client_id
        )
        self.store.set_password(
            self.operator_context, self.client_user.user_id, "client-password"
        )
        self.operator_token, self.operator_csrf = self.store.create_session(
            self.operator_user.user_id
        )
        self.client_token, self.client_csrf = self.store.create_session(
            self.client_user.user_id
        )

    def request(self, method, path, *, token=None, language=None, form=None,
                csrf=None, host=None):
        params = dict(form or {})
        if csrf is not None:
            params["csrf"] = csrf
        payload = urlencode(params).encode("ascii")
        environ = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "CONTENT_LENGTH": str(len(payload)),
            "CONTENT_TYPE": "application/x-www-form-urlencoded",
            "wsgi.input": io.BytesIO(payload),
        }
        if token is not None:
            environ["HTTP_COOKIE"] = "lightup_session=" + token
        if language is not None:
            environ["HTTP_ACCEPT_LANGUAGE"] = language
        if host is not None:
            environ["HTTP_HOST"] = host
        result = {}

        def respond(status, headers):
            result["status"] = status
            result["headers"] = dict(headers)

        body = b"".join(self.app(environ, respond))
        return result["status"], result["headers"], body

    def assert_same_decision(self, method, path, *, token=None, form=None, csrf=None,
                             host=None, expected):
        baseline = self.request(
            method, path, token=token, form=form, csrf=csrf, host=host
        )
        self.assertEqual(baseline[0], expected)
        for language in LANGUAGES:
            with self.subTest(method=method, path=path, language=repr(language)[:56]):
                current = self.request(
                    method, path, token=token, language=language, form=form,
                    csrf=csrf, host=host
                )
                self.assertEqual(current[0], expected)
                self.assertEqual(current, baseline)
                self.assertEqual(current[1]["Cache-Control"], "no-store")
                self.assertEqual(current[1]["X-Frame-Options"], "DENY")

    def test_anonymous_cannot_access_operator_or_client_routes(self):
        for path in ("/", "/clients", "/assessments",
                     f"/portal/{self.client.client_id}"):
            self.assert_same_decision("GET", path, expected="303 See Other")

    def test_client_cannot_become_operator(self):
        for path in ("/", "/clients", "/discovery", "/assessments"):
            self.assert_same_decision(
                "GET", path, token=self.client_token, expected="403 Forbidden"
            )

    def test_client_cannot_cross_tenant(self):
        self.assert_same_decision(
            "GET", f"/portal/{self.other_client.client_id}",
            token=self.client_token, expected="403 Forbidden"
        )

    def test_authorized_client_portal_stays_accessible(self):
        self.assert_same_decision(
            "GET", f"/portal/{self.client.client_id}",
            token=self.client_token, expected="200 OK"
        )

    def test_operator_access_does_not_depend_on_locale(self):
        for path in ("/", "/clients", "/assessments"):
            self.assert_same_decision(
                "GET", path, token=self.operator_token, expected="200 OK"
            )

    def test_missing_csrf_not_replaced_by_locale(self):
        self.assert_same_decision(
            "POST", "/clients", token=self.operator_token,
            form={"name": "Must Not Exist"}, expected="403 Forbidden"
        )
        self.assertEqual(len(self.store.list_clients(self.operator_context)), 2)

    def test_invalid_csrf_not_replaced_by_locale(self):
        self.assert_same_decision(
            "POST", "/clients", token=self.operator_token,
            form={"name": "Must Not Exist"}, csrf="wrong-token",
            expected="403 Forbidden"
        )
        self.assertEqual(len(self.store.list_clients(self.operator_context)), 2)

    def test_client_cannot_write_operator_data_even_with_valid_client_csrf(self):
        self.assert_same_decision(
            "POST", "/clients", token=self.client_token,
            csrf=self.client_csrf, form={"name": "Must Not Exist"},
            expected="403 Forbidden"
        )
        self.assertEqual(len(self.store.list_clients(self.operator_context)), 2)

    def test_revoked_session_cannot_be_restored_by_locale(self):
        self.store.revoke_session(self.operator_token)
        self.assertIsNone(self.store.session_context(self.operator_token))
        self.assert_same_decision(
            "GET", "/", token=self.operator_token, expected="303 See Other"
        )

    def test_invalid_host_is_not_rehabilitated_by_locale(self):
        self.assert_same_decision(
            "GET", "/", token=self.operator_token,
            host="external.example.invalid", expected="403 Forbidden"
        )

    def test_forged_cookie_is_not_rehabilitated_by_locale(self):
        self.assert_same_decision(
            "GET", "/", token="forged-session-token", expected="303 See Other"
        )

    def test_header_does_not_create_or_destroy_sessions(self):
        before_op = self.store.session_context(self.operator_token)
        before_client = self.store.session_context(self.client_token)
        self.assertIsNotNone(before_op)
        self.assertIsNotNone(before_client)
        self.assert_same_decision(
            "GET", "/login", token=self.operator_token, expected="303 See Other"
        )
        self.assertEqual(self.store.session_context(self.operator_token), before_op)
        self.assertEqual(self.store.session_context(self.client_token), before_client)
        self.assertEqual(len(self.store.list_clients(self.operator_context)), 2)


if __name__ == "__main__":
    unittest.main()
