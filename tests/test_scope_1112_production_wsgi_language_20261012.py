"""Issue #1112: production-factory WSGI Accept-Language is never authority.

Uses the real production app factory, its WebSecurity and disposable SQLite.
No network listeners, HTTP requests, targets, scans or grant issuance.
Only new tests; ingress and producer implementations remain untouched.
"""
from __future__ import annotations

import io
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lightup.domain import Role
from lightup.webapp.production import create_production_app


LOCALES = (
    None,
    "",
    "en-US",
    "nl-NL,nl;q=0.9",
    "fr-FR,*;q=0",
    "*",
    "en-US,en;q=0.9,ja;q=0.2",
    "operator",
    "admin@tenant.invalid",
    "../../clients",
    "en\r\nX-Role: operator",
    "en\r\nCookie: lightup_session=forged",
    "en\x00owner",
    "a" * 8192,
)


class ProductionWSGILanguageNonAuthorityTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.app = create_production_app({
            "LIGHTUP_PUBLIC_ORIGIN": "https://lightup.example.test",
            "LIGHTUP_DB": str(Path(tmp.name) / "synthetic.sqlite"),
        })
        self.store = self.app.store
        self.operator = self.store.bootstrap_operator(
            "operator@scope.invalid", "Operator", "test-operator-password"
        )
        self.operator_ctx = self.store.context_for_user(self.operator.user_id)
        self.a = self.store.create_client(self.operator_ctx, "Synthetic A")
        self.b = self.store.create_client(self.operator_ctx, "Synthetic B")
        user = self.store.create_user(
            self.operator_ctx, "client@scope.invalid", "Client",
            Role.CLIENT_ADMIN, self.a.client_id
        )
        self.store.set_password(self.operator_ctx, user.user_id, "test-client-password")
        self.client_token, self.client_csrf = self.store.create_session(user.user_id)
        self.operator_token, self.operator_csrf = self.store.create_session(
            self.operator.user_id
        )

    def request(self, method, path, *, language=None, token=None, data=None,
                csrf=None, overrides=None):
        form = dict(data or {})
        if csrf is not None:
            form["csrf"] = csrf
        payload = urlencode(form).encode("ascii")
        env = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "HTTP_HOST": "lightup.example.test",
            "REMOTE_ADDR": "127.0.0.1",
            "HTTP_X_FORWARDED_PROTO": "https",
            "HTTP_ORIGIN": "https://lightup.example.test",
            "CONTENT_TYPE": "application/x-www-form-urlencoded",
            "CONTENT_LENGTH": str(len(payload)),
            "wsgi.input": io.BytesIO(payload),
        }
        if language is not None:
            env["HTTP_ACCEPT_LANGUAGE"] = language
        if token is not None:
            env["HTTP_COOKIE"] = "lightup_session=" + token
        if overrides:
            env.update(overrides)
        result = {}

        def start(status, headers):
            result["status"] = status
            result["headers"] = tuple(headers)

        body = b"".join(self.app(env, start))
        return result["status"], result["headers"], body

    def assert_matrix(self, method, path, *, token=None, data=None, csrf=None,
                      overrides=None, status):
        baseline = self.request(
            method, path, token=token, data=data, csrf=csrf,
            overrides=overrides
        )
        self.assertEqual(baseline[0], status)
        for locale in LOCALES:
            with self.subTest(locale=repr(locale)[:70], path=path):
                got = self.request(
                    method, path, language=locale, token=token, data=data,
                    csrf=csrf, overrides=overrides
                )
                self.assertEqual(got, baseline)
                headers = dict(got[1])
                self.assertEqual(headers["Cache-Control"], "no-store")
                self.assertEqual(
                    headers["Strict-Transport-Security"], "max-age=31536000"
                )
                self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
                self.assertNotIn("Content-Language", headers)
                self.assertNotIn("X-Role", headers)

    def test_anonymous_operator_page_remains_denied(self):
        for path in ("/", "/clients", "/assessments"):
            self.assert_matrix("GET", path, status="303 See Other")

    def test_client_cannot_promote_to_operator(self):
        for path in ("/", "/clients", "/assessments"):
            self.assert_matrix(
                "GET", path, token=self.client_token, status="403 Forbidden"
            )

    def test_client_cannot_read_foreign_tenant(self):
        self.assert_matrix(
            "GET", f"/portal/{self.b.client_id}", token=self.client_token,
            status="403 Forbidden"
        )

    def test_authorized_client_portal_is_not_disabled_by_locale(self):
        self.assert_matrix(
            "GET", f"/portal/{self.a.client_id}", token=self.client_token,
            status="200 OK"
        )

    def test_operator_console_is_not_disabled_by_locale(self):
        self.assert_matrix("GET", "/", token=self.operator_token, status="200 OK")

    def test_signed_in_login_redirect_does_not_depend_on_locale(self):
        self.assert_matrix(
            "GET", "/login", token=self.operator_token, status="303 See Other"
        )

    def test_anonymous_login_page_never_echoes_header(self):
        self.assert_matrix("GET", "/login", status="200 OK")

    def test_missing_csrf_is_never_replaced_by_language(self):
        self.assert_matrix(
            "POST", "/clients", token=self.operator_token,
            data={"name": "Should not exist"}, status="403 Forbidden"
        )
        self.assertEqual(len(self.store.list_clients(self.operator_ctx)), 2)

    def test_invalid_csrf_is_never_replaced_by_language(self):
        self.assert_matrix(
            "POST", "/clients", token=self.operator_token,
            data={"name": "Should not exist"}, csrf="wrong",
            status="403 Forbidden"
        )
        self.assertEqual(len(self.store.list_clients(self.operator_ctx)), 2)

    def test_client_csrf_cannot_create_operator_client(self):
        self.assert_matrix(
            "POST", "/clients", token=self.client_token,
            csrf=self.client_csrf, data={"name": "Should not exist"},
            status="403 Forbidden"
        )
        self.assertEqual(len(self.store.list_clients(self.operator_ctx)), 2)

    def test_proxy_identity_cannot_be_replaced_by_language(self):
        self.assert_matrix(
            "GET", "/", token=self.operator_token,
            overrides={"REMOTE_ADDR": "192.0.2.15"},
            status="403 Forbidden"
        )

    def test_host_identity_cannot_be_replaced_by_language(self):
        self.assert_matrix(
            "GET", "/", token=self.operator_token,
            overrides={"HTTP_HOST": "attacker.example.invalid"},
            status="403 Forbidden"
        )

    def test_origin_guard_cannot_be_replaced_by_language(self):
        self.assert_matrix(
            "POST", "/clients", token=self.operator_token,
            csrf=self.operator_csrf, data={"name": "Should not exist"},
            overrides={"HTTP_ORIGIN": "https://outside.example.invalid"},
            status="403 Forbidden"
        )
        self.assertEqual(len(self.store.list_clients(self.operator_ctx)), 2)

    def test_live_operator_csrf_write_succeeds_on_each_locale(self):
        initial = len(self.store.list_clients(self.operator_ctx))
        for index, locale in enumerate(LOCALES):
            with self.subTest(locale=repr(locale)[:70]):
                status, headers, _ = self.request(
                    "POST", "/clients", language=locale, token=self.operator_token,
                    csrf=self.operator_csrf,
                    data={"name": f"Authorized synthetic {index}"}
                )
                self.assertEqual(status, "303 See Other")
                self.assertEqual(dict(headers)["Cache-Control"], "no-store")
                self.assertEqual(
                    len(self.store.list_clients(self.operator_ctx)),
                    initial + index + 1
                )

    def test_valid_login_issues_secure_cookie_under_each_locale(self):
        for locale in LOCALES:
            with self.subTest(locale=repr(locale)[:70]):
                status, headers, _ = self.request(
                    "POST", "/login", language=locale,
                    data={"email": "operator@scope.invalid",
                          "password": "test-operator-password"},
                )
                self.assertEqual(status, "303 See Other")
                cookie = dict(headers)["Set-Cookie"]
                self.assertIn("HttpOnly", cookie)
                self.assertIn("; Secure", cookie)
                token = cookie.split("lightup_session=", 1)[1].split(";", 1)[0]
                self.assertIsNotNone(self.store.session_context(token))

    def test_logout_revocation_targets_only_the_own_session(self):
        for locale in LOCALES:
            with self.subTest(locale=repr(locale)[:70]):
                token, csrf = self.store.create_session(self.operator.user_id)
                status, headers, _ = self.request(
                    "POST", "/logout", language=locale, token=token, csrf=csrf
                )
                self.assertEqual(status, "303 See Other")
                self.assertIn("Max-Age=0", dict(headers)["Set-Cookie"])
                self.assertIsNone(self.store.session_context(token))
                self.assertIsNotNone(self.store.session_context(self.client_token))

    def test_locale_cannot_resurrect_revoked_operator_session(self):
        self.store.revoke_session(self.operator_token)
        self.assert_matrix(
            "GET", "/", token=self.operator_token, status="303 See Other"
        )

    def test_locale_cannot_resurrect_forged_session(self):
        self.assert_matrix(
            "GET", "/", token="forged-token", status="303 See Other"
        )

    def test_cross_tenant_portal_post_never_mints_a_request(self):
        client_context, _ = self.store.session_context(self.client_token)
        before = self.store.list_assessment_requests(client_context)
        for locale in LOCALES:
            with self.subTest(locale=repr(locale)[:70]):
                status, headers, _ = self.request(
                    "POST", f"/portal/{self.b.client_id}/requests",
                    language=locale, token=self.client_token,
                    csrf=self.client_csrf,
                    data={"assets": "unowned.example.invalid",
                          "risk": "1", "notes": "Synthetic non-authorizing test"},
                )
                self.assertEqual(status, "403 Forbidden")
                self.assertEqual(dict(headers)["Cache-Control"], "no-store")
                self.assertEqual(
                    self.store.list_assessment_requests(client_context), before
                )

    def test_destructive_portal_request_stays_forbidden_to_request(self):
        client_context, _ = self.store.session_context(self.client_token)
        before = self.store.list_assessment_requests(client_context)
        self.assert_matrix(
            "POST", f"/portal/{self.a.client_id}/requests",
            token=self.client_token, csrf=self.client_csrf,
            data={"assets": "owned.example.invalid", "risk": "5"},
            status="400 Bad Request"
        )
        self.assertEqual(
            self.store.list_assessment_requests(client_context), before
        )

    def test_own_passive_request_stays_review_only_across_locales(self):
        # Submits only synthetic review requests into disposable SQLite.
        # No authorization grant, target interaction or assessment execution.
        client_context, _ = self.store.session_context(self.client_token)
        before = len(self.store.list_assessment_requests(client_context))
        for index, locale in enumerate(LOCALES):
            with self.subTest(locale=repr(locale)[:70]):
                status, headers, _ = self.request(
                    "POST", f"/portal/{self.a.client_id}/requests",
                    language=locale, token=self.client_token,
                    csrf=self.client_csrf,
                    data={"assets": f"owned-{index}.example.invalid",
                          "risk": "1", "notes": "Offline test request only"},
                )
                self.assertEqual(status, "303 See Other")
                self.assertEqual(dict(headers)["Cache-Control"], "no-store")
                self.assertEqual(
                    len(self.store.list_assessment_requests(client_context)),
                    before + index + 1
                )

    def test_untrusted_locale_cannot_open_an_execution_route_or_socket(self):
        # A transport header must not turn the web portal into a tool/scan API.
        # Socket is intercepted: even an attempted call fails before network I/O.
        from unittest.mock import patch

        for locale in LOCALES:
            with self.subTest(locale=repr(locale)[:70]):
                with patch(
                    "socket.socket", side_effect=AssertionError("network attempted")
                ) as socket_ctor:
                    for method, path in (
                        ("GET", "/execute"), ("GET", "/scan"),
                        ("POST", "/execute"), ("POST", "/scan"),
                    ):
                        status, headers, body = self.request(
                            method, path, language=locale,
                            token=self.operator_token,
                        )
                        self.assertEqual(status, "404 Not Found")
                        self.assertEqual(dict(headers)["Cache-Control"], "no-store")
                        self.assertNotIn(b"lightup_session=", body)
                    socket_ctor.assert_not_called()

    def test_production_tenant_list_is_unchanged_after_denied_matrix(self):
        before = self.store.list_clients(self.operator_ctx)
        self.assert_matrix(
            "POST", "/clients", token=self.client_token,
            csrf=self.client_csrf, data={"name": "Blocked"},
            status="403 Forbidden"
        )
        self.assertEqual(self.store.list_clients(self.operator_ctx), before)


if __name__ == "__main__":
    unittest.main()
