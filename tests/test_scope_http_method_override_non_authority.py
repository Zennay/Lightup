"""HTTP method-override headers are not authorization evidence.

Exercise the actual LightUp WSGI dispatch and tenant/CSRF gates with a
temporary SQLite store. No network listener, target interaction or scanning.
"""
from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlencode

from lightup.domain import DomainStore, Role
from lightup.webapp import create_app


class MethodOverrideNonAuthorityTests(unittest.TestCase):
    OVERRIDES = (
        "HTTP_X_HTTP_METHOD_OVERRIDE",
        "HTTP_X_METHOD_OVERRIDE",
        "HTTP_X_ORIGINAL_METHOD",
    )

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = DomainStore(Path(self.tmp.name) / "method-override.db")
        self.app = create_app(self.store)
        operator_user = self.store.bootstrap_operator(
            "operator@lightup.test", "Operator", "offline-operator-password"
        )
        self.operator = self.store.context_for_user(operator_user.user_id)
        client = self.store.create_client(self.operator, "Offline existing client")
        client_user = self.store.create_user(
            self.operator, "client@lightup.test", "Client",
            Role.CLIENT_ADMIN, client.client_id
        )
        self.operator_token, self.operator_csrf = self.store.create_session(
            operator_user.user_id
        )
        self.client_token, self.client_csrf = self.store.create_session(
            client_user.user_id
        )

    def request(self, method, path, *, form=None, token=None, headers=None):
        payload = urlencode(form or {}).encode("utf-8")
        environ = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "CONTENT_TYPE": "application/x-www-form-urlencoded",
            "CONTENT_LENGTH": str(len(payload)),
            "wsgi.input": io.BytesIO(payload),
        }
        if token is not None:
            environ["HTTP_COOKIE"] = f"lightup_session={token}"
        environ.update(headers or {})
        captured = {}

        def start_response(status, response_headers):
            captured["status"] = status
            captured["headers"] = dict(response_headers)

        body = b"".join(self.app(environ, start_response))
        return captured["status"], captured["headers"], body

    def client_count(self):
        return len(self.store.list_clients(self.operator))

    def test_get_cannot_be_promoted_to_mutating_post(self):
        before = self.client_count()
        for name in self.OVERRIDES:
            with self.subTest(header=name):
                status, _, _ = self.request(
                    "GET", "/clients",
                    form={"name": "Spoofed", "csrf": self.operator_csrf},
                    token=self.operator_token,
                    headers={name: "POST"},
                )
                self.assertEqual(status, "200 OK")
                self.assertEqual(self.client_count(), before)

    def test_post_cannot_bypass_csrf_by_claiming_to_be_get(self):
        before = self.client_count()
        for name in self.OVERRIDES:
            with self.subTest(header=name):
                status, _, _ = self.request(
                    "POST", "/clients", form={"name": "Spoofed"},
                    token=self.operator_token, headers={name: "GET"},
                )
                self.assertEqual(status, "403 Forbidden")
                self.assertEqual(self.client_count(), before)

    def test_post_cannot_bypass_operator_role_by_claiming_get(self):
        before = self.client_count()
        for name in self.OVERRIDES:
            with self.subTest(header=name):
                status, _, _ = self.request(
                    "POST", "/clients",
                    form={"name": "Spoofed", "csrf": self.client_csrf},
                    token=self.client_token, headers={name: "GET"},
                )
                self.assertEqual(status, "403 Forbidden")
                self.assertEqual(self.client_count(), before)

    def test_post_cannot_bypass_session_requirement(self):
        before = self.client_count()
        for name in self.OVERRIDES:
            with self.subTest(header=name):
                status, headers, _ = self.request(
                    "POST", "/clients",
                    form={"name": "Spoofed", "csrf": self.operator_csrf},
                    headers={name: "GET"},
                )
                self.assertEqual(status, "303 See Other")
                self.assertEqual(headers.get("Location"), "/login")
                self.assertEqual(self.client_count(), before)

    def test_get_cannot_trigger_logout_by_claiming_post(self):
        for name in self.OVERRIDES:
            with self.subTest(header=name):
                status, _, _ = self.request(
                    "GET", "/logout",
                    form={"csrf": self.operator_csrf},
                    token=self.operator_token,
                    headers={name: "POST"},
                )
                self.assertEqual(status, "404 Not Found")
                self.assertIsNotNone(
                    self.store.session_context(self.operator_token)
                )

    def test_post_logout_still_requires_csrf_when_claiming_get(self):
        for name in self.OVERRIDES:
            with self.subTest(header=name):
                status, _, _ = self.request(
                    "POST", "/logout", token=self.operator_token,
                    headers={name: "GET"},
                )
                self.assertEqual(status, "403 Forbidden")
                self.assertIsNotNone(
                    self.store.session_context(self.operator_token)
                )

    def test_conflicting_override_headers_cannot_bypass_csrf(self):
        before = self.client_count()
        status, _, _ = self.request(
            "POST", "/clients", form={"name": "Spoofed"},
            token=self.operator_token,
            headers={
                "HTTP_X_HTTP_METHOD_OVERRIDE": "GET",
                "HTTP_X_METHOD_OVERRIDE": "DELETE",
                "HTTP_X_ORIGINAL_METHOD": "PATCH",
            },
        )
        self.assertEqual(status, "403 Forbidden")
        self.assertEqual(self.client_count(), before)

    def test_actual_post_with_valid_operator_and_csrf_is_positive_control(self):
        before = self.client_count()
        status, headers, _ = self.request(
            "POST", "/clients",
            form={"name": "Authorized fixture", "csrf": self.operator_csrf},
            token=self.operator_token,
            headers={"HTTP_X_HTTP_METHOD_OVERRIDE": "GET"},
        )
        self.assertEqual(status, "303 See Other")
        self.assertEqual(self.client_count(), before + 1)



class ProductionMethodOverrideNonAuthorityTests(MethodOverrideNonAuthorityTests):
    """Repeat real WSGI checks behind configured HTTPS/trusted-loopback proxy."""

    def setUp(self):
        super().setUp()
        from lightup.webapp.security import WebSecurity

        self.app = create_app(
            self.store,
            WebSecurity(
                public_origin="https://security.example.test",
                trusted_proxy_ip="127.0.0.1",
            ),
        )

    def request(self, method, path, *, form=None, token=None, headers=None):
        proxy_context = {
            "REMOTE_ADDR": "127.0.0.1",
            "HTTP_HOST": "security.example.test",
            "HTTP_X_FORWARDED_PROTO": "https",
            "HTTP_ORIGIN": "https://security.example.test",
        }
        proxy_context.update(headers or {})
        return super().request(
            method, path, form=form, token=token, headers=proxy_context
        )

    def test_override_does_not_skip_cross_origin_submission_denial(self):
        before = self.client_count()
        status, _, _ = self.request(
            "POST", "/clients",
            form={"name": "Spoofed", "csrf": self.operator_csrf},
            token=self.operator_token,
            headers={
                "HTTP_X_HTTP_METHOD_OVERRIDE": "GET",
                "HTTP_ORIGIN": "https://outside.example.test",
            },
        )
        self.assertEqual(status, "403 Forbidden")
        self.assertEqual(self.client_count(), before)

    def test_override_does_not_skip_https_forwarding_requirement(self):
        before = self.client_count()
        status, _, _ = self.request(
            "POST", "/clients",
            form={"name": "Spoofed", "csrf": self.operator_csrf},
            token=self.operator_token,
            headers={
                "HTTP_X_HTTP_METHOD_OVERRIDE": "GET",
                "HTTP_X_FORWARDED_PROTO": "http",
            },
        )
        self.assertEqual(status, "403 Forbidden")
        self.assertEqual(self.client_count(), before)

    def test_override_does_not_skip_trusted_proxy_peer_requirement(self):
        before = self.client_count()
        status, _, _ = self.request(
            "POST", "/clients",
            form={"name": "Spoofed", "csrf": self.operator_csrf},
            token=self.operator_token,
            headers={
                "HTTP_X_HTTP_METHOD_OVERRIDE": "GET",
                "REMOTE_ADDR": "198.51.100.8",
            },
        )
        self.assertEqual(status, "403 Forbidden")
        self.assertEqual(self.client_count(), before)

    def test_override_does_not_skip_production_host_guard(self):
        before = self.client_count()
        status, _, _ = self.request(
            "POST", "/clients",
            form={"name": "Spoofed", "csrf": self.operator_csrf},
            token=self.operator_token,
            headers={
                "HTTP_X_HTTP_METHOD_OVERRIDE": "GET",
                "HTTP_HOST": "outside.example.test",
            },
        )
        self.assertEqual(status, "403 Forbidden")
        self.assertEqual(self.client_count(), before)


if __name__ == "__main__":
    unittest.main()
