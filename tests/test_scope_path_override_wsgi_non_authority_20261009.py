"""Offline route-authority regression: path override headers are not WSGI authority.

This tests the actual LightUp WSGI application against temporary SQLite only.
It does NOT prove that an upstream reverse proxy never rewrites PATH_INFO.
"""
from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlencode

from lightup.domain import DomainStore, Role
from lightup.webapp import create_app
from lightup.webapp.security import WebSecurity


# These are transport metadata, not routing instructions for our application.
PATH_HINTS = (
    "HTTP_X_ORIGINAL_URL",
    "HTTP_X_REWRITE_URL",
    "HTTP_X_ORIGINAL_URI",
    "HTTP_X_FORWARDED_URI",
    "HTTP_X_FORWARDED_PATH",
    "HTTP_X_FORWARDED_PREFIX",
    "HTTP_X_SCRIPT_NAME",
)


class PathOverrideNonAuthorityTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = DomainStore(Path(self.temp.name) / "domain.db")
        op = self.store.bootstrap_operator(
            "operator@lightup.test", "Operator", "local-test-password"
        )
        self.operator = self.store.context_for_user(op.user_id)
        self.client_a = self.store.create_client(self.operator, "Client A")
        self.client_b = self.store.create_client(self.operator, "Client B")
        tenant = self.store.create_user(
            self.operator, "a@lightup.test", "A",
            Role.CLIENT_ADMIN, self.client_a.client_id
        )
        self.op_token, self.op_csrf = self.store.create_session(op.user_id)
        self.tenant_token, self.tenant_csrf = self.store.create_session(tenant.user_id)

    def send(self, production, method, path, *, token=None, csrf=None,
             form=None, hints=None):
        security = (WebSecurity(public_origin="https://lightup.example.com")
                    if production else WebSecurity())
        app = create_app(self.store, security=security)
        fields = dict(form or {})
        if csrf is not None:
            fields["csrf"] = csrf
        body = urlencode(fields).encode("utf-8")
        env = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "CONTENT_TYPE": "application/x-www-form-urlencoded",
            "CONTENT_LENGTH": str(len(body)),
            "wsgi.input": io.BytesIO(body),
            "HTTP_HOST": "lightup.example.com" if production else "localhost",
        }
        if production:
            env.update({
                "REMOTE_ADDR": "127.0.0.1",
                "HTTP_X_FORWARDED_PROTO": "https",
                "HTTP_ORIGIN": "https://lightup.example.com",
            })
        if token is not None:
            env["HTTP_COOKIE"] = "lightup_session=" + token
        env.update(hints or {})
        captured = {}

        def start_response(status, headers):
            captured["status"] = status
            captured["headers"] = dict(headers)

        payload = b"".join(app(env, start_response))
        return captured["status"], captured["headers"], payload

    def client_count(self):
        return len(self.store.list_clients(self.operator))

    def test_get_unknown_path_stays_unknown_despite_each_override_header(self):
        for production in (False, True):
            for key in PATH_HINTS:
                with self.subTest(production=production, header=key):
                    status, _, _ = self.send(
                        production, "GET", "/nonexistent",
                        token=self.op_token, hints={key: "/clients"}
                    )
                    self.assertEqual(status, "404 Not Found")

    def test_conflicting_override_headers_do_not_route_unknown_path(self):
        spoofed = {name: ("/clients" if i % 2 else "/")
                   for i, name in enumerate(PATH_HINTS)}
        for production in (False, True):
            with self.subTest(production=production):
                status, _, _ = self.send(
                    production, "GET", "/does-not-exist",
                    token=self.op_token, hints=spoofed
                )
                self.assertEqual(status, "404 Not Found")

    def test_tenant_cannot_see_other_portal_using_override_headers(self):
        spoofed = {name: "/portal/" + self.client_a.client_id
                   for name in PATH_HINTS}
        for production in (False, True):
            with self.subTest(production=production):
                denied, _, _ = self.send(
                    production, "GET", "/portal/" + self.client_b.client_id,
                    token=self.tenant_token, hints=spoofed
                )
                self.assertEqual(denied, "403 Forbidden")
                allowed, _, _ = self.send(
                    production, "GET", "/portal/" + self.client_a.client_id,
                    token=self.tenant_token,
                    hints={name: "/portal/" + self.client_b.client_id
                           for name in PATH_HINTS}
                )
                self.assertEqual(allowed, "200 OK")

    def test_spoofed_write_route_cannot_create_client(self):
        spoofed = {name: "/clients" for name in PATH_HINTS}
        before = self.client_count()
        for production in (False, True):
            with self.subTest(production=production):
                status, _, _ = self.send(
                    production, "POST", "/nonexistent",
                    token=self.op_token, csrf=self.op_csrf,
                    form={"name": "Injected"}, hints=spoofed
                )
                self.assertEqual(status, "404 Not Found")
                self.assertEqual(self.client_count(), before)

    def test_override_cannot_bypass_csrf_or_operator_role(self):
        spoofed = {name: "/login" for name in PATH_HINTS}
        before = self.client_count()
        for production in (False, True):
            with self.subTest(production=production):
                no_csrf, _, _ = self.send(
                    production, "POST", "/clients", token=self.op_token,
                    form={"name": "No CSRF"}, hints=spoofed
                )
                self.assertEqual(no_csrf, "403 Forbidden")
                wrong_role, _, _ = self.send(
                    production, "POST", "/clients",
                    token=self.tenant_token, csrf=self.tenant_csrf,
                    form={"name": "Tenant injected"}, hints=spoofed
                )
                self.assertEqual(wrong_role, "403 Forbidden")
                self.assertEqual(self.client_count(), before)

    def test_anonymous_spoofed_client_write_cannot_create_client(self):
        before = self.client_count()
        for production in (False, True):
            with self.subTest(production=production):
                status, headers, _ = self.send(
                    production, "POST", "/clients",
                    form={"name": "Anonymous"}, hints={
                        name: "/login" for name in PATH_HINTS
                    }
                )
                self.assertEqual(status, "303 See Other")
                self.assertEqual(headers["Location"], "/login")
                self.assertEqual(self.client_count(), before)

    def test_real_write_route_still_works_with_irrelevant_override_headers(self):
        for production in (False, True):
            with self.subTest(production=production):
                before = self.client_count()
                status, _, _ = self.send(
                    production, "POST", "/clients",
                    token=self.op_token, csrf=self.op_csrf,
                    form={"name": "Legitimate"},
                    hints={name: "/nonexistent" for name in PATH_HINTS}
                )
                self.assertEqual(status, "303 See Other")
                self.assertEqual(self.client_count(), before + 1)

    def test_logout_only_uses_canonical_wsgi_path(self):
        for production in (False, True):
            with self.subTest(production=production):
                token, csrf = self.store.create_session(self.operator.user_id)
                fake_logout, _, _ = self.send(
                    production, "POST", "/nonexistent",
                    token=token, csrf=csrf,
                    hints={name: "/logout" for name in PATH_HINTS}
                )
                self.assertEqual(fake_logout, "404 Not Found")
                self.assertIsNotNone(self.store.session_context(token))
                actual_logout, _, _ = self.send(
                    production, "POST", "/logout",
                    token=token, csrf=csrf,
                    hints={name: "/nonexistent" for name in PATH_HINTS}
                )
                self.assertEqual(actual_logout, "303 See Other")
                self.assertIsNone(self.store.session_context(token))


if __name__ == "__main__":
    unittest.main()
