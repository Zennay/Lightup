"""Real-WSGI, offline identity-header non-authority regressions.

Synthetic HTTP/WSGI environments only. No listeners, external targets,
assessment execution, grants, or deployment. This file is owned independently
of production webapp/security and other workers' tests.
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


# Upstream-provided identity conventions and user-controlled HTTP counterparts
# must never be accepted as substitutes for LightUp's server-side session.
SPOOFED_IDENTITIES = (
    ("REMOTE_USER", "op@lightup.test"),
    ("AUTH_TYPE", "Basic"),
    ("HTTP_AUTHORIZATION", "Bearer pretend-operator"),
    ("HTTP_X_REMOTE_USER", "op@lightup.test"),
    ("HTTP_X_AUTH_REQUEST_USER", "op@lightup.test"),
    ("HTTP_X_FORWARDED_USER", "op@lightup.test"),
    ("HTTP_X_FORWARDED_EMAIL", "op@lightup.test"),
    ("HTTP_X_USER", "op@lightup.test"),
    ("HTTP_X_API_KEY", "pretend-operator-key"),
)


class WsgiIdentityMetadataNonauthorityTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = DomainStore(Path(self.tmp.name) / "web.db")
        self.operator_user = self.store.bootstrap_operator(
            "op@lightup.test", "Operator", "operator-password"
        )
        self.operator_ctx = self.store.context_for_user(self.operator_user.user_id)
        self.client_a = self.store.create_client(self.operator_ctx, "Client A")
        self.client_b = self.store.create_client(self.operator_ctx, "Client B")
        self.client_user = self.store.create_user(
            self.operator_ctx, "client@lightup.test", "Client Admin",
            Role.CLIENT_ADMIN, self.client_a.client_id,
        )
        self.op_token, self.op_csrf = self.store.create_session(self.operator_user.user_id)
        self.client_token, self.client_csrf = self.store.create_session(self.client_user.user_id)

    def app_for(self, mode):
        if mode == "production":
            return create_app(self.store, WebSecurity("https://lightup.example.test"))
        return create_app(self.store, WebSecurity())

    def request(self, mode, method, path, *, token=None, form=None, extra=None):
        body = urlencode(form or {}).encode("utf-8")
        env = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "CONTENT_LENGTH": str(len(body)),
            "CONTENT_TYPE": "application/x-www-form-urlencoded",
            "wsgi.input": io.BytesIO(body),
            "REMOTE_ADDR": "127.0.0.1",
            "HTTP_HOST": "lightup.example.test" if mode == "production" else "localhost",
            "HTTP_ORIGIN": "https://lightup.example.test" if mode == "production"
                           else "http://localhost",
        }
        if mode == "production":
            env["HTTP_X_FORWARDED_PROTO"] = "https"
        if token is not None:
            env["HTTP_COOKIE"] = f"lightup_session={token}"
        env.update(extra or {})
        outcome = {}

        def respond(status, headers):
            outcome["status"] = status
            outcome["headers"] = dict(headers)

        payload = b"".join(self.app_for(mode)(env, respond)).decode("utf-8")
        return outcome["status"], outcome["headers"], payload

    def assert_no_new_clients(self):
        self.assertEqual(
            {c.client_id for c in self.store.list_clients(self.operator_ctx)},
            {self.client_a.client_id, self.client_b.client_id},
        )

    def test_anonymous_identity_metadata_never_opens_admin_or_other_portal(self):
        for mode in ("development", "production"):
            for key, value in SPOOFED_IDENTITIES:
                for path in ("/", "/clients", "/assessments",
                             f"/portal/{self.client_b.client_id}"):
                    with self.subTest(mode=mode, key=key, path=path):
                        status, headers, body = self.request(
                            mode, "GET", path, extra={key: value}
                        )
                        self.assertEqual(status, "303 See Other")
                        self.assertEqual(headers["Location"], "/login")
                        self.assertEqual(headers["Cache-Control"], "no-store")
                        self.assertNotIn("Client B", body)
        self.assert_no_new_clients()

    def test_anonymous_identity_metadata_cannot_create_even_with_operator_csrf(self):
        for mode in ("development", "production"):
            for key, value in SPOOFED_IDENTITIES:
                with self.subTest(mode=mode, key=key):
                    status, headers, _ = self.request(
                        mode, "POST", "/clients",
                        form={"csrf": self.op_csrf, "name": "Forged"},
                        extra={key: value},
                    )
                    self.assertEqual(status, "303 See Other")
                    self.assertEqual(headers["Location"], "/login")
                    self.assert_no_new_clients()
        self.assertIsNotNone(self.store.session_context(self.op_token))

    def test_client_cookie_cannot_be_promoted_to_operator_by_identity_metadata(self):
        for mode in ("development", "production"):
            for key, value in SPOOFED_IDENTITIES:
                with self.subTest(mode=mode, key=key):
                    status, _, _ = self.request(
                        mode, "GET", "/clients", token=self.client_token,
                        extra={key: value},
                    )
                    self.assertEqual(status, "403 Forbidden")
                    status, _, body = self.request(
                        mode, "GET", f"/portal/{self.client_b.client_id}",
                        token=self.client_token, extra={key: value},
                    )
                    self.assertEqual(status, "403 Forbidden")
                    self.assertNotIn("Client B", body)
        self.assert_no_new_clients()

    def test_client_csrf_with_forged_operator_identity_cannot_write(self):
        for mode in ("development", "production"):
            for key, value in SPOOFED_IDENTITIES:
                with self.subTest(mode=mode, key=key):
                    status, _, _ = self.request(
                        mode, "POST", "/clients", token=self.client_token,
                        form={"csrf": self.client_csrf, "name": "Forged"},
                        extra={key: value},
                    )
                    self.assertEqual(status, "403 Forbidden")
                    self.assert_no_new_clients()
        self.assertIsNotNone(self.store.session_context(self.client_token))

    def test_spoofed_csrf_header_cannot_replace_missing_or_invalid_form_csrf(self):
        for mode in ("development", "production"):
            for form in ({"name": "Forged"}, {"name": "Forged", "csrf": "invalid"}):
                with self.subTest(mode=mode, form=form):
                    status, _, _ = self.request(
                        mode, "POST", "/clients", token=self.op_token,
                        form=form, extra={"HTTP_X_CSRF_TOKEN": self.op_csrf,
                                          "HTTP_X_AUTH_REQUEST_USER": "op@lightup.test"},
                    )
                    self.assertEqual(status, "403 Forbidden")
                    self.assert_no_new_clients()
        self.assertIsNotNone(self.store.session_context(self.op_token))

    def test_spoofed_identity_logout_without_session_does_not_revoke_other_sessions(self):
        for mode in ("development", "production"):
            for key, value in SPOOFED_IDENTITIES:
                with self.subTest(mode=mode, key=key):
                    status, headers, _ = self.request(
                        mode, "POST", "/logout", form={"csrf": self.op_csrf},
                        extra={key: value},
                    )
                    self.assertEqual(status, "303 See Other")
                    self.assertEqual(headers["Location"], "/login")
                    self.assertNotIn("Set-Cookie", headers)
                    self.assertIsNotNone(self.store.session_context(self.op_token))
                    self.assertIsNotNone(self.store.session_context(self.client_token))

    def test_revoked_cookie_cannot_be_resurrected_by_wsgi_identity(self):
        self.store.revoke_session(self.op_token)
        self.assertIsNone(self.store.session_context(self.op_token))
        for mode in ("development", "production"):
            for key, value in SPOOFED_IDENTITIES:
                with self.subTest(mode=mode, key=key):
                    status, headers, _ = self.request(
                        mode, "GET", "/clients", token=self.op_token,
                        extra={key: value},
                    )
                    self.assertEqual(status, "303 See Other")
                    self.assertEqual(headers["Location"], "/login")
        self.assert_no_new_clients()

    def test_genuine_operator_cookie_plus_form_csrf_remain_authoritative(self):
        # Non-authoritative identity hints must neither elevate nor disable
        # an otherwise authorized operator action.
        for mode in ("development", "production"):
            with self.subTest(mode=mode):
                status, headers, _ = self.request(
                    mode, "POST", "/clients", token=self.op_token,
                    form={"csrf": self.op_csrf, "name": f"Allowed {mode}"},
                    extra={"REMOTE_USER": "client@lightup.test",
                           "HTTP_X_FORWARDED_USER": "client@lightup.test"},
                )
                self.assertEqual(status, "303 See Other")
                self.assertEqual(headers["Location"], "/clients")
        names = {c.name for c in self.store.list_clients(self.operator_ctx)}
        self.assertEqual(names, {"Client A", "Client B", "Allowed development",
                                 "Allowed production"})


if __name__ == "__main__":
    unittest.main()
