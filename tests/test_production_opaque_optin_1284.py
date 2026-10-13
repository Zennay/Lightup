"""Genuine production-shaped WSGI and SQLite acceptance, all synthetic/offline.

Exercise only the explicit opt-in factory. No Gunicorn, TLS, network, real
proxy, target, customer, scan, grant issuance or deployment is involved.
"""
from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.parse import urlencode

from lightup.domain import Role
from lightup.webapp.opaque_error_wsgi_optin import OpaqueErrorWSGI
from lightup.webapp.production import create_production_app
from lightup.webapp.production_opaque_optin import create_opaque_production_app


class OpaqueProductionFactory1284Tests(unittest.TestCase):
    ORIGIN = "https://lightup.example.test"
    PRIVATE_ID = "PrivateClientId1284ShouldNotLeaveHTTP"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = str(Path(self.tmp.name) / "synthetic-production.sqlite3")
        self.config = {"LIGHTUP_PUBLIC_ORIGIN": self.ORIGIN, "LIGHTUP_DB": self.db}
        self.app = create_opaque_production_app(self.config)
        self.store = self.app._app.store
        self.operator = self.store.bootstrap_operator(
            "operator-1284@example.test", "Operator", "synthetic-password")
        self.ctx = self.store.context_for_user(self.operator.user_id)
        self.client_a = self.store.create_client(self.ctx, "Synthetic A")
        self.client_b = self.store.create_client(self.ctx, "Synthetic B")
        self.user_a = self.store.create_user(
            self.ctx, "client-1284@example.test", "Client",
            Role.CLIENT_ADMIN, self.client_a.client_id)
        self.op_token, self.op_csrf = self.store.create_session(self.operator.user_id)
        self.a_token, self.a_csrf = self.store.create_session(self.user_a.user_id)

    def request(self, method, path, form=None, token=None, overrides=None, app=None):
        raw = urlencode(form or {}).encode("utf-8")
        env = {
            "HTTP_HOST": "lightup.example.test",
            "REMOTE_ADDR": "127.0.0.1",
            "HTTP_X_FORWARDED_PROTO": "https",
            "HTTP_ORIGIN": self.ORIGIN,
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "CONTENT_LENGTH": str(len(raw)),
            "CONTENT_TYPE": "application/x-www-form-urlencoded",
            "wsgi.input": io.BytesIO(raw),
        }
        if token:
            env["HTTP_COOKIE"] = "lightup_session=" + token
        if overrides:
            env.update(overrides)
        result = {}
        body = b"".join((app or self.app)(
            env, lambda status, headers: result.update(
                status=status, headers=dict(headers))))
        return result["status"], result["headers"], body

    def test_optin_factory_not_default_factory(self):
        self.assertIsInstance(self.app, OpaqueErrorWSGI)
        legacy = create_production_app(self.config)
        self.assertNotIsInstance(legacy, OpaqueErrorWSGI)
        self.assertEqual(type(legacy).__name__, "LightUpWebApp")

    def test_bad_configuration_refused_before_database_create(self):
        bad_configs = (
            {},
            {"LIGHTUP_PUBLIC_ORIGIN": "http://lightup.example.test", "LIGHTUP_DB": self.db},
            {"LIGHTUP_PUBLIC_ORIGIN": self.ORIGIN, "LIGHTUP_DB": "relative.sqlite3"},
            {"LIGHTUP_PUBLIC_ORIGIN": "https://other.test/path", "LIGHTUP_DB": self.db},
            {"LIGHTUP_PUBLIC_ORIGIN": self.ORIGIN, "LIGHTUP_DB": self.db,
             "LIGHTUP_TRUSTED_PROXY_IP": "198.51.100.1"},
        )
        for bad in bad_configs:
            with self.subTest(bad=bad), patch("lightup.webapp.production.DomainStore") as factory:
                with self.assertRaises(ValueError):
                    create_opaque_production_app(bad)
                factory.assert_not_called()

    def test_authenticated_unknown_id_no_echo_and_security_headers(self):
        status, h, body = self.request(
            "GET", "/clients/" + self.PRIVATE_ID, token=self.op_token)
        self.assertEqual(status, "400 Bad Request")
        self.assertNotIn(self.PRIVATE_ID.encode(), body)
        self.assertNotIn(b"unknown client", body)
        self.assertEqual(h["Strict-Transport-Security"], "max-age=31536000")
        self.assertEqual(h["Cache-Control"], "no-store")
        self.assertEqual(h["X-Frame-Options"], "DENY")
        self.assertIn("frame-ancestors 'none'", h["Content-Security-Policy"])
        self.assertEqual(h["Content-Type"], "text/html; charset=utf-8")
        self.assertEqual(int(h["Content-Length"]), len(body))
        self.assertNotIn("Set-Cookie", h)
        self.assertNotIn("Location", h)

    def test_original_factory_still_echoes_unknown_id(self):
        legacy = create_production_app(self.config)
        status, h, body = self.request(
            "GET", "/clients/" + self.PRIVATE_ID,
            token=self.op_token, app=legacy)
        self.assertEqual(status, "400 Bad Request")
        self.assertIn(self.PRIVATE_ID.encode(), body)
        self.assertEqual(h["Strict-Transport-Security"], "max-age=31536000")

    def test_validation_error_is_private_and_durable_data_unchanged(self):
        before = len(self.store.list_clients(self.ctx))
        status, h, body = self.request(
            "POST", "/clients", form={"name": "", "csrf": self.op_csrf},
            token=self.op_token)
        self.assertEqual(status, "400 Bad Request")
        self.assertNotIn(b"client name is required", body)
        self.assertEqual(h["Cache-Control"], "no-store")
        self.assertEqual(len(self.store.list_clients(self.ctx)), before)

    def test_authorized_get_unchanged(self):
        legacy = create_production_app(self.config)
        expected = self.request("GET", "/clients", token=self.op_token, app=legacy)
        actual = self.request("GET", "/clients", token=self.op_token)
        self.assertEqual(actual, expected)
        self.assertEqual(actual[0], "200 OK")
        self.assertIn(b"Synthetic A", actual[2])

    def test_same_origin_valid_operator_post_persists(self):
        before = len(self.store.list_clients(self.ctx))
        status, h, _ = self.request(
            "POST", "/clients",
            form={"name": "Synthetic allowed", "csrf": self.op_csrf},
            token=self.op_token)
        self.assertEqual(status, "303 See Other")
        self.assertEqual(h["Location"], "/clients")
        self.assertEqual(h["Strict-Transport-Security"], "max-age=31536000")
        self.assertEqual(len(self.store.list_clients(self.ctx)), before + 1)

    def test_missing_or_wrong_csrf_never_mutates(self):
        before = len(self.store.list_clients(self.ctx))
        for csrf in (None, "", "wrong"):
            with self.subTest(csrf=csrf):
                form = {"name": "Denied"}
                if csrf is not None:
                    form["csrf"] = csrf
                status, _, _ = self.request("POST", "/clients", form=form,
                                             token=self.op_token)
                self.assertEqual(status, "403 Forbidden")
        self.assertEqual(len(self.store.list_clients(self.ctx)), before)

    def test_cross_origin_and_cross_site_post_refuse_before_mutation(self):
        before = len(self.store.list_clients(self.ctx))
        cases = (
            {"HTTP_ORIGIN": "https://evil.example.test"},
            {"HTTP_ORIGIN": "null"},
            {"HTTP_SEC_FETCH_SITE": "cross-site"},
            {"REMOTE_ADDR": "192.0.2.44", "HTTP_X_FORWARDED_FOR": "127.0.0.1"},
            {"HTTP_X_FORWARDED_PROTO": "http"},
            {"HTTP_HOST": "evil.example.test"},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                status, h, body = self.request(
                    "POST", "/clients",
                    form={"name": "Forbidden", "csrf": self.op_csrf},
                    token=self.op_token, overrides=overrides)
                self.assertEqual(status, "403 Forbidden")
                self.assertEqual(h["Cache-Control"], "no-store")
                self.assertNotIn(b"Forbidden new tenant", body)
        self.assertEqual(len(self.store.list_clients(self.ctx)), before)

    def test_rejected_origin_precedes_body_parsing_and_session_lookup(self):
        unread = Mock()
        env = {
            "HTTP_HOST": "lightup.example.test",
            "REMOTE_ADDR": "127.0.0.1",
            "HTTP_X_FORWARDED_PROTO": "https",
            "HTTP_ORIGIN": "https://untrusted.example.test",
            "REQUEST_METHOD": "POST",
            "PATH_INFO": "/clients",
            "CONTENT_LENGTH": "999999999",
            "CONTENT_TYPE": "application/x-www-form-urlencoded",
            "HTTP_COOKIE": "lightup_session=" + self.op_token,
            "wsgi.input": unread,
        }
        out = {}
        with patch.object(self.store, "session_context") as lookup:
            body = b"".join(self.app(
                env, lambda status, headers: out.update(
                    status=status, headers=dict(headers))))
            lookup.assert_not_called()
        unread.read.assert_not_called()
        self.assertEqual(out["status"], "403 Forbidden")
        self.assertNotIn(self.PRIVATE_ID.encode(), body)
        self.assertEqual(out["headers"]["Cache-Control"], "no-store")

    def test_oversized_form_refused_before_session_and_stream_read(self):
        unread = Mock()
        env = {
            "HTTP_HOST": "lightup.example.test",
            "REMOTE_ADDR": "127.0.0.1",
            "HTTP_X_FORWARDED_PROTO": "https",
            "HTTP_ORIGIN": self.ORIGIN,
            "REQUEST_METHOD": "POST",
            "PATH_INFO": "/clients",
            "CONTENT_LENGTH": "65537",
            "CONTENT_TYPE": "application/x-www-form-urlencoded",
            "HTTP_COOKIE": "lightup_session=" + self.op_token,
            "wsgi.input": unread,
        }
        out = {}
        with patch.object(self.store, "session_context") as lookup:
            body = b"".join(self.app(
                env, lambda status, headers: out.update(
                    status=status, headers=dict(headers))))
            lookup.assert_not_called()
        unread.read.assert_not_called()
        self.assertEqual(out["status"], "413 Payload Too Large")
        self.assertNotIn(self.PRIVATE_ID.encode(), body)
        self.assertEqual(out["headers"]["Cache-Control"], "no-store")


    def test_client_role_cannot_create_other_tenant(self):
        before = len(self.store.list_clients(self.ctx))
        status, _, _ = self.request(
            "POST", "/clients", form={"name": "Illegal", "csrf": self.a_csrf},
            token=self.a_token)
        self.assertEqual(status, "403 Forbidden")
        self.assertEqual(len(self.store.list_clients(self.ctx)), before)

    def test_client_cannot_get_unknown_operator_client_details(self):
        status, h, body = self.request(
            "GET", "/clients/" + self.PRIVATE_ID, token=self.a_token)
        self.assertEqual(status, "403 Forbidden")
        self.assertNotIn(self.PRIVATE_ID.encode(), body)
        self.assertEqual(h["Cache-Control"], "no-store")

    def test_anonymous_redirect_never_reflects_private_identifier(self):
        status, h, body = self.request("GET", "/clients/" + self.PRIVATE_ID)
        self.assertEqual(status, "303 See Other")
        self.assertEqual(h["Location"], "/login")
        self.assertEqual(h["Strict-Transport-Security"], "max-age=31536000")
        self.assertNotIn(self.PRIVATE_ID.encode(), body)

    def test_real_login_sets_secure_session_cookie(self):
        status, h, body = self.request(
            "POST", "/login",
            form={"email": "operator-1284@example.test",
                  "password": "synthetic-password"})
        self.assertEqual(status, "303 See Other")
        self.assertEqual(body, b"")
        self.assertIn("Secure", h["Set-Cookie"])
        self.assertIn("HttpOnly", h["Set-Cookie"])
        self.assertIn("SameSite=Strict", h["Set-Cookie"])
        self.assertEqual(h["Cache-Control"], "no-store")
        self.assertEqual(h["Strict-Transport-Security"], "max-age=31536000")

    def test_logout_revokes_session_and_cookie(self):
        status, h, body = self.request(
            "POST", "/logout", form={"csrf": self.op_csrf}, token=self.op_token)
        self.assertEqual(status, "303 See Other")
        self.assertEqual(body, b"")
        self.assertIn("Max-Age=0", h["Set-Cookie"])
        self.assertIn("Secure", h["Set-Cookie"])
        self.assertIsNone(self.store.session_context(self.op_token))

    def test_error_does_not_revoke_valid_session(self):
        self.request("GET", "/clients/" + self.PRIVATE_ID, token=self.op_token)
        self.assertIsNotNone(self.store.session_context(self.op_token))
        status, _, _ = self.request("GET", "/clients", token=self.op_token)
        self.assertEqual(status, "200 OK")


if __name__ == "__main__":
    unittest.main()
