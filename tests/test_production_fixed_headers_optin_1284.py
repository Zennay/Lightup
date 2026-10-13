"""Real synthetic WSGI/privacy verification for fixed-header opt-in #1284."""
from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.parse import urlencode

from lightup.domain import Role
from lightup.webapp import create_app
from lightup.webapp.opaque_error_wsgi_optin import OpaqueErrorWSGI
from lightup.webapp.production_opaque_optin import create_opaque_production_app
from lightup.webapp.production_fixed_headers_optin import (
    FixedHeaderOpaqueProductionWSGI, create_fixed_header_opaque_production_app,
)


class FixedHeaderProductionPrivacy1284Tests(unittest.TestCase):
    PRIVATE = "Private1284HeaderAuditMarker"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config = {
            "LIGHTUP_PUBLIC_ORIGIN": "https://lightup.example.test",
            "LIGHTUP_DB": str(Path(self.tmp.name) / "private-lab.sqlite3"),
        }
        self.app = create_fixed_header_opaque_production_app(self.config)
        self.store = self.app._app._app.store
        self.operator = self.store.bootstrap_operator(
            "op-fixed@lightup.test", "Operator", "synthetic-password")
        self.ctx = self.store.context_for_user(self.operator.user_id)
        self.client = self.store.create_client(self.ctx, "Tenant Fixed")
        self.client_user = self.store.create_user(
            self.ctx, "tenant-fixed@lightup.test", "Client",
            Role.CLIENT_ADMIN, self.client.client_id)
        self.op_token, self.op_csrf = self.store.create_session(self.operator.user_id)
        self.client_token, self.client_csrf = self.store.create_session(
            self.client_user.user_id)

    def request(self, method="GET", path="/clients", form=None, token=None,
                overrides=None, app=None):
        raw = urlencode(form or {}).encode("utf-8")
        env = {
            "HTTP_HOST": "lightup.example.test",
            "REMOTE_ADDR": "127.0.0.1",
            "HTTP_X_FORWARDED_PROTO": "https",
            "HTTP_ORIGIN": "https://lightup.example.test",
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
        meta = {}
        body = b"".join((app or self.app)(
            env, lambda status, headers: meta.update(
                status=status, headers=list(headers))))
        return meta["status"], meta["headers"], body

    @staticmethod
    def as_dict(headers):
        return dict(headers)

    def test_exact_nested_production_gate_only(self):
        self.assertIsInstance(self.app, FixedHeaderOpaqueProductionWSGI)
        self.assertIs(type(self.app._app), OpaqueErrorWSGI)
        with self.assertRaises(TypeError):
            FixedHeaderOpaqueProductionWSGI(object())
        with self.assertRaises(TypeError):
            FixedHeaderOpaqueProductionWSGI(create_app(self.store))
        with self.assertRaises(ValueError):
            FixedHeaderOpaqueProductionWSGI(
                OpaqueErrorWSGI(create_app(self.store)))

    def test_invalid_configuration_rejected_before_store(self):
        for cfg in ({}, {"LIGHTUP_PUBLIC_ORIGIN": "http://lightup.example.test",
                          "LIGHTUP_DB": self.config["LIGHTUP_DB"]},
                    {"LIGHTUP_PUBLIC_ORIGIN": self.config["LIGHTUP_PUBLIC_ORIGIN"],
                     "LIGHTUP_DB": "relative.db"},
                    {"LIGHTUP_PUBLIC_ORIGIN": self.config["LIGHTUP_PUBLIC_ORIGIN"],
                     "LIGHTUP_DB": self.config["LIGHTUP_DB"],
                     "LIGHTUP_TRUSTED_PROXY_IP": "203.0.113.3"}):
            with self.subTest(config=cfg), patch(
                "lightup.webapp.production.DomainStore"
            ) as store:
                with self.assertRaises(ValueError):
                    create_fixed_header_opaque_production_app(cfg)
                store.assert_not_called()

    def test_real_authenticated_unknown_client_returns_constant_400(self):
        status, headers, body = self.request(
            path="/clients/" + self.PRIVATE, token=self.op_token)
        self.assertEqual(status, "400 Bad Request")
        self.assertNotIn(self.PRIVATE.encode(), body)
        self.assertNotIn(b"unknown client", body)
        self.assertIn(b"Request failed", body)
        self.assertEqual(int(self.as_dict(headers)["Content-Length"]), len(body))
        self.assertEqual(len(headers), len(set(k.lower() for k, _ in headers)))

    def test_real_invalid_form_is_private_and_no_mutation(self):
        old = len(self.store.list_clients(self.ctx))
        status, headers, body = self.request(
            "POST", "/clients", {"name": "", "csrf": self.op_csrf},
            self.op_token)
        self.assertEqual(status, "400 Bad Request")
        self.assertNotIn(b"client name is required", body)
        self.assertEqual(self.as_dict(headers)["Cache-Control"], "no-store")
        self.assertEqual(len(self.store.list_clients(self.ctx)), old)

    def test_fixed_400_security_headers_are_stricter_than_default(self):
        status, headers, body = self.request(
            path="/clients/" + self.PRIVATE, token=self.op_token)
        self.assertEqual(status, "400 Bad Request")
        h = self.as_dict(headers)
        self.assertEqual(h["Content-Type"], "text/html; charset=utf-8")
        self.assertEqual(h["Strict-Transport-Security"], "max-age=31536000")
        self.assertEqual(h["Cache-Control"], "no-store")
        self.assertEqual(h["Pragma"], "no-cache")
        self.assertEqual(h["Referrer-Policy"], "no-referrer")
        self.assertEqual(h["X-Content-Type-Options"], "nosniff")
        self.assertEqual(h["X-Frame-Options"], "DENY")
        self.assertIn("default-src 'none'", h["Content-Security-Policy"])
        self.assertIn("form-action 'none'", h["Content-Security-Policy"])
        self.assertNotIn("script-src 'unsafe-inline'", h["Content-Security-Policy"])
        self.assertNotIn("Set-Cookie", h)
        self.assertNotIn("Location", h)
        self.assertEqual(int(h["Content-Length"]), len(body))

    def test_hostile_allowed_header_names_cannot_relax_private_400(self):
        # The parent opt-in forwarded values for certain permitted header NAMES.
        # This synthetic upstream intentionally supplies unsafe VALUES, plus
        # cookies/redirects/duplicate headers. No installed ingress is tested.
        def hostile(_environ, start_response):
            start_response("400 Bad Request", [
                ("Cache-Control", "public, max-age=86400"),
                ("Cache-Control", "public"),
                ("Content-Security-Policy", "default-src *; script-src 'unsafe-inline'"),
                ("Strict-Transport-Security", "max-age=0"),
                ("X-Frame-Options", "ALLOWALL"),
                ("Referrer-Policy", "unsafe-url"),
                ("X-Content-Type-Options", "disabled"),
                ("Content-Type", "text/plain"),
                ("Content-Length", "100000"),
                ("Set-Cookie", "auth=" + self.PRIVATE),
                ("Location", "https://evil.example.test/" + self.PRIVATE),
                ("X-Private", self.PRIVATE),
            ])
            return [self.PRIVATE.encode("utf-8")]

        self.app._app._app = hostile
        status, headers, body = self.request()
        self.assertEqual(status, "400 Bad Request")
        self.assertNotIn(self.PRIVATE.encode(), body)
        h = self.as_dict(headers)
        self.assertEqual(h["Cache-Control"], "no-store")
        self.assertEqual(h["Strict-Transport-Security"], "max-age=31536000")
        self.assertEqual(h["X-Frame-Options"], "DENY")
        self.assertEqual(h["Referrer-Policy"], "no-referrer")
        self.assertEqual(h["X-Content-Type-Options"], "nosniff")
        self.assertEqual(h["Content-Security-Policy"].split(";")[0], "default-src 'none'")
        self.assertNotIn("Location", h)
        self.assertNotIn("Set-Cookie", h)
        self.assertNotIn("X-Private", h)
        self.assertEqual(len(headers), len(set(key.lower() for key, _ in headers)))
        self.assertEqual(int(h["Content-Length"]), len(body))

    def test_consecutive_private_400_responses_are_identical(self):
        first = self.request(path="/clients/" + self.PRIVATE, token=self.op_token)
        second = self.request("POST", "/clients",
                              {"name": "", "csrf": self.op_csrf}, self.op_token)
        self.assertEqual(first, second)

    def test_authorized_get_has_identical_status_headers_and_bytes(self):
        bare = create_opaque_production_app(self.config)
        plain = self.request(token=self.op_token, app=bare)
        strict = self.request(token=self.op_token)
        self.assertEqual(strict, plain)
        self.assertEqual(strict[0], "200 OK")

    def test_valid_operator_post_persists_and_redirect_unchanged(self):
        before = len(self.store.list_clients(self.ctx))
        status, headers, _ = self.request(
            "POST", "/clients", {"name": "Valid", "csrf": self.op_csrf},
            self.op_token)
        self.assertEqual(status, "303 See Other")
        self.assertEqual(self.as_dict(headers)["Location"], "/clients")
        self.assertEqual(len(self.store.list_clients(self.ctx)), before + 1)

    def test_cross_origin_and_proxy_impersonation_never_mutate(self):
        before = len(self.store.list_clients(self.ctx))
        changes = (
            {"HTTP_ORIGIN": "https://bad.example.test"},
            {"HTTP_SEC_FETCH_SITE": "cross-site"},
            {"REMOTE_ADDR": "192.0.2.3", "HTTP_X_FORWARDED_FOR": "127.0.0.1"},
            {"HTTP_X_FORWARDED_PROTO": "http"},
            {"HTTP_HOST": "bad.example.test"},
        )
        for override in changes:
            with self.subTest(override=override):
                status, _, _ = self.request(
                    "POST", "/clients", {"name": "Bad", "csrf": self.op_csrf},
                    self.op_token, override)
                self.assertEqual(status, "403 Forbidden")
        self.assertEqual(len(self.store.list_clients(self.ctx)), before)

    def test_wrong_csrf_and_client_role_cannot_create(self):
        before = len(self.store.list_clients(self.ctx))
        for token, csrf in ((self.op_token, "incorrect"),
                            (self.client_token, self.client_csrf)):
            status, _, _ = self.request(
                "POST", "/clients", {"name": "Invalid", "csrf": csrf}, token)
            self.assertEqual(status, "403 Forbidden")
        self.assertEqual(len(self.store.list_clients(self.ctx)), before)

    def test_anonymous_and_client_visibility_unchanged(self):
        anonymous = self.request(path="/clients/" + self.PRIVATE)
        tenant = self.request(path="/clients/" + self.PRIVATE,
                              token=self.client_token)
        self.assertEqual(anonymous[0], "303 See Other")
        self.assertEqual(tenant[0], "403 Forbidden")
        self.assertNotIn(self.PRIVATE.encode(), anonymous[2])
        self.assertNotIn(self.PRIVATE.encode(), tenant[2])

    def test_login_and_logout_cookies_are_preserved_for_non400(self):
        status, h, _ = self.request("POST", "/login", {
            "email": "op-fixed@lightup.test", "password": "synthetic-password"})
        self.assertEqual(status, "303 See Other")
        cookie = self.as_dict(h)["Set-Cookie"]
        self.assertIn("Secure", cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        status, h, _ = self.request(
            "POST", "/logout", {"csrf": self.op_csrf}, self.op_token)
        self.assertEqual(status, "303 See Other")
        self.assertIn("Max-Age=0", self.as_dict(h)["Set-Cookie"])
        self.assertIsNone(self.store.session_context(self.op_token))

    def test_rejected_origin_precedes_body_read_and_session_lookup(self):
        stream = Mock()
        env = {
            "HTTP_HOST": "lightup.example.test",
            "REMOTE_ADDR": "127.0.0.1",
            "HTTP_X_FORWARDED_PROTO": "https",
            "HTTP_ORIGIN": "https://evil.example.test",
            "REQUEST_METHOD": "POST",
            "PATH_INFO": "/clients",
            "CONTENT_LENGTH": "1234567",
            "CONTENT_TYPE": "application/x-www-form-urlencoded",
            "HTTP_COOKIE": "lightup_session=" + self.op_token,
            "wsgi.input": stream,
        }
        received = {}
        with patch.object(self.store, "session_context") as resolve:
            payload = b"".join(self.app(
                env, lambda s, h: received.update(status=s, headers=dict(h))))
            resolve.assert_not_called()
        stream.read.assert_not_called()
        self.assertEqual(received["status"], "403 Forbidden")
        self.assertNotIn(self.PRIVATE.encode(), payload)


if __name__ == "__main__":
    unittest.main()
