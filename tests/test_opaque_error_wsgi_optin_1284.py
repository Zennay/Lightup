"""Real in-process WSGI acceptance for the explicitly opt-in #1284 wrapper."""
from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlencode

from lightup.domain import DomainStore, Role
from lightup.webapp import create_app
from lightup.webapp.opaque_error_wsgi_optin import OpaqueErrorWSGI


class OpaqueErrorWsgi1284Tests(unittest.TestCase):
    PRIVATE_MARKER = "PrivateMarkerShouldNeverReachClient1284"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = DomainStore(Path(self.tmp.name) / "privacy-optin.sqlite3")
        self.original = create_app(self.store)
        self.app = OpaqueErrorWSGI(self.original)
        self.operator_user = self.store.bootstrap_operator(
            "operator-optin@lightup.test", "Operator", "test-password")
        self.ctx = self.store.context_for_user(self.operator_user.user_id)
        self.client = self.store.create_client(self.ctx, "Tenant Optin")
        client_user = self.store.create_user(
            self.ctx, "tenant-optin@lightup.test", "Client User",
            Role.CLIENT_ADMIN, self.client.client_id)
        self.operator_token, self.operator_csrf = self.store.create_session(
            self.operator_user.user_id)
        self.client_token, self.client_csrf = self.store.create_session(
            client_user.user_id)

    def request(self, app, method, path, form=None, token=None, csrf=None):
        fields = dict(form or {})
        if csrf is not None:
            fields["csrf"] = csrf
        data = urlencode(fields).encode("utf-8")
        env = {
            "REQUEST_METHOD": method, "PATH_INFO": path,
            "CONTENT_LENGTH": str(len(data)),
            "CONTENT_TYPE": "application/x-www-form-urlencoded",
            "wsgi.input": io.BytesIO(data),
        }
        if token:
            env["HTTP_COOKIE"] = f"lightup_session={token}"
        response = {}
        body = b"".join(app(
            env, lambda status, headers: response.update(
                status=status, headers=dict(headers))))
        return response["status"], response["headers"], body

    def test_exact_webapp_instance_required(self):
        with self.assertRaises(TypeError):
            OpaqueErrorWSGI(object())
        with self.assertRaises(TypeError):
            OpaqueErrorWSGI(None)

    def test_real_operator_unknown_client_is_constant_private_400(self):
        status, headers, body = self.request(
            self.app, "GET", "/clients/" + self.PRIVATE_MARKER,
            token=self.operator_token)
        self.assertEqual(status, "400 Bad Request")
        self.assertNotIn(self.PRIVATE_MARKER.encode(), body)
        self.assertNotIn(b"unknown client", body)
        self.assertNotIn(b"Traceback", body)
        self.assertIn(b"Request failed", body)
        self.assertEqual(int(headers["Content-Length"]), len(body))
        self.assertEqual(headers["Content-Type"], "text/html; charset=utf-8")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])

    def test_real_operator_invalid_form_error_is_nonleaking(self):
        before = len(self.store.list_clients(self.ctx))
        status, headers, body = self.request(
            self.app, "POST", "/clients", {"name": ""},
            token=self.operator_token, csrf=self.operator_csrf)
        self.assertEqual(status, "400 Bad Request")
        self.assertNotIn(b"client name is required", body)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(len(self.store.list_clients(self.ctx)), before)

    def test_original_default_still_exposes_private_marker(self):
        # Important: this optional wrapper does not repair default factory.
        status, _, body = self.request(
            self.original, "GET", "/clients/" + self.PRIVATE_MARKER,
            token=self.operator_token)
        self.assertEqual(status, "400 Bad Request")
        self.assertIn(self.PRIVATE_MARKER.encode(), body)

    def test_normal_authorized_get_passes_through_unchanged(self):
        original = self.request(
            self.original, "GET", "/clients", token=self.operator_token)
        wrapped = self.request(
            self.app, "GET", "/clients", token=self.operator_token)
        self.assertEqual(wrapped, original)
        self.assertEqual(wrapped[0], "200 OK")
        self.assertIn(b"Tenant Optin", wrapped[2])

    def test_anonymous_denial_is_preserved(self):
        original = self.request(
            self.original, "GET", "/clients/" + self.PRIVATE_MARKER)
        wrapped = self.request(
            self.app, "GET", "/clients/" + self.PRIVATE_MARKER)
        self.assertEqual(wrapped, original)
        self.assertEqual(wrapped[0], "303 See Other")
        self.assertNotIn(self.PRIVATE_MARKER.encode(), wrapped[2])

    def test_nonoperator_denial_is_preserved(self):
        original = self.request(
            self.original, "GET", "/clients/" + self.PRIVATE_MARKER,
            token=self.client_token)
        wrapped = self.request(
            self.app, "GET", "/clients/" + self.PRIVATE_MARKER,
            token=self.client_token)
        self.assertEqual(wrapped, original)
        self.assertEqual(wrapped[0], "403 Forbidden")

    def test_bad_csrf_is_preserved_without_mutation(self):
        before = len(self.store.list_clients(self.ctx))
        status, _, body = self.request(
            self.app, "POST", "/clients", {"name": "Forbidden new tenant"},
            token=self.operator_token, csrf="invalid")
        self.assertEqual(status, "403 Forbidden")
        self.assertNotIn(b"Forbidden new tenant", body)
        self.assertEqual(len(self.store.list_clients(self.ctx)), before)

    def test_valid_csrf_and_post_are_preserved(self):
        before = len(self.store.list_clients(self.ctx))
        status, headers, _ = self.request(
            self.app, "POST", "/clients", {"name": "Authorized new tenant"},
            token=self.operator_token, csrf=self.operator_csrf)
        self.assertEqual(status, "303 See Other")
        self.assertEqual(headers["Location"], "/clients")
        self.assertEqual(len(self.store.list_clients(self.ctx)), before + 1)

    def test_session_kept_after_sanitized_error(self):
        self.request(self.app, "GET", "/clients/" + self.PRIVATE_MARKER,
                     token=self.operator_token)
        self.assertIsNotNone(self.store.session_context(self.operator_token))
        status, _, _ = self.request(
            self.app, "GET", "/clients", token=self.operator_token)
        self.assertEqual(status, "200 OK")


    def test_synthetic_400_strips_untrusted_response_headers(self):
        # Inject only a fake WSGI response into a disposable wrapper instance.
        # This is NOT a claim the default app currently emits these headers.
        def fake_original(_environ, start_response):
            start_response("400 Bad Request", [
                ("Content-Type", "text/plain"),
                ("Content-Length", "9999"),
                ("X-Internal-Trace", self.PRIVATE_MARKER),
                ("Location", "/private-debug"),
                ("Set-Cookie", "internal_session=secret"),
                ("ETag", self.PRIVATE_MARKER),
                ("Cache-Control", "no-store"),
                ("Strict-Transport-Security", "max-age=31536000"),
            ])
            return [self.PRIVATE_MARKER.encode("utf-8")]

        self.app._app = fake_original
        status, headers, body = self.request(self.app, "GET", "/clients")
        self.assertEqual(status, "400 Bad Request")
        self.assertNotIn(self.PRIVATE_MARKER.encode(), body)
        self.assertNotIn("X-Internal-Trace", headers)
        self.assertNotIn("Location", headers)
        self.assertNotIn("Set-Cookie", headers)
        self.assertNotIn("ETag", headers)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["Strict-Transport-Security"], "max-age=31536000")
        self.assertEqual(int(headers["Content-Length"]), len(body))


if __name__ == "__main__":
    unittest.main()
