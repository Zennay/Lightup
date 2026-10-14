"""Offline/real-app acceptance for optional WSGI root-mount authorization boundary."""
from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.parse import urlencode

from lightup.domain import DomainStore, Role
from lightup.webapp import create_app
from lightup.webapp.root_mount_guard import RootMountGuard
from lightup.webapp.root_mount_guarded_production import create_root_mount_guarded_production_app
from lightup.webapp.security import WebSecurity


_MISSING = object()


class _StrSubclass(str):
    pass


class RootMountGuardIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = DomainStore(Path(self.tmp.name) / "lightup.db")
        self.user = self.store.bootstrap_operator(
            "operator@lightup.test", "Operator", "password-only-for-offline-tests"
        )
        self.context = self.store.context_for_user(self.user.user_id)
        self.token, self.csrf = self.store.create_session(self.user.user_id)

    def app(self, production):
        security = WebSecurity("https://lightup.example.test") if production else WebSecurity()
        return RootMountGuard(create_app(self.store, security), production=production)

    def request(self, *, production, method, path, mount=_MISSING, form=None,
                token=None, unreadable=False, headers=None):
        body = urlencode(form or {}).encode("ascii")
        stream = Mock() if unreadable else io.BytesIO(body)
        env = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "CONTENT_LENGTH": str(len(body)),
            "CONTENT_TYPE": "application/x-www-form-urlencoded",
            "wsgi.input": stream,
            "HTTP_HOST": "lightup.example.test" if production else "localhost",
            "REMOTE_ADDR": "127.0.0.1",
        }
        if production:
            env["HTTP_X_FORWARDED_PROTO"] = "https"
            if method == "POST":
                env["HTTP_ORIGIN"] = "https://lightup.example.test"
        if mount is not _MISSING:
            env["SCRIPT_NAME"] = mount
        if token is not None:
            env["HTTP_COOKIE"] = "lightup_session=" + token
        if headers:
            env.update(headers)
        captured = {}

        def respond(status, response_headers):
            captured["status"] = status
            captured["headers"] = dict(response_headers)

        result = b"".join(self.app(production)(env, respond))
        return captured["status"], captured["headers"], result, stream

    def test_noncanonical_script_name_denied_before_session_or_body(self):
        bad_values = (
            "/", "/lightup", "/clients", "//", "/../", "/lightup\n",
            " ", "", None, 0, False, b"", [], {},
            _StrSubclass(""), _StrSubclass("/lightup"),
        )
        # An exact empty built-in str is the one valid supplied mount.
        bad_values = tuple(item for item in bad_values if item != "" or type(item) is not str)
        for production in (False, True):
            for mount in bad_values:
                with self.subTest(production=production, mount=repr(mount)):
                    with patch.object(
                        self.store, "session_context", wraps=self.store.session_context
                    ) as session_lookup:
                        status, headers, body, stream = self.request(
                            production=production, method="POST", path="/clients",
                            mount=mount, form={"csrf": self.csrf, "name": "Injected"},
                            token=self.token, unreadable=True,
                        )
                        self.assertEqual(status, "400 Bad Request")
                        self.assertEqual(body, b"<h1>Bad request</h1>")
                        self.assertEqual(headers["Cache-Control"], "no-store")
                        self.assertIn("frame-ancestors 'none'",
                                      headers["Content-Security-Policy"])
                        self.assertEqual(headers["X-Frame-Options"], "DENY")
                        self.assertNotIn("Set-Cookie", headers)
                        self.assertEqual(headers.get("Strict-Transport-Security") is not None,
                                         production)
                        session_lookup.assert_not_called()
                        stream.read.assert_not_called()
                    self.assertEqual(self.store.list_clients(self.context), [])
                    self.assertIsNotNone(self.store.session_context(self.token))

    def test_bad_mount_does_not_revoke_session_on_logout(self):
        for production in (False, True):
            with self.subTest(production=production):
                with patch.object(
                    self.store, "revoke_session", wraps=self.store.revoke_session
                ) as revoke:
                    status, headers, _, _ = self.request(
                        production=production, method="POST", path="/logout",
                        mount="/admin", form={"csrf": self.csrf}, token=self.token,
                    )
                    self.assertEqual(status, "400 Bad Request")
                    self.assertNotIn("Set-Cookie", headers)
                    revoke.assert_not_called()
                self.assertIsNotNone(self.store.session_context(self.token))

    def test_bad_mount_cannot_rotate_session_through_login(self):
        for production in (False, True):
            with self.subTest(production=production):
                with patch.object(
                    self.store, "authenticate", wraps=self.store.authenticate
                ) as authenticate:
                    status, headers, _, _ = self.request(
                        production=production, method="POST", path="/login",
                        mount="/client", token=self.token,
                        form={"email": "operator@lightup.test",
                              "password": "password-only-for-offline-tests"},
                    )
                    self.assertEqual(status, "400 Bad Request")
                    self.assertNotIn("Set-Cookie", headers)
                    authenticate.assert_not_called()
                self.assertIsNotNone(self.store.session_context(self.token))

    def test_exact_root_mount_preserves_roles_csrf_and_operator_write(self):
        for production in (False, True):
            with self.subTest(production=production):
                for mount in (_MISSING, ""):
                    status, _, _, _ = self.request(
                        production=production, method="GET", path="/clients",
                        mount=mount, token=self.token,
                    )
                    self.assertEqual(status, "200 OK")
                denied, _, _, _ = self.request(
                    production=production, method="POST", path="/clients",
                    mount="", token=self.token, form={"name": "No CSRF"},
                )
                self.assertEqual(denied, "403 Forbidden")
                self.assertEqual(self.store.list_clients(self.context), [])
                ok, _, _, _ = self.request(
                    production=production, method="POST", path="/clients",
                    mount="", token=self.token,
                    form={"name": "Approved", "csrf": self.csrf},
                )
                self.assertEqual(ok, "303 See Other")
                self.assertEqual(len(self.store.list_clients(self.context)), 1)
                # Restore fixture before repeating under the other security mode.
                if not production:
                    self.store = DomainStore(Path(self.tmp.name) / "second-mode.db")
                    self.user = self.store.bootstrap_operator(
                        "operator@lightup.test", "Operator",
                        "password-only-for-offline-tests"
                    )
                    self.context = self.store.context_for_user(self.user.user_id)
                    self.token, self.csrf = self.store.create_session(self.user.user_id)

    def test_script_name_header_hints_are_not_mount_authority(self):
        for production in (False, True):
            with self.subTest(production=production):
                status, _, _, _ = self.request(
                    production=production, method="GET", path="/clients",
                    mount="", token=self.token,
                    headers={"HTTP_X_SCRIPT_NAME": "/operator",
                             "HTTP_X_FORWARDED_PREFIX": "/portal",
                             "HTTP_X_ORIGINAL_SCRIPT_NAME": "/operator"},
                )
                self.assertEqual(status, "200 OK")
                status, _, _, _ = self.request(
                    production=production, method="GET", path="/not-a-route",
                    mount="", token=self.token,
                    headers={"HTTP_X_SCRIPT_NAME": "/clients"},
                )
                self.assertEqual(status, "404 Not Found")

    def test_production_flag_must_be_exact_boolean(self):
        for invalid in ("false", 0, 1, None, [], _StrSubclass("true")):
            with self.subTest(invalid=repr(invalid)), self.assertRaises(TypeError):
                RootMountGuard(lambda _env, _start: [], production=invalid)



    def test_root_mount_keeps_client_tenant_and_role_boundaries(self):
        allowed = self.store.create_client(self.context, "Tenant One")
        other = self.store.create_client(self.context, "Tenant Two")
        user = self.store.create_user(
            self.context, "admin@tenant-one.test", "Tenant Admin",
            Role.CLIENT_ADMIN, allowed.client_id,
        )
        client_token, client_csrf = self.store.create_session(user.user_id)
        for production in (False, True):
            with self.subTest(production=production):
                # A prefix supplied by the caller never promotes a client
                # session into operator or cross-tenant authority.
                headers = {"HTTP_X_FORWARDED_PREFIX": "/admin",
                           "HTTP_X_SCRIPT_NAME": "/clients"}
                status, _, _, _ = self.request(
                    production=production, method="GET", path="/clients",
                    mount="", token=client_token, headers=headers,
                )
                self.assertEqual(status, "403 Forbidden")
                status, _, _, _ = self.request(
                    production=production, method="GET",
                    path=f"/portal/{other.client_id}",
                    mount="", token=client_token, headers=headers,
                )
                self.assertEqual(status, "403 Forbidden")
                status, _, _, _ = self.request(
                    production=production, method="POST", path="/clients",
                    mount="", token=client_token,
                    form={"csrf": client_csrf, "name": "Forbidden tenant"},
                    headers=headers,
                )
                self.assertEqual(status, "403 Forbidden")
                status, _, _, _ = self.request(
                    production=production, method="GET",
                    path=f"/portal/{allowed.client_id}",
                    mount="", token=client_token,
                )
                self.assertEqual(status, "200 OK")
                self.assertEqual(len(self.store.list_clients(self.context)), 2)

    def test_production_mode_cannot_disagree_with_wrapped_application(self):
        development = create_app(self.store, WebSecurity())
        production = create_app(
            self.store, WebSecurity("https://lightup.example.test")
        )
        with self.assertRaises(TypeError):
            RootMountGuard(development)
        with self.assertRaises(ValueError):
            RootMountGuard(development, production=True)
        with self.assertRaises(ValueError):
            RootMountGuard(production, production=False)
        self.assertIsInstance(RootMountGuard(production, production=True), RootMountGuard)


    def test_opt_in_real_production_factory_retains_existing_config_and_hsts(self):
        db = str(Path(self.tmp.name) / "root-guard-production.db")
        factory = create_root_mount_guarded_production_app({
            "LIGHTUP_PUBLIC_ORIGIN": "https://lightup.example.test",
            "LIGHTUP_DB": db,
        })
        self.assertIsInstance(factory, RootMountGuard)
        self.assertTrue(factory.production)
        self.assertTrue(factory.app.security.production)

        def invoke(script_name):
            headers = {}
            env = {
                "HTTP_HOST": "lightup.example.test",
                "HTTP_X_FORWARDED_PROTO": "https",
                "REMOTE_ADDR": "127.0.0.1",
                "REQUEST_METHOD": "GET",
                "PATH_INFO": "/login",
                "SCRIPT_NAME": script_name,
                "CONTENT_LENGTH": "0",
                "wsgi.input": io.BytesIO(b""),
            }
            response = b"".join(factory(
                env, lambda status, values: headers.update(
                    {"status": status, **dict(values)}
                ),
            ))
            return headers, response

        denied, payload = invoke("/external")
        self.assertEqual(denied["status"], "400 Bad Request")
        self.assertNotIn("Set-Cookie", denied)
        self.assertEqual(denied["Cache-Control"], "no-store")
        self.assertEqual(denied["Strict-Transport-Security"], "max-age=31536000")
        self.assertEqual(payload, b"<h1>Bad request</h1>")
        accepted, body = invoke("")
        self.assertEqual(accepted["status"], "200 OK")
        self.assertEqual(accepted["Strict-Transport-Security"], "max-age=31536000")
        self.assertIn(b"Sign in", body)
        for invalid in (
            {},
            {"LIGHTUP_PUBLIC_ORIGIN": "https://lightup.example.test",
             "LIGHTUP_DB": "relative.db"},
            {"LIGHTUP_PUBLIC_ORIGIN": "http://lightup.example.test",
             "LIGHTUP_DB": db},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                create_root_mount_guarded_production_app(invalid)

if __name__ == "__main__":
    unittest.main()
