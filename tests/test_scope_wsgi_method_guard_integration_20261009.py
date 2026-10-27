"""Real LightUp WSGI/SQLite method guard tests; entirely offline and inert."""
from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlencode

from lightup.domain import DomainStore, Role
from lightup.webapp import create_app
from lightup.webapp.security import WebSecurity
from lightup.webapp.method_guard import (
    CanonicalMethodGuard, MethodRejected, canonical_request_method,
)
from lightup.webapp.method_guarded_production import create_method_guarded_production_app


class CanonicalMethodContractTest(unittest.TestCase):
    def test_exact_methods_only(self):
        for method in ("GET", "POST"):
            self.assertEqual(canonical_request_method({"REQUEST_METHOD": method}), method)

    def test_no_lowercase_alias_or_unrecognized_method(self):
        for method in ("get", "post", "GeT", "PoSt", "HEAD", "OPTIONS", "DELETE", "PATCH"):
            with self.subTest(method=method), self.assertRaises(MethodRejected) as ctx:
                canonical_request_method({"REQUEST_METHOD": method})
            self.assertEqual(ctx.exception.status, "405 Method Not Allowed")

    def test_fail_closed_on_noncanonical_types_and_bytes(self):
        class MethodSubclass(str):
            pass
        for value in (None, b"POST", 0, True, ["POST"], MethodSubclass("POST"),
                      "", "POST\n", "GET\r", "POST ", " POST", "PÖST", "GET/POST",
                      "P" * 33, "POST\x00"):
            with self.subTest(value=repr(value)), self.assertRaises(MethodRejected) as ctx:
                canonical_request_method({"REQUEST_METHOD": value})
            self.assertEqual(ctx.exception.status, "400 Bad Request")
        with self.assertRaises(MethodRejected):
            canonical_request_method({})

    def test_production_flag_is_exact_builtin_boolean(self):
        for value in ("true", 1, None, 0, object()):
            with self.subTest(value=repr(value)), self.assertRaises(ValueError):
                CanonicalMethodGuard(lambda *_: [], production=value)


class MethodGuardRealWebAppTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "domain.sqlite"
        self.store = DomainStore(self.db)
        self.op_user = self.store.bootstrap_operator(
            "operator@lightup.test", "Operator", "example-secret-password")
        self.operator = self.store.context_for_user(self.op_user.user_id)
        self.op_token, self.op_csrf = self.store.create_session(self.op_user.user_id)
        client = self.store.create_client(self.operator, "Existing Test Tenant")
        self.client_id = client.client_id
        user = self.store.create_user(self.operator, "client@lightup.test", "Client",
                                      Role.CLIENT_ADMIN, self.client_id)
        self.client_token, self.client_csrf = self.store.create_session(user.user_id)

    def tearDown(self):
        self.tmp.cleanup()

    def make_app(self, production):
        sec = WebSecurity("https://lightup.example", "127.0.0.1") if production else None
        return CanonicalMethodGuard(create_app(self.store, sec), production=production)

    def call(self, app, method, path, *, production=False, token=None,
             csrf=None, fields=None, stream=None):
        data = dict(fields or {})
        if csrf is not None:
            data["csrf"] = csrf
        body = urlencode(data).encode("utf-8")
        env = {
            "PATH_INFO": path,
            "CONTENT_LENGTH": str(len(body)),
            "CONTENT_TYPE": "application/x-www-form-urlencoded",
            "wsgi.input": io.BytesIO(body) if stream is None else stream,
            "HTTP_HOST": "lightup.example" if production else "localhost",
        }
        if method is not None:
            env["REQUEST_METHOD"] = method
        if token is not None:
            env["HTTP_COOKIE"] = "lightup_session=" + token
        if production:
            env.update(REMOTE_ADDR="127.0.0.1",
                       HTTP_X_FORWARDED_PROTO="https",
                       HTTP_ORIGIN="https://lightup.example")
        captured = {}
        payload = b"".join(app(env, lambda status, headers:
                               captured.update(status=status, headers=dict(headers))))
        return captured["status"], captured["headers"], payload

    def test_denied_methods_never_authenticate_or_mutate_clients(self):
        cases = ("post", "PoSt", "get", "GeT", "DELETE", "OPTIONS",
                 b"POST", 99, "POST\n", "GET ", "POST\x00", None)
        initial_clients = len(self.store.list_clients(self.operator))
        for production in (False, True):
            app = self.make_app(production)
            for method in cases:
                with self.subTest(production=production, method=repr(method)):
                    with patch.object(self.store, "session_context") as lookup:
                        status, headers, payload = self.call(
                            app, method, "/clients", production=production,
                            token=self.op_token, csrf=self.op_csrf,
                            fields={"name": "Should Not Exist"})
                        lookup.assert_not_called()
                    self.assertIn(status.split()[0], ("400", "405"))
                    self.assertEqual(headers["Cache-Control"], "no-store")
                    self.assertEqual(headers["X-Frame-Options"], "DENY")
                    self.assertNotIn(b"Overview", payload)
                    self.assertNotIn("Set-Cookie", headers)
                    self.assertEqual("Strict-Transport-Security" in headers, production)
        self.assertEqual(len(self.store.list_clients(self.operator)), initial_clients)
        self.assertIsNotNone(self.store.session_context(self.op_token))

    def test_denied_logout_cannot_revoke_operator_or_tenant_session(self):
        for production in (False, True):
            app = self.make_app(production)
            for method in ("post", "PoSt", "POST\n", "DELETE"):
                with self.subTest(production=production, method=repr(method)):
                    status, _, _ = self.call(
                        app, method, "/logout", production=production,
                        token=self.op_token, csrf=self.op_csrf)
                    self.assertIn(status.split()[0], ("400", "405"))
                    self.assertIsNotNone(self.store.session_context(self.op_token))
                    self.assertIsNotNone(self.store.session_context(self.client_token))

    def test_denial_is_before_body_or_downstream_app(self):
        class Unreadable:
            def read(self, *_):
                raise AssertionError("denied method must not read body")
        def must_not_enter(*_):
            raise AssertionError("denied method entered app")
        for production in (False, True):
            guard = CanonicalMethodGuard(must_not_enter, production=production)
            for method in (b"POST", "post", None, "POST\n", "OPTIONS"):
                with self.subTest(production=production, method=repr(method)):
                    status, headers, payload = self.call(
                        guard, method, "/clients", production=production,
                        stream=Unreadable(), token=self.op_token,
                        csrf=self.op_csrf, fields={"name": "No"})
                    self.assertIn(status.split()[0], ("400", "405"))
                    self.assertEqual(payload, b"Request rejected")
                    self.assertNotIn("Set-Cookie", headers)
                    self.assertEqual(headers["Content-Length"], str(len(payload)))

    def test_valid_operator_and_tenant_roles_still_enforced(self):
        before = len(self.store.list_clients(self.operator))
        for production in (False, True):
            app = self.make_app(production)
            status, _, payload = self.call(
                app, "GET", "/", production=production, token=self.op_token)
            self.assertEqual(status, "200 OK")
            self.assertIn(b"LightUp", payload)
            status, _, _ = self.call(
                app, "POST", "/clients", production=production,
                token=self.client_token, csrf=self.client_csrf,
                fields={"name": "Unauthorized"})
            self.assertEqual(status, "403 Forbidden")
            status, _, _ = self.call(
                app, "POST", "/clients", production=production,
                token=self.op_token, csrf="invalid",
                fields={"name": "Bad CSRF"})
            self.assertEqual(status, "403 Forbidden")
            status, _, _ = self.call(
                app, "POST", "/clients", production=production,
                token=self.op_token, csrf=self.op_csrf,
                fields={"name": "Approved " + ("Production" if production else "Development")})
            self.assertEqual(status, "303 See Other")
        self.assertEqual(len(self.store.list_clients(self.operator)), before + 2)

    def test_real_opt_in_production_factory_rejects_before_app(self):
        config = {"LIGHTUP_PUBLIC_ORIGIN": "https://lightup.example",
                  "LIGHTUP_DB": str(self.db)}
        app = create_method_guarded_production_app(config)
        self.assertIsInstance(app, CanonicalMethodGuard)
        status, headers, _ = self.call(
            app, "post", "/logout", production=True,
            token=self.op_token, csrf=self.op_csrf)
        self.assertEqual(status, "405 Method Not Allowed")
        self.assertEqual(headers["Strict-Transport-Security"], "max-age=31536000")
        self.assertEqual(headers["Allow"], "GET, POST")
        self.assertIsNotNone(self.store.session_context(self.op_token))
        status, headers, _ = self.call(app, "GET", "/login", production=True)
        self.assertEqual(status, "200 OK")
        self.assertIn("Strict-Transport-Security", headers)

    def test_invalid_production_configuration_stays_closed(self):
        for config in ({}, {"LIGHTUP_PUBLIC_ORIGIN": "http://lightup.example",
                            "LIGHTUP_DB": str(self.db)},
                       {"LIGHTUP_PUBLIC_ORIGIN": "https://lightup.example",
                        "LIGHTUP_DB": "relative.db"}):
            with self.subTest(config=config), self.assertRaises(ValueError):
                create_method_guarded_production_app(config)


if __name__ == "__main__":
    unittest.main()
