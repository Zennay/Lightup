"""Real LightUp WSGI/SQLite regression for opt-in cookie envelope admission.

No listening sockets, external assets, grants, scanners or deployment.
"""
from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.parse import urlencode

from lightup.domain import DomainStore, Role
from lightup.webapp import create_app
from lightup.webapp.session_cookie_guard import (
    CookieEnvelopeGuard,
    create_cookie_guarded_production_app,
    validate_cookie_envelope,
)


class SessionCookieGuardTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def fixtures(self, production):
        db_path = str(Path(self.tmp.name) / ("prod.db" if production else "dev.db"))
        if production:
            app = create_cookie_guarded_production_app({
                "LIGHTUP_PUBLIC_ORIGIN": "https://lightup.example.test",
                "LIGHTUP_DB": db_path,
            })
            store = app.app.store
        else:
            store = DomainStore(db_path)
            app = CookieEnvelopeGuard(create_app(store))
        operator = store.bootstrap_operator(
            "operator@lightup.test", "Operator", "operator-fixture-password")
        context = store.context_for_user(operator.user_id)
        client = store.create_client(context, "Existing tenant")
        tenant_user = store.create_user(
            context, "tenant@lightup.test", "Tenant", Role.CLIENT_ADMIN,
            client.client_id)
        operator_cookie, operator_csrf = store.create_session(operator.user_id)
        tenant_cookie, tenant_csrf = store.create_session(tenant_user.user_id)
        return (app, store, context, operator_cookie, operator_csrf,
                tenant_cookie, tenant_csrf)

    @staticmethod
    def request(app, production, path="/", method="GET", raw_cookie=None,
                form=None, stream=None):
        body = urlencode(form or {}).encode("utf-8")
        env = {
            "REQUEST_METHOD": method, "PATH_INFO": path,
            "CONTENT_TYPE": "application/x-www-form-urlencoded",
            "CONTENT_LENGTH": str(len(body)),
            "wsgi.input": io.BytesIO(body) if stream is None else stream,
        }
        if production:
            env.update({
                "REMOTE_ADDR": "127.0.0.1",
                "HTTP_HOST": "lightup.example.test",
                "HTTP_X_FORWARDED_PROTO": "https",
                "HTTP_ORIGIN": "https://lightup.example.test",
            })
        if raw_cookie is not None:
            env["HTTP_COOKIE"] = raw_cookie
        output = {}

        def start_response(status, headers):
            output["status"] = status
            output["headers"] = dict(headers)

        output["body"] = b"".join(app(env, start_response))
        return output

    def test_guard_denies_noncanonical_cookie_before_delegate(self):
        sentinel = Mock(return_value=[b"delegated"])
        guard = CookieEnvelopeGuard(sentinel, production=True)
        cases = [
            b"lightup_session=abc",  # not a built-in WSGI str
            123, ["lightup_session=abc"],
            type("FakeStr", (str,), {})("lightup_session=abc"),
            "lightup_session=foo; lightup_session=bar",
            "lightup_session=foo;lightup_session=foo",
            "lightup_session=foo, lightup_session=bar",
            "lightup_session=foo lightup_session=bar",
            "unrelated=da rk; lightup_session=bar",
            "lightup_session=foo\r\nX-Auth: operator",
            "lightup_session=foo\x00evil",
            "lightup_session=foo\tother",
            "theme=\"value;lightup_session=foo\"",
            "lightup_session=foo\\;lightup_session=bar",
            "lightup_session=foo; invalid",
            "lightup_session=foo;;theme=dark",
            "lightup_session =foo",
            "theme=dark;lightup_session=foo" + "x" * 8192,
        ]
        for value in cases:
            with self.subTest(cookie=repr(value)[:80]):
                output = {}
                env = {"HTTP_COOKIE": value, "wsgi.input": Mock()}
                guard(env, lambda s, h: output.update(status=s, headers=dict(h)))
                self.assertEqual(output["status"], "400 Bad Request")
                self.assertEqual(output["headers"]["Cache-Control"], "no-store")
                self.assertEqual(output["headers"]["Strict-Transport-Security"],
                                 "max-age=31536000")
                self.assertNotIn("Set-Cookie", output["headers"])
                sentinel.assert_not_called()
                env["wsgi.input"].read.assert_not_called()

    def test_valid_and_missing_envelopes_are_accepted(self):
        canonical = "A" * 43
        for value in (f"lightup_session={canonical}",
                      f"theme=dark; lightup_session={canonical}",
                      "unrelated=x=y", ""):
            with self.subTest(value=value):
                validate_cookie_envelope({"HTTP_COOKIE": value})
        validate_cookie_envelope({})
        for production in (0, 1, "true", None):
            with self.subTest(production=production):
                with self.assertRaises(ValueError):
                    CookieEnvelopeGuard(Mock(), production=production)

    def test_invalid_opaque_session_shapes_deny_before_real_sqlite_lookup(self):
        """Token structure is a prerequisite; a valid shape is NOT authority."""
        for production in (False, True):
            with self.subTest(production=production):
                (app, store, context, op_token, op_csrf, client_token,
                 client_csrf) = self.fixtures(production)
                self.assertEqual(len(op_token), 43)
                cases = [
                    op_token[:-1],                    # truncated
                    op_token + "A",                   # appended
                    op_token + "=",                   # padding
                    op_token[:12] + "%" + op_token[13:],  # percent encoding
                    op_token[:12] + "." + op_token[13:],  # wrong alphabet
                    op_token[:12] + "é" + op_token[13:],  # latin-1 high byte
                    "", "not-a-session",              # blank/short
                ]
                for token in cases:
                    cookie = f"theme=light; lightup_session={token}"
                    for path, method, form in (
                        ("/", "GET", None),
                        ("/clients", "POST", {"name": "Invalid", "csrf": op_csrf}),
                        ("/logout", "POST", {"csrf": op_csrf}),
                    ):
                        with self.subTest(shape=repr(token), path=path,
                                          method=method):
                            stream = Mock()
                            with patch.object(store, "session_context") as lookup:
                                response = self.request(app, production, path,
                                                        method, cookie, form, stream)
                                lookup.assert_not_called()
                            stream.read.assert_not_called()
                            self.assertEqual(response["status"], "400 Bad Request")
                            self.assertNotIn("Set-Cookie", response["headers"])
                            self.assertEqual(len(store.list_clients(context)), 1)
                # A token-like value with correct syntax is still not an
                # authentication decision; the actual session DB remains source.
                fake = "A" * 43
                response = self.request(app, production, "/",
                                        raw_cookie=f"lightup_session={fake}")
                self.assertEqual(response["status"], "303 See Other")
                self.assertEqual(response["headers"]["Location"], "/login")
                self.assertIsNotNone(store.session_context(op_token))
                self.assertIsNotNone(store.session_context(client_token))

    def test_real_sqlite_denials_keep_sessions_rows_and_body_untouched(self):
        for production in (False, True):
            with self.subTest(production=production):
                (app, store, context, op_token, op_csrf, client_token,
                 client_csrf) = self.fixtures(production)
                baseline = len(store.list_clients(context))
                invalid = [
                    f"lightup_session={client_token}; lightup_session={op_token}",
                    f"lightup_session={op_token}; lightup_session={client_token}",
                    f"lightup_session={op_token}, lightup_session={client_token}",
                    f"lightup_session={client_token} lightup_session={op_token}",
                    f"lightup_session={op_token}\nX-Admin: true",
                    b"lightup_session=foreign",
                    "lightup_session=x" * 2000,
                ]
                for cookie in invalid:
                    for path, method, form in [
                        ("/", "GET", None),
                        ("/clients", "POST", {"name": "Injected", "csrf": op_csrf}),
                        ("/logout", "POST", {"csrf": op_csrf}),
                    ]:
                        with self.subTest(cookie=repr(cookie)[:40],
                                          path=path, method=method):
                            stream = Mock()
                            with patch.object(store, "session_context",
                                              wraps=store.session_context) as lookup:
                                with patch.object(store, "revoke_session",
                                                  wraps=store.revoke_session) as revoke:
                                    res = self.request(
                                        app, production, path, method, cookie,
                                        form, stream)
                                    lookup.assert_not_called()
                                    revoke.assert_not_called()
                            stream.read.assert_not_called()
                            self.assertEqual(res["status"], "400 Bad Request")
                            self.assertEqual(res["headers"]["Cache-Control"], "no-store")
                            self.assertNotIn("Set-Cookie", res["headers"])
                            self.assertEqual(
                                "Strict-Transport-Security" in res["headers"],
                                production)
                            self.assertEqual(len(store.list_clients(context)), baseline)
                            self.assertIsNotNone(store.session_context(op_token))
                            self.assertIsNotNone(store.session_context(client_token))

    def test_real_sqlite_positive_csrf_and_role_controls_preserved(self):
        for production in (False, True):
            with self.subTest(production=production):
                (app, store, context, op_token, op_csrf, client_token,
                 client_csrf) = self.fixtures(production)
                self.assertEqual(
                    self.request(app, production, "/", raw_cookie=
                                 f"theme=light; lightup_session={op_token}")["status"],
                    "200 OK")
                self.assertEqual(self.request(
                    app, production, "/", raw_cookie=
                    f"lightup_session={client_token}")["status"], "403 Forbidden")
                denied = self.request(
                    app, production, "/clients", "POST",
                    f"lightup_session={op_token}", {"name": "Denied"})
                self.assertEqual(denied["status"], "403 Forbidden")
                rejected_role = self.request(
                    app, production, "/clients", "POST",
                    f"lightup_session={client_token}",
                    {"name": "Denied", "csrf": client_csrf})
                self.assertEqual(rejected_role["status"], "403 Forbidden")
                self.assertEqual(len(store.list_clients(context)), 1)
                approved = self.request(
                    app, production, "/clients", "POST",
                    f"lightup_session={op_token}",
                    {"name": "Allowed", "csrf": op_csrf})
                self.assertEqual(approved["status"], "303 See Other")
                self.assertEqual(len(store.list_clients(context)), 2)

    def test_duplicate_cookie_login_cannot_rotate_or_create_session(self):
        # Even valid login credentials cannot make an ambiguous existing
        # session cookie a selector for which old session should be revoked.
        for production in (False, True):
            with self.subTest(production=production):
                (app, store, context, op_token, op_csrf, client_token,
                 client_csrf) = self.fixtures(production)
                cookies = [
                    f"lightup_session={client_token}; lightup_session={op_token}",
                    f"lightup_session={op_token}; lightup_session={client_token}",
                ]
                for cookie in cookies:
                    with self.subTest(cookie=cookie[:24]):
                        with patch.object(store, "authenticate",
                                          wraps=store.authenticate) as authn:
                            with patch.object(store, "revoke_session",
                                              wraps=store.revoke_session) as revoke:
                                with patch.object(store, "create_session",
                                                  wraps=store.create_session) as create:
                                    result = self.request(
                                        app, production, "/login", "POST",
                                        cookie, {
                                            "email": "operator@lightup.test",
                                            "password": "operator-fixture-password",
                                        })
                                    authn.assert_not_called()
                                    revoke.assert_not_called()
                                    create.assert_not_called()
                        self.assertEqual(result["status"], "400 Bad Request")
                        self.assertNotIn("Set-Cookie", result["headers"])
                        self.assertIsNotNone(store.session_context(op_token))
                        self.assertIsNotNone(store.session_context(client_token))

    def test_production_factory_remains_fail_closed_for_bad_configuration(self):
        with self.assertRaises(ValueError):
            create_cookie_guarded_production_app({})
        with self.assertRaises(ValueError):
            create_cookie_guarded_production_app({
                "LIGHTUP_PUBLIC_ORIGIN": "http://lightup.example.test",
                "LIGHTUP_DB": str(Path(self.tmp.name) / "bad.db"),
            })


if __name__ == "__main__":
    unittest.main()
