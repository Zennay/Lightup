"""Fail-closed PATH_INFO type and routing-identity acceptance for real LightUp WSGI.

No sockets, remote targets, grants, deployment or synthetic authorization.
RED expected-failure tests document source-owned security gaps until integrated.
"""
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


class _PathSubclass(str):
    """Noncanonical path object must not inherit a trusted server path."""


class _NoReadStream:
    def read(self, amount=-1):
        raise AssertionError("Invalid PATH_INFO must be rejected before reading a body")


class PathInfoIdentityWSGITests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tempdir.name) / "lightup.db")
        op = self.store.bootstrap_operator(
            "operator@path.test", "Operator", "operator-password"
        )
        self.ctx = self.store.context_for_user(op.user_id)
        self.op_cookie, self.op_csrf = self.store.create_session(op.user_id)
        tenant = self.store.create_client(self.ctx, "Existing tenant")
        client = self.store.create_user(
            self.ctx, "client@path.test", "Client", Role.CLIENT_ADMIN, tenant.client_id
        )
        self.client_cookie, self.client_csrf = self.store.create_session(client.user_id)
        self.original_count = len(self.store.list_clients(self.ctx))

    def tearDown(self):
        self.tempdir.cleanup()

    def _app(self, production=False):
        security = (
            WebSecurity(public_origin="https://lightup.example", trusted_proxy_ip="127.0.0.1")
            if production else WebSecurity()
        )
        return create_app(self.store, security=security)

    def _env(self, path, *, method="POST", token=None, csrf=None,
             stream=None, production=False):
        fields = {"name": "Must Not Be Created"}
        if csrf is not None:
            fields["csrf"] = csrf
        body = urlencode(fields).encode("utf-8")
        env = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "CONTENT_LENGTH": str(len(body)),
            "CONTENT_TYPE": "application/x-www-form-urlencoded",
            "wsgi.input": stream if stream is not None else io.BytesIO(body),
        }
        if token is not None:
            env["HTTP_COOKIE"] = f"lightup_session={token}"
        if production:
            env.update({
                "REMOTE_ADDR": "127.0.0.1",
                "HTTP_X_FORWARDED_PROTO": "https",
                "HTTP_HOST": "lightup.example",
                "HTTP_ORIGIN": "https://lightup.example",
            })
        return env

    def _invoke(self, environ, *, production=False):
        capture = {}
        result = self._app(production)(
            environ, lambda status, headers: capture.update(
                status=status, headers=dict(headers)
            )
        )
        return capture["status"], capture["headers"], b"".join(result)

    def _assert_early_rejection(self, path, *, production=False):
        # Even a valid operator cookie and CSRF cannot make an invalid path
        # authoritative. The stream/session lookup must remain untouched.
        env = self._env(
            path, token=self.op_cookie, csrf=self.op_csrf,
            stream=_NoReadStream(), production=production
        )
        with patch.object(self.store, "session_context", wraps=self.store.session_context) as lookup:
            status, headers, _ = self._invoke(env, production=production)
            self.assertIn(status[:3], {"400", "403", "404"})
            lookup.assert_not_called()
            self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(len(self.store.list_clients(self.ctx)), self.original_count)
        self.assertIsNotNone(self.store.session_context(self.op_cookie))

    # Known RED gaps in main: __call__ dispatches arbitrary PATH_INFO to
    # regexes after form parsing and session lookup. expectedFailure is not
    # an acceptance pass; source owner must make these assertions green.
    @unittest.expectedFailure
    def test_red_bytes_path_rejected_before_body_or_session_dev(self):
        self._assert_early_rejection(b"/clients")

    @unittest.expectedFailure
    def test_red_integer_path_rejected_before_body_or_session_prod(self):
        self._assert_early_rejection(42, production=True)

    @unittest.expectedFailure
    def test_red_list_path_rejected_before_body_or_session_dev(self):
        self._assert_early_rejection(["/clients"])

    @unittest.expectedFailure
    def test_red_str_subclass_path_cannot_authorize_operator_write(self):
        # This is especially important: regex accepts a str subclass today.
        # Use a real stream to expose any authorized write on the RED branch.
        path = _PathSubclass("/clients")
        env = self._env(path, token=self.op_cookie, csrf=self.op_csrf)
        with patch.object(self.store, "session_context", wraps=self.store.session_context) as lookup:
            status, _, _ = self._invoke(env)
            self.assertIn(status[:3], {"400", "403", "404"})
            lookup.assert_not_called()
        self.assertEqual(len(self.store.list_clients(self.ctx)), self.original_count)

    def test_valid_operator_request_still_creates_client_in_dev_and_prod(self):
        for production in (False, True):
            with self.subTest(production=production):
                before = len(self.store.list_clients(self.ctx))
                env = self._env(
                    "/clients", token=self.op_cookie, csrf=self.op_csrf,
                    production=production
                )
                status, headers, _ = self._invoke(env, production=production)
                self.assertEqual(status, "303 See Other")
                self.assertEqual(headers["Location"], "/clients")
                self.assertEqual(len(self.store.list_clients(self.ctx)), before + 1)

    def test_client_session_and_proxy_identity_cannot_authorize_operator_write(self):
        for production in (False, True):
            with self.subTest(production=production):
                env = self._env(
                    "/clients", token=self.client_cookie, csrf=self.client_csrf,
                    production=production
                )
                env["HTTP_X_FORWARDED_USER"] = "operator"
                env["REMOTE_USER"] = "operator"
                status, _, _ = self._invoke(env, production=production)
                self.assertEqual(status, "403 Forbidden")
                self.assertEqual(
                    len(self.store.list_clients(self.ctx)), self.original_count
                )

    def test_unknown_plain_str_path_never_writes_even_with_operator_csrf(self):
        for production in (False, True):
            with self.subTest(production=production):
                env = self._env(
                    "/no-such-route", token=self.op_cookie, csrf=self.op_csrf,
                    production=production
                )
                status, _, _ = self._invoke(env, production=production)
                self.assertEqual(status, "404 Not Found")
                self.assertEqual(
                    len(self.store.list_clients(self.ctx)), self.original_count
                )

    def test_bad_csrf_on_valid_path_cannot_write_or_revoke_operator(self):
        for production in (False, True):
            with self.subTest(production=production):
                env = self._env(
                    "/clients", token=self.op_cookie, csrf="not-a-real-token",
                    production=production
                )
                status, _, _ = self._invoke(env, production=production)
                self.assertEqual(status, "403 Forbidden")
                self.assertEqual(
                    len(self.store.list_clients(self.ctx)), self.original_count
                )
                self.assertIsNotNone(self.store.session_context(self.op_cookie))


if __name__ == "__main__":
    unittest.main()
