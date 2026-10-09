"""Offline functional and real-WSGI acceptance for the isolated route guard."""
from __future__ import annotations

import io
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlencode

from lightup.domain import DomainStore, Role
from lightup.webapp import create_app
from lightup.webapp.pathinfo_guard import (
    MAX_PATH_INFO_CHARS,
    CanonicalPathInfoGuard,
    InvalidPathInfo,
    canonical_path_info,
)
from lightup.webapp.security import WebSecurity


class _RouteStringSubclass(str):
    def __bool__(self):
        raise AssertionError("Path subclass truthiness must never be evaluated")


class _ForbiddenReadStream:
    def read(self, amount=-1):
        raise AssertionError("Rejected path read request data")


class CanonicalPathInfoPureTests(unittest.TestCase):
    def test_valid_canonical_routes_are_not_decoded_normalized_or_rewritten(self):
        for raw in ("/", "/clients", "/api/%0A", "/caf\u00e9", "/" + "x" * (MAX_PATH_INFO_CHARS - 1)):
            with self.subTest(raw=repr(raw)[:50]):
                self.assertEqual(canonical_path_info({"PATH_INFO": raw}), raw)
        self.assertEqual(canonical_path_info({"PATH_INFO": ""}), "/")

    def test_invalid_metadata_cannot_be_coerced_into_a_route(self):
        for raw in (None, 0, 1, b"/clients", ["/clients"], ("/clients",),
                    {"path": "/clients"}, _RouteStringSubclass("/clients"),
                    "clients", "/clients\n", "/clients\r", "/clients\x00",
                    "/clients\t", "/clients\x7f", "/" + "x" * MAX_PATH_INFO_CHARS):
            with self.subTest(raw=repr(raw)[:50]):
                with self.assertRaises(InvalidPathInfo):
                    canonical_path_info({"PATH_INFO": raw})
        with self.assertRaises(InvalidPathInfo):
            canonical_path_info({})

    def test_terminal_line_feed_can_match_anchored_python_regex_without_guard(self):
        # This is an in-process lexical fact, not an installed-proxy exploit.
        self.assertIsNotNone(re.compile(r"^/clients$").match("/clients\n"))
        with self.assertRaises(InvalidPathInfo):
            canonical_path_info({"PATH_INFO": "/clients\n"})

    def test_production_flag_is_exact_boolean_not_truthy_metadata(self):
        for supplied in (1, 0, "yes", None, [], object()):
            with self.subTest(value=repr(supplied)):
                with self.assertRaises(TypeError):
                    CanonicalPathInfoGuard(lambda *_: [], production=supplied)

    def test_invalid_path_cannot_invoke_wrapped_application(self):
        calls = []
        def downstream(*_):
            calls.append("entered")
            raise AssertionError("wrapped application was entered")

        capture = {}
        response = CanonicalPathInfoGuard(downstream)(
            {"PATH_INFO": b"/clients"},
            lambda status, headers: capture.update(status=status, headers=dict(headers)),
        )
        self.assertEqual(response, [b"Invalid request path\n"])
        self.assertEqual(capture["status"], "400 Bad Request")
        self.assertEqual(capture["headers"]["Cache-Control"], "no-store")
        self.assertEqual(capture["headers"]["X-Frame-Options"], "DENY")
        self.assertIn("frame-ancestors 'none'", capture["headers"]["Content-Security-Policy"])
        self.assertEqual(capture["headers"]["Content-Length"], str(len(response[0])))
        self.assertEqual(calls, [])


class CanonicalPathInfoRealWSGITests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tempdir.name) / "state.sqlite")
        op = self.store.bootstrap_operator(
            "op@scope.test", "Operator", "operator-password"
        )
        self.operator = self.store.context_for_user(op.user_id)
        tenant = self.store.create_client(self.operator, "Existing client")
        self.tenant_id = tenant.client_id
        user = self.store.create_user(
            self.operator, "client@scope.test", "Client", Role.CLIENT_ADMIN, tenant.client_id
        )
        self.op_cookie, self.op_csrf = self.store.create_session(op.user_id)
        self.client_cookie, self.client_csrf = self.store.create_session(user.user_id)
        self.original_client_count = len(self.store.list_clients(self.operator))

    def tearDown(self):
        self.tempdir.cleanup()

    def _environ(self, path, *, method="POST", token=None, csrf=None,
                 production=False, input_stream=None, client_name="Added by operator"):
        body = urlencode({"name": client_name, "csrf": csrf or ""}).encode("utf-8")
        env = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "CONTENT_TYPE": "application/x-www-form-urlencoded",
            "CONTENT_LENGTH": str(len(body)),
            "wsgi.input": input_stream if input_stream is not None else io.BytesIO(body),
        }
        if token:
            env["HTTP_COOKIE"] = f"lightup_session={token}"
        if production:
            env.update({
                "REMOTE_ADDR": "127.0.0.1",
                "HTTP_X_FORWARDED_PROTO": "https",
                "HTTP_HOST": "lightup.example",
                "HTTP_ORIGIN": "https://lightup.example",
            })
        return env

    def _invoke(self, env, *, production=False):
        security = (
            WebSecurity(public_origin="https://lightup.example", trusted_proxy_ip="127.0.0.1")
            if production else WebSecurity()
        )
        app = CanonicalPathInfoGuard(create_app(self.store, security), production=production)
        response = {}
        chunks = app(env, lambda status, headers: response.update(
            status=status, headers=dict(headers)
        ))
        return response["status"], response["headers"], b"".join(chunks)

    def test_bad_paths_fail_before_io_session_or_mutation_in_both_environments(self):
        bad_paths = (
            b"/clients", 42, None, ["/clients"], _RouteStringSubclass("/clients"),
            "/clients\n", "/clients\r", "/clients\x00",
            "/clients\x7f", "/" + "A" * MAX_PATH_INFO_CHARS,
            "clients",
        )
        for production in (False, True):
            for path in bad_paths:
                with self.subTest(production=production, path=repr(path)[:48]):
                    env = self._environ(
                        path, token=self.op_cookie, csrf=self.op_csrf,
                        production=production, input_stream=_ForbiddenReadStream()
                    )
                    with patch.object(self.store, "session_context",
                                      wraps=self.store.session_context) as lookup:
                        status, headers, body = self._invoke(env, production=production)
                        lookup.assert_not_called()
                    self.assertEqual(status, "400 Bad Request")
                    self.assertEqual(body, b"Invalid request path\n")
                    self.assertEqual(headers["Cache-Control"], "no-store")
                    if production:
                        self.assertEqual(
                            headers["Strict-Transport-Security"], "max-age=31536000"
                        )
                    else:
                        self.assertNotIn("Strict-Transport-Security", headers)
                    self.assertEqual(len(self.store.list_clients(self.operator)),
                                     self.original_client_count)
                    self.assertIsNotNone(self.store.session_context(self.op_cookie))

    def test_noncanonical_dashboard_read_denied_even_with_real_operator_cookie(self):
        for production in (False, True):
            for bad in (_RouteStringSubclass("/"), "/\n", b"/"):
                with self.subTest(production=production, path=repr(bad)):
                    env = self._environ(
                        bad, method="GET", token=self.op_cookie, production=production
                    )
                    with patch.object(self.store, "session_context") as lookup:
                        status, _, body = self._invoke(env, production=production)
                        lookup.assert_not_called()
                    self.assertEqual(status, "400 Bad Request")
                    self.assertNotIn(b"Active testing", body)

    def test_ambiguous_logout_path_never_revokes_a_valid_session(self):
        for production in (False, True):
            with self.subTest(production=production):
                env = self._environ(
                    "/logout\\n", token=self.op_cookie, csrf=self.op_csrf,
                    production=production
                )
                with patch.object(self.store, "session_context",
                                  wraps=self.store.session_context) as lookup:
                    status, _, _ = self._invoke(env, production=production)
                    lookup.assert_not_called()
                self.assertEqual(status, "400 Bad Request")
                self.assertIsNotNone(self.store.session_context(self.op_cookie))
                self.assertIsNotNone(self.store.session_context(self.client_cookie))

    def test_ambiguous_portal_request_path_never_creates_tenant_request(self):
        for production in (False, True):
            with self.subTest(production=production):
                before = self.store.list_assessment_requests(self.operator)
                env = self._environ(
                    f"/portal/{self.tenant_id}/requests\\n",
                    token=self.client_cookie, csrf=self.client_csrf,
                    production=production
                )
                env["REMOTE_USER"] = "operator"
                with patch.object(self.store, "session_context",
                                  wraps=self.store.session_context) as lookup:
                    status, _, _ = self._invoke(env, production=production)
                    lookup.assert_not_called()
                self.assertEqual(status, "400 Bad Request")
                self.assertEqual(self.store.list_assessment_requests(self.operator),
                                 before)
                self.assertIsNotNone(self.store.session_context(self.client_cookie))

    def test_valid_operator_post_and_root_get_are_preserved(self):
        for production in (False, True):
            with self.subTest(production=production):
                before = len(self.store.list_clients(self.operator))
                post = self._environ(
                    "/clients", token=self.op_cookie, csrf=self.op_csrf,
                    client_name=f"Valid client {production}", production=production
                )
                status, headers, _ = self._invoke(post, production=production)
                self.assertEqual(status, "303 See Other")
                self.assertEqual(headers["Location"], "/clients")
                self.assertEqual(len(self.store.list_clients(self.operator)), before + 1)

                get = self._environ("/", method="GET", token=self.op_cookie,
                                    production=production)
                status, _, body = self._invoke(get, production=production)
                self.assertEqual(status, "200 OK")
                self.assertIn(b"Active testing", body)

    def test_guard_does_not_replace_tenant_role_or_csrf_authorization(self):
        for production in (False, True):
            with self.subTest(production=production):
                before = len(self.store.list_clients(self.operator))
                client = self._environ(
                    "/clients", token=self.client_cookie, csrf=self.client_csrf,
                    production=production
                )
                client["REMOTE_USER"] = "operator"
                client["HTTP_X_FORWARDED_USER"] = "operator"
                status, _, _ = self._invoke(client, production=production)
                self.assertEqual(status, "403 Forbidden")
                wrong_csrf = self._environ(
                    "/clients", token=self.op_cookie, csrf="wrong",
                    production=production
                )
                status, _, _ = self._invoke(wrong_csrf, production=production)
                self.assertEqual(status, "403 Forbidden")
                self.assertEqual(len(self.store.list_clients(self.operator)), before)
                self.assertIsNotNone(self.store.session_context(self.op_cookie))


if __name__ == "__main__":
    unittest.main()
