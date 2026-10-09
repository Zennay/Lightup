"""Case-sensitive WSGI method authority: real app RED canaries.

HTTP method tokens are case-sensitive (RFC 9110). No client-supplied
noncanonical token may become an authorized GET or mutating POST merely
because app dispatch uppercases it. In-process tests; SQLite only, no socket,
real target, grant issuance, or executor.
"""
from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlencode

from lightup.domain import DomainStore
from lightup.webapp import create_app


class MethodTokenCaseSensitiveCanaries(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.store = DomainStore(Path(self.tempdir.name) / "methods.db")
        self.app = create_app(self.store)
        operator = self.store.bootstrap_operator(
            "operator@lightup.test", "Operator", "fixture-password"
        )
        self.operator = self.store.context_for_user(operator.user_id)
        self.token, self.csrf = self.store.create_session(operator.user_id)

    def request(self, method, path, form=None):
        data = urlencode(form or {}).encode("utf-8")
        env = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "CONTENT_LENGTH": str(len(data)),
            "CONTENT_TYPE": "application/x-www-form-urlencoded",
            "HTTP_COOKIE": f"lightup_session={self.token}",
            "wsgi.input": io.BytesIO(data),
        }
        capture = {}

        def start_response(status, headers):
            capture["status"] = status
            capture["headers"] = dict(headers)

        b"".join(self.app(env, start_response))
        return capture["status"]

    @unittest.expectedFailure  # RED: app.__call__ currently uppercases WSGI token.
    def test_lowercase_post_must_not_create_client(self):
        before = len(self.store.list_clients(self.operator))
        status = self.request("post", "/clients", {
            "name": "Untrusted lowercase method", "csrf": self.csrf
        })
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(len(self.store.list_clients(self.operator)), before)

    @unittest.expectedFailure
    def test_mixed_case_post_must_not_create_client(self):
        before = len(self.store.list_clients(self.operator))
        status = self.request("PoSt", "/clients", {
            "name": "Untrusted mixed method", "csrf": self.csrf
        })
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(len(self.store.list_clients(self.operator)), before)

    @unittest.expectedFailure
    def test_lowercase_post_must_not_revoke_session(self):
        status = self.request("post", "/logout", {"csrf": self.csrf})
        self.assertEqual(status, "404 Not Found")
        self.assertIsNotNone(self.store.session_context(self.token))

    @unittest.expectedFailure
    def test_lowercase_get_must_not_read_operator_dashboard(self):
        status = self.request("get", "/")
        self.assertEqual(status, "404 Not Found")

    def test_canonical_post_positive_control(self):
        before = len(self.store.list_clients(self.operator))
        status = self.request("POST", "/clients", {
            "name": "Canonical request", "csrf": self.csrf
        })
        self.assertEqual(status, "303 See Other")
        self.assertEqual(len(self.store.list_clients(self.operator)), before + 1)

    def test_canonical_get_positive_control(self):
        self.assertEqual(self.request("GET", "/"), "200 OK")

    def test_unknown_uppercase_token_never_mutates(self):
        before = len(self.store.list_clients(self.operator))
        self.assertEqual(self.request("PATCH", "/clients", {
            "name": "Not allowed", "csrf": self.csrf
        }), "404 Not Found")
        self.assertEqual(len(self.store.list_clients(self.operator)), before)


if __name__ == "__main__":
    unittest.main()
