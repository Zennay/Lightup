"""Independent real-WSGI privacy boundary checks for issue #1284 (offline only).

No production authorization source is changed. Expected failures are source-owner
security requirements and MUST NOT be counted as a resolved privacy boundary.
"""
from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlencode

from lightup.domain import DomainStore, Role
from lightup.webapp import create_app


class WsgiErrorDetailBoundary1284Tests(unittest.TestCase):
    PRIVATE_MARKER = "PrivateResourceMarker1284"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.app = create_app(self.store)
        self.op = self.store.bootstrap_operator(
            "operator-1284@lightup.test", "Operator", "synthetic-op-password")
        self.op_context = self.store.context_for_user(self.op.user_id)
        self.client = self.store.create_client(self.op_context, "Synthetic tenant")
        self.client_user = self.store.create_user(
            self.op_context, "tenant-1284@lightup.test", "Tenant",
            Role.CLIENT_ADMIN, self.client.client_id)
        self.op_session, self.op_csrf = self.store.create_session(self.op.user_id)
        self.client_session, self.client_csrf = self.store.create_session(
            self.client_user.user_id)

    def request(self, method, path, form=None, session=None, csrf=None):
        payload = dict(form or {})
        if csrf is not None:
            payload["csrf"] = csrf
        raw = urlencode(payload).encode("utf-8")
        environ = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "CONTENT_LENGTH": str(len(raw)),
            "CONTENT_TYPE": "application/x-www-form-urlencoded",
            "wsgi.input": io.BytesIO(raw),
        }
        if session is not None:
            environ["HTTP_COOKIE"] = f"lightup_session={session}"
        response = {}
        body = b"".join(self.app(
            environ, lambda status, headers: response.update(
                status=status, headers=dict(headers))))
        return response["status"], response["headers"], body.decode("utf-8")

    def test_operator_normal_client_list_still_succeeds(self):
        status, headers, body = self.request("GET", "/clients", session=self.op_session)
        self.assertEqual(status, "200 OK")
        self.assertIn("Synthetic tenant", body)
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_operator_unknown_client_keeps_400_and_security_headers(self):
        status, headers, _ = self.request(
            "GET", "/clients/" + self.PRIVATE_MARKER, session=self.op_session)
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])

    def test_anonymous_cannot_observe_client_error_details(self):
        status, headers, body = self.request(
            "GET", "/clients/" + self.PRIVATE_MARKER)
        self.assertEqual(status, "303 See Other")
        self.assertEqual(headers["Location"], "/login")
        self.assertNotIn(self.PRIVATE_MARKER, body)

    def test_client_principal_cannot_observe_operator_error_details(self):
        status, _, body = self.request(
            "GET", "/clients/" + self.PRIVATE_MARKER, session=self.client_session)
        self.assertEqual(status, "403 Forbidden")
        self.assertNotIn(self.PRIVATE_MARKER, body)

    def test_unauthorized_create_refused_without_db_mutation(self):
        before = len(self.store.list_clients(self.op_context))
        status, _, _ = self.request(
            "POST", "/clients", {"name": "Unexpected tenant"},
            session=self.client_session, csrf=self.client_csrf)
        self.assertEqual(status, "403 Forbidden")
        self.assertEqual(len(self.store.list_clients(self.op_context)), before)

    def test_invalid_csrf_refused_without_db_mutation(self):
        before = len(self.store.list_clients(self.op_context))
        status, _, _ = self.request(
            "POST", "/clients", {"name": "Unexpected tenant"},
            session=self.op_session, csrf="invalid-csrf")
        self.assertEqual(status, "403 Forbidden")
        self.assertEqual(len(self.store.list_clients(self.op_context)), before)

    def test_validation_failure_keeps_db_unchanged(self):
        before = len(self.store.list_clients(self.op_context))
        status, headers, _ = self.request(
            "POST", "/clients", {"name": ""},
            session=self.op_session, csrf=self.op_csrf)
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(len(self.store.list_clients(self.op_context)), before)

    @unittest.expectedFailure
    def test_red_unknown_client_identifier_must_not_echo(self):
        # Current _dispatch includes raw KeyError text in rendered 400 body.
        status, _, body = self.request(
            "GET", "/clients/" + self.PRIVATE_MARKER, session=self.op_session)
        self.assertEqual(status, "400 Bad Request")
        self.assertNotIn(self.PRIVATE_MARKER, body)
        self.assertNotIn("unknown client", body)

    @unittest.expectedFailure
    def test_red_validation_exception_details_must_not_echo(self):
        # Sanitized production error should never reflect domain exception text.
        status, _, body = self.request(
            "POST", "/clients", {"name": ""},
            session=self.op_session, csrf=self.op_csrf)
        self.assertEqual(status, "400 Bad Request")
        self.assertNotIn("client name is required", body)


if __name__ == "__main__":
    unittest.main()
