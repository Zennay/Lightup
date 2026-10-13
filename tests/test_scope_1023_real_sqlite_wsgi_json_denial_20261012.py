"""#1023 genuine disposable SQLite + default WSGI non-authority controls.

These are negative controls for existing form-based ingress, not proof of
a deployed authorization-envelope endpoint or trusted operator approval.
"""
from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path

from lightup.domain import DomainStore
from lightup.webapp.app import LightUpWebApp
from lightup.webapp.security import WebSecurity


_TABLES = ("assessment_requests", "engagements", "authorization_grants",
           "risk_approvals", "sessions", "clients", "users")


class DefaultWSGINoJsonGrantSQLite(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = DomainStore(Path(self.tmp.name) / "lightup.sqlite3")
        self.app = LightUpWebApp(self.store, WebSecurity())

    def durable_counts(self) -> tuple[int, ...]:
        with self.store._connect() as con:
            return tuple(con.execute("SELECT COUNT(*) FROM " + table).fetchone()[0]
                         for table in _TABLES)

    def request(self, path: str, raw: bytes, content_type: str):
        result = []
        environ = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": path,
            "HTTP_HOST": "localhost",
            "REMOTE_ADDR": "127.0.0.1",
            "wsgi.url_scheme": "http",
            "SERVER_NAME": "localhost",
            "SERVER_PORT": "80",
            "CONTENT_TYPE": content_type,
            "CONTENT_LENGTH": str(len(raw)),
            "wsgi.input": io.BytesIO(raw),
        }

        def receive(status, headers):
            result.append((status, dict(headers)))

        emitted = b"".join(self.app(environ, receive))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][1]["Cache-Control"], "no-store")
        return result[0][0], emitted

    def test_json_grant_request_is_rejected_before_any_sqlite_write(self):
        before = self.durable_counts()
        status, _ = self.request("/engagements/fake/grants",
                                 b'{"risk":5,"approved":true}', "application/json")
        self.assertEqual(status, "415 Unsupported Media Type")
        self.assertEqual(self.durable_counts(), before)

    def test_form_shaped_anonymous_grant_does_not_write_any_sqlite_rows(self):
        before = self.durable_counts()
        status, _ = self.request("/engagements/fake/grants",
                                 b"csrf=forged&approved=true",
                                 "application/x-www-form-urlencoded")
        self.assertEqual(status, "303 See Other")
        self.assertEqual(self.durable_counts(), before)

    def test_json_looking_form_body_fails_without_sqlite_change(self):
        before = self.durable_counts()
        status, _ = self.request("/engagements/fake/grants",
                                 b'{"tenant":"foreign"}',
                                 "application/x-www-form-urlencoded")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(self.durable_counts(), before)

    def test_json_portal_request_cannot_create_assessment(self):
        before = self.durable_counts()
        status, _ = self.request("/portal/foreign/requests",
                                 b'{"requested_risk":5}', "application/json")
        self.assertEqual(status, "415 Unsupported Media Type")
        self.assertEqual(self.durable_counts(), before)


if __name__ == "__main__":
    unittest.main()
