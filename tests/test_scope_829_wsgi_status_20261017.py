"""Issue #829: authenticated *offline* WSGI downstream grant-read acceptance.

The operator-facing client detail screen renders a grant badge from
DomainStore.get_current_grant().  No server is bound, requests are in-process
with fictional users and temporary SQLite. Source REDs deliberately remain
expectedFailure until the read-side source owner integrates a fix.
"""
from __future__ import annotations

import io
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lightup.domain import DomainStore
from lightup.engagements import RiskLevel, ScopeDefinition
from lightup.webapp import create_app


class GrantTenantWebBoundary829(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="scope-829-wsgi-")
        self.db = Path(self.temp.name) / "fictional-domain.db"
        self.store = DomainStore(self.db)
        self.app = create_app(self.store)
        operator_user = self.store.bootstrap_operator(
            "fictional-829-operator@example.invalid",
            "Fictional operator",
            "fictional-password-not-used-outside-disposable-db",
        )
        self.operator = self.store.context_for_user(operator_user.user_id)
        self.token, _ = self.store.create_session(operator_user.user_id)
        self.client_a = self.store.create_client(self.operator, "Fictional A")
        self.client_b = self.store.create_client(self.operator, "Fictional B")
        self.engagement = self.store.create_engagement(
            self.operator, self.client_a.client_id, "Fictional internal lab"
        )
        self.reference = "fictional-829-origin-consent"
        now = datetime.now(timezone.utc)
        self.grant = self.store.record_authorization_grant(
            self.operator, self.engagement.engagement_id,
            "Fictional approver", self.reference,
            ScopeDefinition(
                assets=("127.0.0.1",),
                max_risk=RiskLevel.ANALYSIS_ONLY,
            ),
            now - timedelta(minutes=3),
            now + timedelta(minutes=30),
        )

    def tearDown(self):
        self.temp.cleanup()

    def read_operator_client_page(self, authenticated=True):
        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": f"/clients/{self.client_a.client_id}",
            "CONTENT_LENGTH": "0",
            "wsgi.input": io.BytesIO(b""),
        }
        if authenticated:
            environ["HTTP_COOKIE"] = f"lightup_session={self.token}"
        receipt = {}

        def start_response(status, headers):
            receipt.update(status=status, headers=dict(headers))

        result = b"".join(self.app(environ, start_response))
        return receipt, result.decode("utf-8")

    def corrupt_grant_owner(self):
        with sqlite3.connect(self.db) as conn:
            conn.execute(
                "UPDATE authorization_grants SET client_id=? WHERE grant_id=?",
                (self.client_b.client_id, self.grant.grant_id),
            )

    def test_valid_authorized_operator_sees_real_grant(self):
        response, body = self.read_operator_client_page()
        self.assertEqual(response["status"], "200 OK")
        self.assertIn("Authorization current", body)
        self.assertIn(self.reference, body)
        self.assertEqual(response["headers"]["Cache-Control"], "no-store")

    def test_anonymous_request_does_not_surface_any_grants(self):
        response, body = self.read_operator_client_page(authenticated=False)
        self.assertEqual(response["status"], "303 See Other")
        self.assertEqual(response["headers"]["Location"], "/login")
        self.assertNotIn(self.reference, body)

    def test_corrupt_read_never_mutates_persisted_rows(self):
        self.corrupt_grant_owner()
        with sqlite3.connect(self.db) as con:
            before = tuple(con.execute(
                "SELECT grant_id,client_id,engagement_id,reference "
                "FROM authorization_grants ORDER BY grant_id"
            ).fetchall())
        response, _ = self.read_operator_client_page()
        self.assertEqual(response["status"], "200 OK")
        with sqlite3.connect(self.db) as con:
            after = tuple(con.execute(
                "SELECT grant_id,client_id,engagement_id,reference "
                "FROM authorization_grants ORDER BY grant_id"
            ).fetchall())
        self.assertEqual(before, after)

    @unittest.expectedFailure
    def test_source_red_operator_ui_must_not_show_foreign_tenant_grant(self):
        self.corrupt_grant_owner()
        response, body = self.read_operator_client_page()
        self.assertEqual(response["status"], "200 OK")
        self.assertIn("No current authorization", body)
        self.assertNotIn("Authorization details", body)
        self.assertNotIn(self.reference, body)

    @unittest.expectedFailure
    def test_source_red_operator_ui_must_not_show_cross_tenant_reference(self):
        self.corrupt_grant_owner()
        _, body = self.read_operator_client_page()
        self.assertNotIn(self.reference, body)


if __name__ == "__main__":
    unittest.main()
