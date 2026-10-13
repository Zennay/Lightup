"""#1275: risk approval *decision/write* tenant lineage real SQLite RED.

Standalone source-owner acceptance only; no production code, target or client IO.
An expected failure means the installed main code has NOT passed the contract.
"""

import io
import sqlite3
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlencode

from lightup.domain import AccessContext, DomainStore, Role, RoleError
from lightup.engagements import RiskLevel
from lightup.webapp import create_app


class DecisionLineageSQLiteAcceptance(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="lightup-1275-")
        self.addCleanup(self._tmp.cleanup)
        self.store = DomainStore(Path(self._tmp.name) / "1275.sqlite")
        self.operator = AccessContext("synthetic-operator-1275", Role.OPERATOR)
        self.tenant_a = self.store.create_client(self.operator, "synthetic decision A")
        self.tenant_b = self.store.create_client(self.operator, "synthetic decision B")
        self.client_a = AccessContext("synthetic-a-1275", Role.CLIENT_ADMIN, self.tenant_a.client_id)
        self.client_b = AccessContext("synthetic-b-1275", Role.CLIENT_ADMIN, self.tenant_b.client_id)
        self.engagement_a = self.store.create_engagement(self.operator, self.tenant_a.client_id, "decision A")
        self.engagement_b = self.store.create_engagement(self.operator, self.tenant_b.client_id, "decision B")
        self.approval = self.store.request_risk_elevation(
            self.client_a, self.engagement_a.engagement_id, RiskLevel.ELEVATED, "synthetic-only review"
        )
        with sqlite3.connect(self.store.path) as con:
            con.executescript(
                "CREATE TABLE decision_audit(approval_id TEXT NOT NULL, new_status TEXT NOT NULL);"
                "CREATE TRIGGER decision_state_audit AFTER UPDATE OF status ON risk_approvals "
                "WHEN NEW.status != OLD.status BEGIN "
                "INSERT INTO decision_audit(approval_id,new_status) VALUES(NEW.approval_id,NEW.status);"
                "END;"
            )

    def _snapshot(self):
        with sqlite3.connect(self.store.path) as con:
            return (
                con.execute(
                    "SELECT approval_id,client_id,engagement_id,requested_risk,justification,"
                    "status,requested_by,created_at,decided_by,decided_at "
                    "FROM risk_approvals ORDER BY approval_id"
                ).fetchall(),
                con.execute(
                    "SELECT approval_id,new_status FROM decision_audit ORDER BY rowid"
                ).fetchall(),
            )

    def _status(self):
        with sqlite3.connect(self.store.path) as con:
            return con.execute(
                "SELECT status FROM risk_approvals WHERE approval_id=?",
                (self.approval.approval_id,),
            ).fetchone()[0]

    def _corrupt_client_label(self):
        with sqlite3.connect(self.store.path) as con:
            count = con.execute(
                "UPDATE risk_approvals SET client_id=? WHERE approval_id=?",
                (self.tenant_b.client_id, self.approval.approval_id),
            ).rowcount
        self.assertEqual(count, 1)

    def _corrupt_engagement_pointer(self):
        with sqlite3.connect(self.store.path) as con:
            count = con.execute(
                "UPDATE risk_approvals SET engagement_id=? WHERE approval_id=?",
                (self.engagement_b.engagement_id, self.approval.approval_id),
            ).rowcount
        self.assertEqual(count, 1)

    def _orphan_engagement(self):
        # Only this disposable test fixture uses a connection with FK disabled.
        with sqlite3.connect(self.store.path) as con:
            con.execute("PRAGMA foreign_keys=OFF")
            count = con.execute(
                "DELETE FROM engagements WHERE engagement_id=?",
                (self.engagement_a.engagement_id,),
            ).rowcount
        self.assertEqual(count, 1)

    def _expect_atomic_refusal(self, approve):
        before = self._snapshot()
        with self.assertRaises((ValueError, PermissionError, KeyError)):
            self.store.decide_risk_elevation(self.operator, self.approval.approval_id, approve)
        self.assertEqual(self._snapshot(), before)
        self.assertEqual(self._status(), "pending")

    def test_canonical_operator_approval_commits_once_with_audit(self):
        result = self.store.decide_risk_elevation(self.operator, self.approval.approval_id, True)
        self.assertEqual(result.status.value, "approved")
        self.assertEqual(self._status(), "approved")
        self.assertEqual(self._snapshot()[1], [(self.approval.approval_id, "approved")])

    def test_canonical_operator_denial_commits_once_with_audit(self):
        result = self.store.decide_risk_elevation(self.operator, self.approval.approval_id, False)
        self.assertEqual(result.status.value, "denied")
        self.assertEqual(self._status(), "denied")
        self.assertEqual(self._snapshot()[1], [(self.approval.approval_id, "denied")])

    def test_client_cannot_decide_and_does_not_write_audit(self):
        before = self._snapshot()
        with self.assertRaises(RoleError):
            self.store.decide_risk_elevation(self.client_a, self.approval.approval_id, True)
        self.assertEqual(self._snapshot(), before)

    def test_operator_cannot_self_approve_and_does_not_write_audit(self):
        self.approval = self.store.request_risk_elevation(
            self.operator, self.engagement_a.engagement_id, RiskLevel.STANDARD,
            "synthetic operator-originated request",
        )
        before = self._snapshot()
        with self.assertRaises(RoleError):
            self.store.decide_risk_elevation(self.operator, self.approval.approval_id, True)
        self.assertEqual(self._snapshot(), before)

    def test_repeated_decision_is_read_only(self):
        self.store.decide_risk_elevation(self.operator, self.approval.approval_id, True)
        before = self._snapshot()
        with self.assertRaises(ValueError):
            self.store.decide_risk_elevation(self.operator, self.approval.approval_id, False)
        self.assertEqual(self._snapshot(), before)

    @unittest.expectedFailure
    def test_red_corrupt_client_label_cannot_be_approved(self):
        self._corrupt_client_label()
        self._expect_atomic_refusal(True)

    @unittest.expectedFailure
    def test_red_corrupt_client_label_cannot_be_denied(self):
        self._corrupt_client_label()
        self._expect_atomic_refusal(False)

    @unittest.expectedFailure
    def test_red_foreign_engagement_pointer_cannot_be_approved(self):
        self._corrupt_engagement_pointer()
        self._expect_atomic_refusal(True)

    @unittest.expectedFailure
    def test_red_foreign_engagement_pointer_cannot_be_denied(self):
        self._corrupt_engagement_pointer()
        self._expect_atomic_refusal(False)

    @unittest.expectedFailure
    def test_red_orphan_approval_cannot_be_approved(self):
        self._orphan_engagement()
        self._expect_atomic_refusal(True)

    @unittest.expectedFailure
    def test_red_orphan_approval_cannot_be_denied(self):
        self._orphan_engagement()
        self._expect_atomic_refusal(False)


class DecisionLineageRealWSGIAcceptance(DecisionLineageSQLiteAcceptance):
    def setUp(self):
        super().setUp()
        self.operator_user = self.store.create_user(
            self.operator, "scope-1275-op@example.test", "Lab operator", Role.OPERATOR
        )
        self.operator_session, self.csrf = self.store.create_session(self.operator_user.user_id)
        self.client_user = self.store.create_user(
            self.operator, "scope-1275-client@example.test", "Lab client",
            Role.CLIENT_ADMIN, self.tenant_a.client_id,
        )
        self.client_session, self.client_csrf = self.store.create_session(self.client_user.user_id)
        self.app = create_app(self.store)

    def _post(self, token, csrf, decision="approve"):
        payload = urlencode({"csrf": csrf, "decision": decision}).encode("ascii")
        env = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": f"/assessments/elevations/{self.approval.approval_id}/decision",
            "CONTENT_TYPE": "application/x-www-form-urlencoded",
            "CONTENT_LENGTH": str(len(payload)),
            "wsgi.input": io.BytesIO(payload),
            "HTTP_COOKIE": f"lightup_session={token}" if token else "",
        }
        captured = {}
        def start_response(status, headers):
            captured["status"] = status
            captured["headers"] = dict(headers)
        response = self.app(env, start_response)
        return captured["status"], captured["headers"], b"".join(response)

    def test_real_wsgi_authenticated_operator_canonical_decision(self):
        status, headers, _ = self._post(self.operator_session, self.csrf)
        self.assertEqual(status, "303 See Other")
        self.assertEqual(headers.get("Location"), "/assessments")
        self.assertEqual(self._status(), "approved")

    def test_real_wsgi_client_cannot_approve(self):
        before = self._snapshot()
        status, _, _ = self._post(self.client_session, self.client_csrf)
        self.assertEqual(status, "403 Forbidden")
        self.assertEqual(self._snapshot(), before)

    def test_real_wsgi_bad_csrf_cannot_approve(self):
        before = self._snapshot()
        status, _, _ = self._post(self.operator_session, "wrong-csrf")
        self.assertEqual(status, "403 Forbidden")
        self.assertEqual(self._snapshot(), before)

    def test_real_wsgi_anonymous_cannot_approve(self):
        before = self._snapshot()
        status, headers, _ = self._post(None, "not-a-session")
        self.assertEqual(status, "303 See Other")
        self.assertEqual(headers.get("Location"), "/login")
        self.assertEqual(self._snapshot(), before)

    @unittest.expectedFailure
    def test_red_wsgi_operator_must_not_approve_corrupt_client_lineage(self):
        self._corrupt_client_label()
        before = self._snapshot()
        status, _, _ = self._post(self.operator_session, self.csrf)
        self.assertIn(status, ("400 Bad Request", "403 Forbidden", "409 Conflict"))
        self.assertEqual(self._snapshot(), before)

    @unittest.expectedFailure
    def test_red_wsgi_operator_must_not_deny_foreign_engagement(self):
        self._corrupt_engagement_pointer()
        before = self._snapshot()
        status, _, _ = self._post(self.operator_session, self.csrf, decision="deny")
        self.assertIn(status, ("400 Bad Request", "403 Forbidden", "409 Conflict"))
        self.assertEqual(self._snapshot(), before)


if __name__ == "__main__":
    unittest.main()
