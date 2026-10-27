"""#884: independent real-SQLite engagement RUNNING authority canaries.

Unmodified DomainStore is exercised with synthetic disposable engagements,
tenants and grants. Expected failures are missing production safeguards and
must not be interpreted as a repaired authorization boundary.
"""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role, RoleError, TenantIsolationError
from lightup.engagements import EngagementStatus, RiskLevel, ScopeDefinition


class RunningGrantLifecycleIssue884(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.db = Path(folder.name) / "scope884.db"
        self.store = DomainStore(self.db)
        self.operator = AccessContext("lab-op", Role.OPERATOR)
        client = self.store.create_client(self.operator, "Synthetic client")
        foreign = self.store.create_client(self.operator, "Synthetic foreign tenant")
        self.client = AccessContext("lab-client", Role.CLIENT_ADMIN, client.client_id)
        self.foreign = AccessContext("other-client", Role.CLIENT_ADMIN, foreign.client_id)
        self.engagement = self.store.create_engagement(
            self.operator, client.client_id, "Synthetic engagement"
        )
        self.other = self.store.create_engagement(
            self.operator, foreign.client_id, "Unrelated engagement"
        )

    def status_from_sqlite(self, engagement_id=None):
        with sqlite3.connect(self.db) as conn:
            row = conn.execute(
                "SELECT status FROM engagements WHERE engagement_id=?",
                (engagement_id or self.engagement.engagement_id,),
            ).fetchone()
        return row[0]

    def grant(self, *, engagement_id=None, relative_start=-2, relative_end=2):
        instant = datetime.now(timezone.utc)
        return self.store.record_authorization_grant(
            self.operator, engagement_id or self.engagement.engagement_id,
            "Synthetic approver", "LAB-884",
            ScopeDefinition(("lab884.example.test",), RiskLevel.PASSIVE),
            instant + timedelta(hours=relative_start),
            instant + timedelta(hours=relative_end),
        )

    @unittest.expectedFailure
    def test_red_draft_cannot_be_marked_running_without_grant(self):
        with self.assertRaises((ValueError, PermissionError)):
            self.store.set_engagement_status(
                self.operator, self.engagement.engagement_id, EngagementStatus.RUNNING,
            )
        self.assertEqual(self.status_from_sqlite(), "draft")

    @unittest.expectedFailure
    def test_red_pending_cannot_be_marked_running_without_grant(self):
        self.store.set_engagement_status(
            self.operator, self.engagement.engagement_id,
            EngagementStatus.AUTHORIZATION_PENDING,
        )
        with self.assertRaises((ValueError, PermissionError)):
            self.store.set_engagement_status(
                self.operator, self.engagement.engagement_id, EngagementStatus.RUNNING,
            )
        self.assertEqual(self.status_from_sqlite(), "authorization_pending")

    @unittest.expectedFailure
    def test_red_expired_grant_cannot_start_running(self):
        self.grant(relative_start=-4, relative_end=-2)
        self.store.set_engagement_status(
            self.operator, self.engagement.engagement_id, EngagementStatus.AUTHORIZED,
        )
        with self.assertRaises((ValueError, PermissionError)):
            self.store.set_engagement_status(
                self.operator, self.engagement.engagement_id, EngagementStatus.RUNNING,
            )
        self.assertEqual(self.status_from_sqlite(), "authorized")

    @unittest.expectedFailure
    def test_red_future_not_yet_valid_grant_cannot_start_running(self):
        self.grant(relative_start=2, relative_end=4)
        with self.assertRaises((ValueError, PermissionError)):
            self.store.set_engagement_status(
                self.operator, self.engagement.engagement_id, EngagementStatus.RUNNING,
            )
        self.assertEqual(self.status_from_sqlite(), "draft")

    @unittest.expectedFailure
    def test_red_other_engagement_grant_cannot_authorize_running(self):
        self.grant(engagement_id=self.other.engagement_id)
        with self.assertRaises((ValueError, PermissionError)):
            self.store.set_engagement_status(
                self.operator, self.engagement.engagement_id, EngagementStatus.RUNNING,
            )
        self.assertEqual(self.status_from_sqlite(), "draft")

    @unittest.expectedFailure
    def test_red_closed_engagement_cannot_restart_on_stale_grant(self):
        self.grant()
        self.store.set_engagement_status(
            self.operator, self.engagement.engagement_id, EngagementStatus.CLOSED,
        )
        with self.assertRaises((ValueError, PermissionError)):
            self.store.set_engagement_status(
                self.operator, self.engagement.engagement_id, EngagementStatus.RUNNING,
            )
        self.assertEqual(self.status_from_sqlite(), "closed")

    def test_granted_authorized_to_running_remains_compatible(self):
        grant = self.grant()
        self.assertIsNotNone(
            self.store.get_current_grant(self.client, self.engagement.engagement_id)
        )
        self.store.set_engagement_status(
            self.operator, self.engagement.engagement_id, EngagementStatus.AUTHORIZED,
        )
        running = self.store.set_engagement_status(
            self.operator, self.engagement.engagement_id, EngagementStatus.RUNNING,
        )
        self.assertIs(running.status, EngagementStatus.RUNNING)
        self.assertEqual(self.status_from_sqlite(), "running")
        self.assertEqual(
            self.store.get_current_grant(self.client, self.engagement.engagement_id).grant_id,
            grant.grant_id,
        )

    def test_new_draft_has_no_grant_and_persists_draft(self):
        self.assertIsNone(self.store.get_current_grant(
            self.client, self.engagement.engagement_id
        ))
        self.assertEqual(self.status_from_sqlite(), "draft")

    def test_nonoperator_cannot_mark_running_with_valid_grant(self):
        self.grant()
        with self.assertRaises(RoleError):
            self.store.set_engagement_status(
                self.client, self.engagement.engagement_id, EngagementStatus.RUNNING,
            )
        self.assertEqual(self.status_from_sqlite(), "draft")

    def test_foreign_client_cannot_read_other_tenant_engagement_or_grant(self):
        self.grant()
        with self.assertRaises(TenantIsolationError):
            self.store.get_engagement(self.foreign, self.engagement.engagement_id)
        with self.assertRaises(TenantIsolationError):
            self.store.get_current_grant(self.foreign, self.engagement.engagement_id)
        self.assertEqual(self.status_from_sqlite(), "draft")

    def test_grant_expiry_and_future_start_are_real_sqlite_denials(self):
        for start, end in ((-4, -2), (2, 4)):
            with self.subTest(start=start, end=end):
                # Use a distinct disposable engagement each iteration.
                e = self.store.create_engagement(
                    self.operator, self.engagement.client_id, "Distinct control"
                )
                self.grant(engagement_id=e.engagement_id,
                           relative_start=start, relative_end=end)
                self.assertIsNone(self.store.get_current_grant(
                    self.client, e.engagement_id
                ))

    def test_no_target_execution_or_network_route_is_used(self):
        # All operations are direct local DomainStore lifecycle/SQLite calls.
        # No live client request, socket, DNS, executor, tool registry or target.
        self.assertEqual(self.status_from_sqlite(), "draft")
        self.assertEqual(self.status_from_sqlite(self.other.engagement_id), "draft")


if __name__ == "__main__":
    unittest.main()
