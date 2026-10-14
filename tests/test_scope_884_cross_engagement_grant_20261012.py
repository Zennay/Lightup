"""#884 W2: same-tenant and multi-engagement RUNNING-grant isolation.

Expected RED is a known *default producer* issue, not a bypass assertion.
No network, tools, real clients or target I/O; every row is disposable SQLite.
"""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role, RoleError, TenantIsolationError
from lightup.engagements import EngagementStatus, RiskLevel, ScopeDefinition


class SameTenantGrantLifecycleW2(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db = Path(temp.name) / "engagement-w2.db"
        self.store = DomainStore(self.db)
        self.operator = AccessContext("test-operator", Role.OPERATOR)
        self.c1 = self.store.create_client(self.operator, "Synthetic first")
        self.c2 = self.store.create_client(self.operator, "Synthetic second")
        self.a = AccessContext("test-a", Role.CLIENT_ADMIN, self.c1.client_id)
        self.b = AccessContext("test-b", Role.CLIENT_ADMIN, self.c2.client_id)
        self.one = self.store.create_engagement(self.operator, self.c1.client_id, "A one")
        self.two = self.store.create_engagement(self.operator, self.c1.client_id, "A two")
        self.foreign = self.store.create_engagement(self.operator, self.c2.client_id, "B one")
        self.now = datetime.now(timezone.utc)

    def add_grant(self, engagement_id, start=-3600, end=3600):
        return self.store.record_authorization_grant(
            self.operator, engagement_id, "Synthetic approver", "LAB-884-W2",
            ScopeDefinition(("scope884.example.test",), RiskLevel.PASSIVE),
            self.now + timedelta(seconds=start),
            self.now + timedelta(seconds=end),
        )

    def status(self, engagement_id):
        with sqlite3.connect(self.db) as connection:
            return connection.execute(
                "SELECT status FROM engagements WHERE engagement_id=?",
                (engagement_id,),
            ).fetchone()[0]

    def grants(self):
        with sqlite3.connect(self.db) as connection:
            return connection.execute(
                "SELECT grant_id,client_id,engagement_id,valid_from,valid_until "
                "FROM authorization_grants ORDER BY grant_id"
            ).fetchall()

    @unittest.expectedFailure
    def test_red_same_tenant_other_engagement_grant_cannot_enable_running(self):
        self.add_grant(self.two.engagement_id)
        with self.assertRaises((ValueError, PermissionError)):
            self.store.set_engagement_status(
                self.operator, self.one.engagement_id, EngagementStatus.RUNNING
            )
        self.assertEqual(self.status(self.one.engagement_id), "draft")

    @unittest.expectedFailure
    def test_red_other_tenant_current_grant_cannot_enable_running(self):
        self.add_grant(self.foreign.engagement_id)
        with self.assertRaises((ValueError, PermissionError)):
            self.store.set_engagement_status(
                self.operator, self.one.engagement_id, EngagementStatus.RUNNING
            )
        self.assertEqual(self.status(self.one.engagement_id), "draft")

    @unittest.expectedFailure
    def test_red_marking_authorized_without_grant_still_must_refuse_running(self):
        self.store.set_engagement_status(
            self.operator, self.one.engagement_id, EngagementStatus.AUTHORIZED
        )
        with self.assertRaises((ValueError, PermissionError)):
            self.store.set_engagement_status(
                self.operator, self.one.engagement_id, EngagementStatus.RUNNING
            )
        self.assertEqual(self.status(self.one.engagement_id), "authorized")

    @unittest.expectedFailure
    def test_red_expired_own_and_current_sibling_grant_cannot_enable_running(self):
        self.add_grant(self.one.engagement_id, start=-7200, end=-3600)
        self.add_grant(self.two.engagement_id)
        with self.assertRaises((ValueError, PermissionError)):
            self.store.set_engagement_status(
                self.operator, self.one.engagement_id, EngagementStatus.RUNNING
            )
        self.assertEqual(self.status(self.one.engagement_id), "draft")

    def test_current_grant_selector_is_scoped_to_exact_engagement(self):
        good = self.add_grant(self.two.engagement_id)
        self.assertIsNone(
            self.store.get_current_grant(self.a, self.one.engagement_id, now=self.now)
        )
        selected = self.store.get_current_grant(
            self.a, self.two.engagement_id, now=self.now,
        )
        self.assertEqual(selected.grant_id, good.grant_id)

    def test_other_tenant_grant_does_not_satisfy_own_selector(self):
        self.add_grant(self.foreign.engagement_id)
        self.assertIsNone(
            self.store.get_current_grant(self.a, self.one.engagement_id, now=self.now)
        )

    def test_expired_own_and_valid_sibling_preserve_own_absence(self):
        self.add_grant(self.one.engagement_id, start=-7200, end=-3600)
        self.add_grant(self.two.engagement_id)
        self.assertIsNone(
            self.store.get_current_grant(self.a, self.one.engagement_id, now=self.now)
        )

    def test_current_own_grant_can_enable_canonical_authorized_running(self):
        grant = self.add_grant(self.one.engagement_id)
        self.store.set_engagement_status(
            self.operator, self.one.engagement_id, EngagementStatus.AUTHORIZED
        )
        changed = self.store.set_engagement_status(
            self.operator, self.one.engagement_id, EngagementStatus.RUNNING
        )
        self.assertEqual(changed.status, EngagementStatus.RUNNING)
        self.assertEqual(self.status(self.one.engagement_id), "running")
        self.assertEqual(
            self.store.get_current_grant(self.a, self.one.engagement_id).grant_id,
            grant.grant_id,
        )

    def test_current_grant_still_rejects_other_client_read(self):
        self.add_grant(self.one.engagement_id)
        with self.assertRaises(TenantIsolationError):
            self.store.get_current_grant(
                self.b, self.one.engagement_id, now=self.now,
            )

    def test_nonoperator_cannot_transition_even_with_persisted_grant(self):
        self.add_grant(self.one.engagement_id)
        before = self.status(self.one.engagement_id)
        with self.assertRaises(RoleError):
            self.store.set_engagement_status(
                self.a, self.one.engagement_id, EngagementStatus.RUNNING
            )
        self.assertEqual(self.status(self.one.engagement_id), before)

    def test_setting_pending_does_not_issue_new_grant(self):
        self.store.set_engagement_status(
            self.operator, self.one.engagement_id, EngagementStatus.AUTHORIZATION_PENDING
        )
        self.assertEqual(self.status(self.one.engagement_id), "authorization_pending")
        self.assertEqual(self.grants(), [])

    def test_current_grant_selector_before_and_after_window_is_none(self):
        self.add_grant(self.one.engagement_id)
        self.assertIsNone(self.store.get_current_grant(
            self.a, self.one.engagement_id,
            now=self.now - timedelta(days=2),
        ))
        self.assertIsNone(self.store.get_current_grant(
            self.a, self.one.engagement_id,
            now=self.now + timedelta(days=2),
        ))

    def test_grant_identity_survives_disposable_database_reopen(self):
        grant = self.add_grant(self.one.engagement_id)
        another = DomainStore(self.db)
        self.assertEqual(
            another.get_current_grant(
                self.a, self.one.engagement_id, now=self.now,
            ).grant_id, grant.grant_id
        )

    def test_unrelated_engagement_status_unchanged_by_authorized_control(self):
        self.add_grant(self.one.engagement_id)
        self.store.set_engagement_status(
            self.operator, self.one.engagement_id, EngagementStatus.AUTHORIZED
        )
        self.store.set_engagement_status(
            self.operator, self.one.engagement_id, EngagementStatus.RUNNING
        )
        self.assertEqual(self.status(self.two.engagement_id), "draft")
        self.assertEqual(self.status(self.foreign.engagement_id), "draft")

    def test_grant_sqlite_rows_unchanged_by_all_read_controls(self):
        self.add_grant(self.one.engagement_id)
        before = self.grants()
        self.store.get_current_grant(self.a, self.one.engagement_id, now=self.now)
        self.store.get_current_grant(
            self.a, self.one.engagement_id, now=self.now + timedelta(days=2)
        )
        self.assertEqual(self.grants(), before)


if __name__ == "__main__":
    unittest.main()
