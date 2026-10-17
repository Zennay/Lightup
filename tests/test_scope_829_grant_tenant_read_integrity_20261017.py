"""Offline, temporary-SQLite source acceptance for issue #829.

Only genuine in-process DomainStore operations.  No HTTP, targets, scans,
credential access, grant issuance outside the disposable test database, or
changes to the source owner's production implementation.

expectedFailure means SOURCE UNFIXED, not a passing security assertion.
"""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role, TenantIsolationError
from lightup.engagements import RiskLevel, ScopeDefinition


class GrantTenantReadIntegrity829(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="lightup-scope-829-")
        self.db = Path(self.temp.name) / "only-test.db"
        self.store = DomainStore(self.db)
        self.operator = AccessContext("fictional-operator", Role.OPERATOR)
        self.a = self.store.create_client(self.operator, "Fictional A")
        self.b = self.store.create_client(self.operator, "Fictional B")
        self.ctx_a = AccessContext("fictional-admin-a", Role.CLIENT_ADMIN, self.a.client_id)
        self.ctx_b = AccessContext("fictional-admin-b", Role.CLIENT_ADMIN, self.b.client_id)
        self.eng_a = self.store.create_engagement(self.operator, self.a.client_id, "A fictional lab")
        self.eng_b = self.store.create_engagement(self.operator, self.b.client_id, "B fictional lab")
        self.now = datetime(2030, 5, 15, 12, 0, tzinfo=timezone.utc)
        self.scope = ScopeDefinition(
            assets=("127.0.0.1",), max_risk=RiskLevel.ANALYSIS_ONLY,
            allowed_capabilities=(), excluded_assets=(),
        )

    def tearDown(self):
        self.temp.cleanup()

    def grant(self, engagement, reference="fictional-scope-829"):
        return self.store.record_authorization_grant(
            self.operator, engagement.engagement_id, "Fictional reviewer",
            reference, self.scope, self.now - timedelta(days=1),
            self.now + timedelta(days=1),
        )

    def corrupt_grant_client(self, grant_id: str, wrong_client: str):
        # Deliberately emulate ONE pre-existing corrupt/legacy persisted row.
        # No API call can create an authorization using this tampered row.
        with sqlite3.connect(self.db) as con:
            changed = con.execute(
                "UPDATE authorization_grants SET client_id=? WHERE grant_id=?",
                (wrong_client, grant_id),
            ).rowcount
        self.assertEqual(changed, 1)

    def row_snapshot(self):
        with sqlite3.connect(self.db) as con:
            return tuple(con.execute(
                "SELECT grant_id,client_id,engagement_id,approved_by,reference,"
                "assets_json,excluded_assets_json,allowed_capabilities_json,"
                "max_risk,valid_from,valid_until,recurring_retest_allowed,created_at "
                "FROM authorization_grants ORDER BY grant_id"
            ).fetchall())

    def test_canonical_tenant_a_grant_is_readable_and_current(self):
        good = self.grant(self.eng_a)
        self.assertEqual(
            [g.grant_id for g in self.store.list_authorization_grants(
                self.ctx_a, self.eng_a.engagement_id
            )], [good.grant_id],
        )
        current = self.store.get_current_grant(
            self.ctx_a, self.eng_a.engagement_id, now=self.now
        )
        self.assertEqual(current.grant_id, good.grant_id)
        self.assertEqual(current.client_id, self.a.client_id)

    def test_independent_tenant_b_control_and_operator_canonical_view(self):
        a = self.grant(self.eng_a, "fictional-a")
        b = self.grant(self.eng_b, "fictional-b")
        self.assertEqual(
            [g.grant_id for g in self.store.list_authorization_grants(
                self.ctx_b, self.eng_b.engagement_id
            )], [b.grant_id],
        )
        self.assertEqual(
            [g.grant_id for g in self.store.list_authorization_grants(
                self.operator, self.eng_a.engagement_id
            )], [a.grant_id],
        )

    def test_foreign_engagement_always_rejects_client_read(self):
        self.grant(self.eng_a)
        with self.assertRaises(TenantIsolationError):
            self.store.list_authorization_grants(
                self.ctx_b, self.eng_a.engagement_id
            )
        with self.assertRaises(TenantIsolationError):
            self.store.get_current_grant(
                self.ctx_b, self.eng_a.engagement_id, now=self.now
            )

    def test_expired_canonical_grant_not_current(self):
        self.grant(self.eng_a)
        self.assertIsNone(self.store.get_current_grant(
            self.ctx_a, self.eng_a.engagement_id,
            now=self.now + timedelta(days=2),
        ))

    def test_corrupt_grant_reads_leave_durable_bytes_unchanged(self):
        """Both original source and a future fail-closed fix must read only."""
        good = self.grant(self.eng_a)
        self.corrupt_grant_client(good.grant_id, self.b.client_id)
        before = self.row_snapshot()
        self.store.list_authorization_grants(
            self.ctx_a, self.eng_a.engagement_id
        )
        self.store.get_current_grant(
            self.ctx_a, self.eng_a.engagement_id, now=self.now
        )
        self.assertEqual(self.row_snapshot(), before)

    @unittest.expectedFailure
    def test_source_red_client_a_list_must_filter_corrupt_b_grant(self):
        good = self.grant(self.eng_a)
        self.corrupt_grant_client(good.grant_id, self.b.client_id)
        self.assertEqual(
            self.store.list_authorization_grants(
                self.ctx_a, self.eng_a.engagement_id
            ), [],
        )

    @unittest.expectedFailure
    def test_source_red_operator_list_must_filter_corrupt_grant(self):
        good = self.grant(self.eng_a)
        self.corrupt_grant_client(good.grant_id, self.b.client_id)
        self.assertEqual(
            self.store.list_authorization_grants(
                self.operator, self.eng_a.engagement_id
            ), [],
        )

    @unittest.expectedFailure
    def test_source_red_client_a_current_grant_must_reject_wrong_tenant(self):
        good = self.grant(self.eng_a)
        self.corrupt_grant_client(good.grant_id, self.b.client_id)
        self.assertIsNone(self.store.get_current_grant(
            self.ctx_a, self.eng_a.engagement_id, now=self.now
        ))

    @unittest.expectedFailure
    def test_source_red_operator_current_grant_must_reject_wrong_tenant(self):
        good = self.grant(self.eng_a)
        self.corrupt_grant_client(good.grant_id, self.b.client_id)
        self.assertIsNone(self.store.get_current_grant(
            self.operator, self.eng_a.engagement_id, now=self.now
        ))

    @unittest.expectedFailure
    def test_source_red_mixed_grants_must_preserve_only_valid_lineage(self):
        good = self.grant(self.eng_a, "fictional-good")
        bad = self.grant(self.eng_a, "fictional-bad")
        self.corrupt_grant_client(bad.grant_id, self.b.client_id)
        ids = [g.grant_id for g in self.store.list_authorization_grants(
            self.ctx_a, self.eng_a.engagement_id
        )]
        self.assertEqual(ids, [good.grant_id])

    @unittest.expectedFailure
    def test_source_red_unknown_persisted_client_must_not_escape(self):
        good = self.grant(self.eng_a)
        self.corrupt_grant_client(good.grant_id, "missing-fictional-client-id")
        self.assertEqual(
            self.store.list_authorization_grants(
                self.ctx_a, self.eng_a.engagement_id
            ), [],
        )


    @unittest.expectedFailure
    def test_source_red_current_grant_skips_newer_foreign_row(self):
        """A newer corrupt grant cannot mask an older valid current grant."""
        valid = self.grant(self.eng_a, "fictional-valid-older")
        foreign = self.grant(self.eng_a, "fictional-invalid-newer")
        self.corrupt_grant_client(foreign.grant_id, self.b.client_id)
        current = self.store.get_current_grant(
            self.ctx_a, self.eng_a.engagement_id, now=self.now
        )
        self.assertIsNotNone(current)
        self.assertEqual(current.grant_id, valid.grant_id)

    @unittest.expectedFailure
    def test_source_red_b_tenant_current_rejects_a_lineage(self):
        """Reversed A/B corruption must be denied for the other tenant too."""
        grant = self.grant(self.eng_b)
        self.corrupt_grant_client(grant.grant_id, self.a.client_id)
        self.assertIsNone(self.store.get_current_grant(
            self.ctx_b, self.eng_b.engagement_id, now=self.now
        ))

    @unittest.expectedFailure
    def test_source_red_padded_owner_id_is_not_equivalent(self):
        """Tenant IDs are exact opaque identifiers: never trim or normalize."""
        grant = self.grant(self.eng_a)
        self.corrupt_grant_client(grant.grant_id, " " + self.a.client_id + " ")
        self.assertEqual(self.store.list_authorization_grants(
            self.operator, self.eng_a.engagement_id
        ), [])

    @unittest.expectedFailure
    def test_source_red_binary_persisted_tenant_id_must_not_escape(self):
        """A BLOB stored by legacy/corrupt code must not become a grant."""
        grant = self.grant(self.eng_a)
        with sqlite3.connect(self.db) as con:
            con.execute(
                "UPDATE authorization_grants SET client_id=? WHERE grant_id=?",
                (sqlite3.Binary(self.a.client_id.encode("ascii")), grant.grant_id),
            )
        self.assertEqual(self.store.list_authorization_grants(
            self.ctx_a, self.eng_a.engagement_id
        ), [])

    @unittest.expectedFailure
    def test_source_red_injection_shaped_stored_id_is_never_authority(self):
        """SQL-like strings in durable rows must remain inert and rejected."""
        grant = self.grant(self.eng_a)
        self.corrupt_grant_client(grant.grant_id, "' OR 1=1 -- fictional")
        self.assertIsNone(self.store.get_current_grant(
            self.operator, self.eng_a.engagement_id, now=self.now
        ))

    @unittest.expectedFailure
    def test_source_red_multiple_corrupt_grants_keep_only_valid(self):
        """Filtering must cover EVERY row, not only newest or first."""
        good = self.grant(self.eng_a, "fictional-valid")
        foreign = self.grant(self.eng_a, "fictional-wrong-owner")
        missing = self.grant(self.eng_a, "fictional-missing-owner")
        self.corrupt_grant_client(foreign.grant_id, self.b.client_id)
        self.corrupt_grant_client(missing.grant_id, "missing-fictional-client")
        before = self.row_snapshot()
        observed = self.store.list_authorization_grants(
            self.operator, self.eng_a.engagement_id
        )
        self.assertEqual([g.grant_id for g in observed], [good.grant_id])
        self.assertEqual(self.row_snapshot(), before)

    def test_canonical_two_grants_keep_durable_read_order(self):
        older = self.grant(self.eng_a, "fictional-older")
        newer = self.grant(self.eng_a, "fictional-newer")
        rows = self.store.list_authorization_grants(
            self.ctx_a, self.eng_a.engagement_id
        )
        self.assertEqual([x.grant_id for x in rows], [
            newer.grant_id, older.grant_id
        ])
        self.assertEqual(
            self.store.get_current_grant(
                self.ctx_a, self.eng_a.engagement_id, now=self.now
            ).grant_id, newer.grant_id,
        )

    @unittest.expectedFailure
    def test_source_red_rebound_engagement_owner_cannot_leak_old_grant(self):
        """An owner change between authorization and SELECT must HOLD."""
        good = self.grant(self.eng_a)
        original = self.store.get_engagement

        def rebind_after_access_check(ctx, engagement_id):
            checked = original(ctx, engagement_id)
            with sqlite3.connect(self.db) as con:
                con.execute(
                    "UPDATE engagements SET client_id=? WHERE engagement_id=?",
                    (self.b.client_id, engagement_id),
                )
            return checked

        before = self.row_snapshot()
        with patch.object(
            self.store, "get_engagement", side_effect=rebind_after_access_check
        ):
            grants = self.store.list_authorization_grants(
                self.ctx_a, self.eng_a.engagement_id
            )
        self.assertEqual(grants, [])
        self.assertEqual(self.row_snapshot(), before)
        self.assertNotEqual(good.client_id, self.b.client_id)

    @unittest.expectedFailure
    def test_source_red_operator_current_must_reject_rebound_engagement(self):
        """Even an operator cannot treat a stale pre-rebind grant as current."""
        self.grant(self.eng_a)
        original = self.store.get_engagement

        def rebind_after_access_check(ctx, engagement_id):
            checked = original(ctx, engagement_id)
            with sqlite3.connect(self.db) as con:
                con.execute(
                    "UPDATE engagements SET client_id=? WHERE engagement_id=?",
                    (self.b.client_id, engagement_id),
                )
            return checked

        with patch.object(
            self.store, "get_engagement", side_effect=rebind_after_access_check
        ):
            current = self.store.get_current_grant(
                self.operator, self.eng_a.engagement_id, now=self.now
            )
        self.assertIsNone(current)

    @unittest.expectedFailure
    def test_source_red_foreign_corrupt_scope_cannot_break_valid_listing(self):
        """A wrong-tenant grant's corrupt JSON must be filtered before decode."""
        good = self.grant(self.eng_a, "fictional-valid-json")
        foreign = self.grant(self.eng_a, "fictional-foreign-bad-json")
        with sqlite3.connect(self.db) as con:
            con.execute(
                "UPDATE authorization_grants SET client_id=?, assets_json=? "
                "WHERE grant_id=?",
                (self.b.client_id, "{broken fictional JSON", foreign.grant_id),
            )
        before = self.row_snapshot()
        rows = self.store.list_authorization_grants(
            self.ctx_a, self.eng_a.engagement_id
        )
        self.assertEqual([r.grant_id for r in rows], [good.grant_id])
        self.assertEqual(self.row_snapshot(), before)

    @unittest.expectedFailure
    def test_source_red_foreign_invalid_window_does_not_poison_current(self):
        """Unowned timestamp garbage cannot prevent reading a valid A grant."""
        good = self.grant(self.eng_a, "fictional-valid-date")
        foreign = self.grant(self.eng_a, "fictional-foreign-bad-date")
        with sqlite3.connect(self.db) as con:
            con.execute(
                "UPDATE authorization_grants SET client_id=?,valid_until=? "
                "WHERE grant_id=?",
                (self.b.client_id, "not-a-fictional-datetime", foreign.grant_id),
            )
        current = self.store.get_current_grant(
            self.ctx_a, self.eng_a.engagement_id, now=self.now
        )
        self.assertIsNotNone(current)
        self.assertEqual(current.grant_id, good.grant_id)


if __name__ == "__main__":
    unittest.main()
