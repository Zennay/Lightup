"""Real disposable-SQLite safety acceptance for issue #177; no customer data."""
from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import AssessmentMode, EngagementStatus, RiskLevel, ScopeDefinition
from lightup.request_grant_offline_review_177 import ReviewStatus
from lightup import request_grant_sqlite_preflight_177 as persisted_review
from lightup.request_grant_sqlite_preflight_177 import (
    review_persisted_request_grant,
    review_persisted_grant_batch,
    _has_provenance_fk,
    _bound_sqlite_work,
)


class PersistedRequestGrantSqlitePreflightTests(unittest.TestCase):
    """All SQL fixtures are isolated temporary DBs; no network or active target."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="lightup-177-synthetic-")
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "scope-fixture.sqlite3"
        self.store = DomainStore(self.path)
        self.operator = AccessContext("synthetic-operator", Role.OPERATOR)
        client = self.store.create_client(self.operator, "Synthetic client")
        self.client = client.client_id
        self.member = AccessContext("synthetic-client-member", Role.CLIENT_MEMBER, client.client_id)
        self.request = self.store.submit_assessment_request(
            self.member,
            requested_assets=("app.example.test", "api.example.test"),
            requested_mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            requested_risk=RiskLevel.STANDARD,
        )
        self.request = self.store.review_assessment_request(
            self.operator, self.request.request_id, True
        )
        engagement = self.store.create_engagement(self.operator, client.client_id, "Synthetic plan")
        self.engagement = engagement.engagement_id
        self.now = datetime.now(timezone.utc)
        self.valid_from = self.now + timedelta(minutes=1)
        self.reviewed_at = self.now + timedelta(minutes=2)
        self.grant = self.store.record_authorization_grant(
            self.operator,
            engagement.engagement_id,
            self.operator.user_id,
            "FICTIONAL-REQUEST-ONLY",
            ScopeDefinition(
                assets=("app.example.test",),
                max_risk=RiskLevel.LOW_IMPACT,
                allowed_capabilities=("web-baseline",),
            ),
            self.valid_from,
            self.now + timedelta(days=1),
        )
        self.store.set_engagement_status(
            self.operator, engagement.engagement_id, EngagementStatus.AUTHORIZED
        )

    def review(self, db=None, grant_id=None, instant=None):
        return review_persisted_request_grant(
            self.path if db is None else db,
            self.grant.grant_id if grant_id is None else grant_id,
            reviewed_at=self.reviewed_at if instant is None else instant,
        )

    def assert_hold(self):
        self.assertIs(self.review().status, ReviewStatus.HOLD)

    def assert_no_authority(self, result):
        for item in (
            "authorized", "grant_allowed", "dispatch_allowed",
            "scan_allowed", "merge_allowed", "deploy_allowed",
        ):
            self.assertIs(getattr(result, item), False)
        self.assertNotIn(self.client, str(result))
        self.assertNotIn("app.example.test", str(result))

    def upgrade_synthetic_only(self):
        # TEST-ONLY migration, never executed on an actual production database.
        with sqlite3.connect(self.path) as con:
            con.execute("PRAGMA foreign_keys=ON")
            con.execute(
                "ALTER TABLE authorization_grants "
                "ADD COLUMN approved_request_id TEXT REFERENCES assessment_requests(request_id)"
            )
            con.execute(
                "UPDATE authorization_grants SET approved_request_id=? WHERE grant_id=?",
                (self.request.request_id, self.grant.grant_id),
            )

    def update(self, table, field, value, key, key_value):
        # Mutations are permitted only in this isolated real SQLite test fixture.
        assert table in ("authorization_grants", "assessment_requests", "engagements")
        assert field in (
            "approved_request_id", "client_id", "engagement_id", "status",
            "requested_mode", "requested_risk", "requested_assets_json", "max_risk",
            "assets_json", "allowed_capabilities_json", "decided_by", "decided_at",
            "valid_from", "valid_until", "created_at", "recurring_retest_allowed",
        )
        assert key in ("grant_id", "request_id", "engagement_id")
        with sqlite3.connect(self.path) as con:
            updated = con.execute(
                f"UPDATE {table} SET {field}=? WHERE {key}=?",
                (value, key_value),
            ).rowcount
            self.assertEqual(updated, 1, "synthetic mutation must affect exactly one row")

    # Producer-level acceptance is intentionally RED until source-owner #177
    # adds the actual durable approved-request FK invariant. These tests
    # exercise REAL DomainStore methods against disposable local SQLite.
    @unittest.expectedFailure
    def test_red_domain_grant_without_approved_request_must_be_denied(self):
        other = self.store.create_client(self.operator, "No approval synthetic client")
        engagement = self.store.create_engagement(
            self.operator, other.client_id, "No request fixture"
        )
        with self.assertRaises(ValueError):
            self.store.record_authorization_grant(
                self.operator, engagement.engagement_id, self.operator.user_id,
                "NOT-A-CONSENT-RECORD",
                ScopeDefinition(
                    assets=("unapproved.example.test",),
                    max_risk=RiskLevel.LOW_IMPACT,
                    allowed_capabilities=("web-baseline",),
                ),
                self.valid_from, self.now + timedelta(days=1),
            )

    @unittest.expectedFailure
    def test_red_domain_grant_target_beyond_approved_request_must_be_denied(self):
        with self.assertRaises(ValueError):
            self.store.record_authorization_grant(
                self.operator, self.engagement, self.operator.user_id,
                "SYNTHETIC-ASSET-EXPANSION",
                ScopeDefinition(
                    assets=("outside-approved-request.example.test",),
                    max_risk=RiskLevel.LOW_IMPACT,
                    allowed_capabilities=("web-baseline",),
                ),
                self.valid_from, self.now + timedelta(days=1),
            )

    @unittest.expectedFailure
    def test_red_domain_grant_wrong_approval_operator_must_be_denied(self):
        with self.assertRaises(ValueError):
            self.store.record_authorization_grant(
                self.operator, self.engagement, "unrelated-operator",
                "SYNTHETIC-UNBOUND-APPROVER",
                ScopeDefinition(
                    assets=("app.example.test",),
                    max_risk=RiskLevel.LOW_IMPACT,
                    allowed_capabilities=("web-baseline",),
                ),
                self.valid_from, self.now + timedelta(days=1),
            )

    @unittest.expectedFailure
    def test_red_domain_recurring_retest_without_request_consent_must_be_denied(self):
        # The approved request model has NO field attesting to independent
        # customer authorization for recurring active assessments.
        with self.assertRaises(ValueError):
            self.store.record_authorization_grant(
                self.operator, self.engagement, self.operator.user_id,
                "UNCONSENTED-RECURRING-SYNTHETIC",
                ScopeDefinition(
                    assets=("app.example.test",),
                    max_risk=RiskLevel.LOW_IMPACT,
                    allowed_capabilities=("web-baseline",),
                ),
                self.valid_from, self.now + timedelta(days=1),
                recurring_retest_allowed=True,
            )

    @unittest.expectedFailure
    def test_red_operator_cannot_approve_own_client_request(self):
        other = self.store.create_client(self.operator, "Operator-created fixture")
        submitted = self.store.submit_assessment_request(
            self.operator,
            requested_assets=("operator-created.example.test",),
            requested_mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            requested_risk=RiskLevel.STANDARD,
            client_id=other.client_id,
        )
        self.assertEqual(submitted.requested_by, self.operator.user_id)
        with self.assertRaises(ValueError):
            self.store.review_assessment_request(
                self.operator, submitted.request_id, True
            )

    @unittest.expectedFailure
    def test_red_domain_rejected_request_must_never_authorize_grant(self):
        other = self.store.create_client(self.operator, "Rejected synthetic client")
        member = AccessContext(
            "rejected-client-member", Role.CLIENT_MEMBER, other.client_id
        )
        request = self.store.submit_assessment_request(
            member, ("rejected.example.test",),
            AssessmentMode.AUTHORIZED_ASSESSMENT, RiskLevel.STANDARD,
        )
        self.store.review_assessment_request(self.operator, request.request_id, False)
        engagement = self.store.create_engagement(
            self.operator, other.client_id, "Rejected request fixture"
        )
        with self.assertRaises(ValueError):
            self.store.record_authorization_grant(
                self.operator, engagement.engagement_id, self.operator.user_id,
                "REJECTED-REQUEST-IS-NOT-CONSENT",
                ScopeDefinition(
                    assets=("rejected.example.test",),
                    max_risk=RiskLevel.LOW_IMPACT,
                    allowed_capabilities=("web-baseline",),
                ),
                self.valid_from, self.now + timedelta(days=1),
            )

    def test_shipped_domain_schema_without_request_fk_is_always_hold(self):
        self.assert_hold()
        # Regression: even existing matching APPROVED request cannot imply
        # authority when the grant has NO persisted request_id FK.
        r = self.review()
        self.assert_no_authority(r)
        self.assertEqual(r.reason, "invalid_or_unverified_input")

    def test_unknown_db_never_gets_created_by_read_only_review(self):
        absent = self.path.parent / "does-not-exist.sqlite3"
        r = self.review(db=absent)
        self.assertIs(r.status, ReviewStatus.HOLD)
        self.assertFalse(absent.exists())
        self.assert_no_authority(r)

    def test_explicit_synthetic_fk_can_only_be_review_only(self):
        self.upgrade_synthetic_only()
        r = self.review()
        self.assertIs(r.status, ReviewStatus.REVIEW_ONLY)
        self.assert_no_authority(r)
        with self.assertRaises((FrozenInstanceError, AttributeError)):
            r.authorized = True

    def test_unlinked_nullable_fk_and_invalid_grant_id_hold(self):
        self.upgrade_synthetic_only()
        self.update(
            "authorization_grants", "approved_request_id", None,
            "grant_id", self.grant.grant_id,
        )
        self.assert_hold()
        self.assertIs(self.review(grant_id="no-such-grant").status, ReviewStatus.HOLD)
        self.assertIs(self.review(grant_id=" ").status, ReviewStatus.HOLD)

    def test_invalid_request_state_mode_and_risk_hold(self):
        corruptions = (
            ("assessment_requests", "status", "rejected", "request_id"),
            ("assessment_requests", "status", "approve", "request_id"),
            ("assessment_requests", "requested_mode", "passive_discovery", "request_id"),
            ("assessment_requests", "requested_risk", "invalid", "request_id"),
            ("assessment_requests", "requested_risk", 0, "request_id"),
            ("authorization_grants", "max_risk", 4, "grant_id"),
        )
        for index, (table, field, val, key) in enumerate(corruptions):
            with self.subTest(field=field, value=val):
                if index:
                    self._reset_fixture()
                self.upgrade_synthetic_only()
                # Re-resolve the ID of the fresh fixture rather than reusing
                # a stale UUID from the first setup.
                identity = (
                    self.request.request_id if key == "request_id"
                    else self.grant.grant_id
                )
                self.update(table, field, val, key, identity)
                self.assert_hold()

    def _reset_fixture(self):
        # Re-initialize a fresh disposable DB between independent corruptions.
        self.tmp.cleanup()
        self.setUp()

    def test_persisted_grant_created_at_must_follow_review_decision(self):
        decided = datetime.fromisoformat(self.request.decided_at)
        for index, invalid in enumerate((
            (decided - timedelta(seconds=1)).isoformat(),
            (self.reviewed_at + timedelta(seconds=1)).isoformat(),
            "2030-01-31T24:00:00+00:00",
            "2030-01-31T10:00:00+01:00",
            "",
        )):
            with self.subTest(created_at=invalid):
                if index:
                    self._reset_fixture()
                self.upgrade_synthetic_only()
                self.update(
                    "authorization_grants", "created_at", invalid,
                    "grant_id", self.grant.grant_id,
                )
                self.assert_hold()

    def test_backdated_grant_activation_cannot_precede_record_creation(self):
        self.upgrade_synthetic_only()
        with sqlite3.connect(self.path) as con:
            original = con.execute(
                "SELECT created_at, valid_from FROM authorization_grants WHERE grant_id=?",
                (self.grant.grant_id,),
            ).fetchone()
        recorded = datetime.fromisoformat(original[0])
        decided = datetime.fromisoformat(self.request.decided_at)
        # Keep the claimed grant window after approval so the regression
        # specifically detects backdating BEFORE grant persistence.
        self.assertLess(decided, recorded)
        self.assertLess(recorded, datetime.fromisoformat(original[1]))
        retroactive_start = recorded - timedelta(microseconds=1)
        self.assertGreaterEqual(retroactive_start, decided)
        self.update(
            "authorization_grants", "valid_from", retroactive_start.isoformat(),
            "grant_id", self.grant.grant_id,
        )
        result = self.review()
        self.assertIs(result.status, ReviewStatus.HOLD)
        self.assert_no_authority(result)

    def test_grant_cannot_predate_its_engagement_even_if_window_matches(self):
        self.upgrade_synthetic_only()
        with sqlite3.connect(self.path) as con:
            recorded = datetime.fromisoformat(con.execute(
                "SELECT created_at FROM authorization_grants WHERE grant_id=?",
                (self.grant.grant_id,),
            ).fetchone()[0])
        future_engagement_creation = recorded + timedelta(seconds=1)
        # Engagement still predates the declared validity window; only the
        # new durable grant-record chronology check can reject this.
        self.assertLess(future_engagement_creation, self.valid_from)
        self.update(
            "engagements", "created_at", future_engagement_creation.isoformat(),
            "engagement_id", self.engagement,
        )
        result = self.review()
        self.assertIs(result.status, ReviewStatus.HOLD)
        self.assert_no_authority(result)

    def test_exact_grant_created_at_equal_to_start_is_only_reviewable(self):
        self.upgrade_synthetic_only()
        # Monotonic equality is allowed for structural review, never as
        # verified consent or execution permission.
        self.update(
            "authorization_grants", "created_at", self.valid_from.isoformat(),
            "grant_id", self.grant.grant_id,
        )
        result = self.review()
        self.assertIs(result.status, ReviewStatus.REVIEW_ONLY)
        self.assert_no_authority(result)

    def test_persisted_self_approval_must_hold_even_with_matching_fk(self):
        self.upgrade_synthetic_only()
        with sqlite3.connect(self.path) as con:
            affected = con.execute(
                "UPDATE assessment_requests SET requested_by=? WHERE request_id=?",
                (self.operator.user_id, self.request.request_id),
            ).rowcount
            self.assertEqual(affected, 1)
        self.assert_hold()

    def test_real_tenant_and_decider_lineage_mismatches_hold(self):
        corruptions = (
            ("authorization_grants", "client_id", "foreign", "grant_id"),
            ("engagements", "client_id", "foreign", "engagement_id"),
            ("assessment_requests", "client_id", "foreign", "request_id"),
        )
        for index, (table, field, val, key) in enumerate(corruptions):
            with self.subTest(field=field, value=val):
                if index:
                    self._reset_fixture()
                self.upgrade_synthetic_only()
                identity = {
                    "grant_id": self.grant.grant_id,
                    "request_id": self.request.request_id,
                    "engagement_id": self.engagement,
                }[key]
                self.update(table, field, val, key, identity)
                self.assert_hold()
        self._reset_fixture()
        self.upgrade_synthetic_only()
        with sqlite3.connect(self.path) as con:
            changed = con.execute(
                "UPDATE authorization_grants SET approved_by=? WHERE grant_id=?",
                ("different-operator", self.grant.grant_id),
            ).rowcount
            self.assertEqual(changed, 1)
        self.assert_hold()

    def test_corrupt_json_and_unknown_capability_hold(self):
        for table, column, payload, key in (
            ("assessment_requests", "requested_assets_json", '{"asset": "app.example.test"}', "request_id"),
            ("assessment_requests", "requested_assets_json", '["app.example.test",7]', "request_id"),
            ("authorization_grants", "assets_json", '["outsider.example.test"]', "grant_id"),
            ("authorization_grants", "allowed_capabilities_json", '[]', "grant_id"),
            ("authorization_grants", "allowed_capabilities_json", '["wireless-lab"]', "grant_id"),
            ("authorization_grants", "allowed_capabilities_json", '["not-a-tool"]', "grant_id"),
        ):
            with self.subTest(field=column, payload=payload):
                self.upgrade_synthetic_only()
                self.update(
                    table, column, payload, key,
                    self.request.request_id if key == "request_id" else self.grant.grant_id,
                )
                self.assert_hold()
                self._reset_fixture()

    def test_real_sqlite_empty_validity_interval_cannot_be_reviewed(self):
        self.upgrade_synthetic_only()
        self.update(
            "authorization_grants", "valid_until", self.valid_from.isoformat(),
            "grant_id", self.grant.grant_id,
        )
        # At the one coincident instant, old inclusive comparisons would
        # have reported REVIEW_ONLY for an impossible zero-length interval.
        receipt = self.review(instant=self.valid_from)
        self.assertIs(receipt.status, ReviewStatus.HOLD)
        self.assert_no_authority(receipt)

    def test_real_sqlite_retest_flag_true_has_no_matching_request_optin(self):
        self.upgrade_synthetic_only()
        self.update(
            "authorization_grants", "recurring_retest_allowed", 1,
            "grant_id", self.grant.grant_id,
        )
        result = self.review()
        self.assertIs(result.status, ReviewStatus.HOLD)
        self.assert_no_authority(result)

    def test_corrupt_grant_dates_and_retest_flag_hold(self):
        for field, value in (
            ("valid_from", "2030-01-31T24:00:00+00:00"),
            ("valid_from", "2030-01-31T10:00:00+01:00"),
            ("valid_until", "garbage"),
            ("recurring_retest_allowed", 2),
            ("recurring_retest_allowed", "true"),
        ):
            with self.subTest(field=field, value=value):
                self.upgrade_synthetic_only()
                self.update("authorization_grants", field, value, "grant_id", self.grant.grant_id)
                self.assert_hold()
                self._reset_fixture()

    def test_wrong_engagement_status_or_approved_request_hold(self):
        self.upgrade_synthetic_only()
        self.update("engagements", "status", "running", "engagement_id", self.engagement)
        self.assert_hold()

    def test_self_asserted_fk_like_column_without_sqlite_constraint_hold(self):
        # Never trust self-asserted approved_request_id without an actual FK.
        with sqlite3.connect(self.path) as con:
            con.execute(
                "ALTER TABLE authorization_grants "
                "ADD COLUMN approved_request_id TEXT"
            )
            con.execute(
                "UPDATE authorization_grants SET approved_request_id=? WHERE grant_id=?",
                (self.request.request_id, self.grant.grant_id),
            )
        self.assert_hold()

    def test_declared_fk_must_be_exactly_one_independent_column(self):
        # Isolated in-memory SQLite schema only; no real client database.
        with sqlite3.connect(":memory:") as con:
            con.executescript("""
                CREATE TABLE assessment_requests(
                    request_id TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    UNIQUE(request_id, client_id)
                );
                CREATE TABLE authorization_grants(
                    grant_id TEXT PRIMARY KEY,
                    approved_request_id TEXT,
                    client_id TEXT,
                    FOREIGN KEY(approved_request_id, client_id)
                        REFERENCES assessment_requests(request_id, client_id)
                );
            """)
            introspection = con.execute(
                "PRAGMA foreign_key_list(authorization_grants)"
            ).fetchall()
            self.assertEqual(len(introspection), 2)
            self.assertEqual(introspection[0][3], "approved_request_id")
            self.assertEqual(introspection[0][1], 0)
            self.assertFalse(_has_provenance_fk(con))

    def test_single_column_fk_is_required_but_not_release_authority(self):
        with sqlite3.connect(":memory:") as con:
            con.executescript("""
                CREATE TABLE assessment_requests(request_id TEXT PRIMARY KEY);
                CREATE TABLE authorization_grants(
                    grant_id TEXT PRIMARY KEY,
                    approved_request_id TEXT
                        REFERENCES assessment_requests(request_id)
                );
            """)
            self.assertTrue(_has_provenance_fk(con))
            # The isolated schema lacks the full requested asset/engagement
            # evidence, so a real review remains HOLD.
        self.upgrade_synthetic_only()
        actual = self.review()
        self.assertIs(actual.status, ReviewStatus.REVIEW_ONLY)
        self.assert_no_authority(actual)

    def test_fk_to_wrong_parent_column_cannot_imply_approved_request(self):
        with sqlite3.connect(":memory:") as con:
            con.executescript("""
                CREATE TABLE assessment_requests(
                    request_id TEXT PRIMARY KEY,
                    alias TEXT UNIQUE
                );
                CREATE TABLE authorization_grants(
                    approved_request_id TEXT
                        REFERENCES assessment_requests(alias)
                );
            """)
            self.assertFalse(_has_provenance_fk(con))

    def test_sqlite_fk_schema_still_cannot_authorize_real_targets(self):
        self.upgrade_synthetic_only()
        with sqlite3.connect(self.path) as con:
            rows = con.execute("PRAGMA foreign_key_list(authorization_grants)").fetchall()
            self.assertTrue(any(
                row[2] == "assessment_requests"
                and row[3] == "approved_request_id"
                and row[4] == "request_id"
                for row in rows
            ))
        result = self.review()
        self.assertIs(result.status, ReviewStatus.REVIEW_ONLY)
        self.assert_no_authority(result)

    def test_no_changes_after_review_of_real_sqlite_snapshot(self):
        self.upgrade_synthetic_only()
        def snapshot():
            with sqlite3.connect(self.path) as con:
                return (
                    con.execute("SELECT * FROM assessment_requests").fetchall(),
                    con.execute("SELECT * FROM authorization_grants").fetchall(),
                    con.execute("SELECT * FROM engagements").fetchall(),
                )
        before = snapshot()
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            result = self.review()
        self.assertIs(result.status, ReviewStatus.REVIEW_ONLY)
        self.assertEqual(snapshot(), before)

    def _second_synthetic_grant(self, asset="api.example.test"):
        req = self.store.submit_assessment_request(
            self.member,
            requested_assets=(asset,),
            requested_mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            requested_risk=RiskLevel.STANDARD,
        )
        req = self.store.review_assessment_request(self.operator, req.request_id, True)
        granted = self.store.record_authorization_grant(
            self.operator,
            self.engagement,
            self.operator.user_id,
            "SECOND-FICTIONAL-REQUEST",
            ScopeDefinition(
                assets=(asset,),
                max_risk=RiskLevel.LOW_IMPACT,
                allowed_capabilities=("web-baseline",),
            ),
            self.valid_from,
            self.now + timedelta(days=1),
        )
        with sqlite3.connect(self.path) as con:
            con.execute(
                "UPDATE authorization_grants SET approved_request_id=? WHERE grant_id=?",
                (req.request_id, granted.grant_id),
            )
        return granted.grant_id

    def test_malformed_link_can_refer_to_real_parent_and_still_hold(self):
        # The SQL foreign key validates *equality*, not the canonical ID
        # grammar of the referenced approval. Both rows can be internally
        # consistent but unsupported as proof of a real approved request.
        with sqlite3.connect(":memory:") as con:
            con.executescript("""
                PRAGMA foreign_keys=ON;
                CREATE TABLE assessment_requests(request_id TEXT PRIMARY KEY);
                CREATE TABLE authorization_grants(
                    approved_request_id TEXT
                    REFERENCES assessment_requests(request_id)
                );
                INSERT INTO assessment_requests VALUES('bad/approval/key');
                INSERT INTO authorization_grants VALUES('bad/approval/key');
            """)
            self.assertEqual(con.execute(
                "PRAGMA foreign_key_check(authorization_grants)"
            ).fetchall(), [])
            self.assertFalse(_has_provenance_fk(con))

    def test_other_null_request_reference_holds_despite_clean_sqlite_fk_check(self):
        self.upgrade_synthetic_only()
        other = self._second_synthetic_grant("api.example.test")
        self.assertIs(self.review().status, ReviewStatus.REVIEW_ONLY)
        with sqlite3.connect(self.path) as con:
            changed = con.execute(
                "UPDATE authorization_grants SET approved_request_id=NULL "
                "WHERE grant_id=?",
                (other,),
            ).rowcount
            self.assertEqual(changed, 1)
            # SQLite explicitly permits NULL child FKs. Ordinary integrity
            # checks cannot prove that ALL grants have verified approval.
            self.assertEqual(
                con.execute("PRAGMA foreign_key_check(authorization_grants)").fetchall(),
                [],
            )
        chosen = self.review()
        self.assertIs(chosen.status, ReviewStatus.HOLD)
        self.assert_no_authority(chosen)
        batch = review_persisted_grant_batch(
            self.path, (self.grant.grant_id,), reviewed_at=self.reviewed_at
        )
        self.assertIs(batch.status, ReviewStatus.HOLD)
        self.assert_no_authority(batch)

    def test_null_request_reference_is_not_a_valid_offline_schema_proof(self):
        with sqlite3.connect(":memory:") as con:
            con.executescript("""
                PRAGMA foreign_keys=ON;
                CREATE TABLE assessment_requests(request_id TEXT PRIMARY KEY);
                CREATE TABLE authorization_grants(
                    grant_id TEXT PRIMARY KEY,
                    approved_request_id TEXT
                        REFERENCES assessment_requests(request_id)
                );
                INSERT INTO authorization_grants VALUES('grant-without-consent', NULL);
            """)
            self.assertEqual(
                con.execute("PRAGMA foreign_key_check(authorization_grants)").fetchall(),
                [],
            )
            self.assertFalse(_has_provenance_fk(con))

    def test_other_orphan_grant_fk_corruption_holds_entire_sqlite_snapshot(self):
        self.upgrade_synthetic_only()
        unrelated = self._second_synthetic_grant("api.example.test")
        self.assertIs(self.review().status, ReviewStatus.REVIEW_ONLY)
        # Simulate a separate misconfigured writer with foreign_keys=OFF:
        # the FK is DECLARED but not necessarily enforced on all writers.
        with sqlite3.connect(self.path) as con:
            con.execute("PRAGMA foreign_keys=OFF")
            affected = con.execute(
                "UPDATE authorization_grants SET approved_request_id=? WHERE grant_id=?",
                ("ghost-approved-request", unrelated),
            ).rowcount
            self.assertEqual(affected, 1)
            broken = con.execute(
                "PRAGMA foreign_key_check(authorization_grants)"
            ).fetchall()
            self.assertTrue(broken)
        # This review concerns the *first*, otherwise intact grant.
        # Broken provenance in a different grant prevents even structural
        # REVIEW_ONLY for a shared untrusted database snapshot.
        receipt = self.review()
        self.assertIs(receipt.status, ReviewStatus.HOLD)
        self.assert_no_authority(receipt)
        batch = review_persisted_grant_batch(
            self.path, (self.grant.grant_id,), reviewed_at=self.reviewed_at,
        )
        self.assertIs(batch.status, ReviewStatus.HOLD)
        self.assert_no_authority(batch)

    def test_single_grant_holds_when_other_stored_grant_reuses_approval(self):
        self.upgrade_synthetic_only()
        second_id = self._second_synthetic_grant("api.example.test")
        # Two fully coherent, independent synthetic requests initially pass.
        self.assertIs(self.review().status, ReviewStatus.REVIEW_ONLY)
        self.assertIs(self.review(grant_id=second_id).status, ReviewStatus.REVIEW_ONLY)

        with sqlite3.connect(self.path) as con:
            modified = con.execute(
                "UPDATE authorization_grants SET approved_request_id=? "
                "WHERE grant_id=?",
                (self.request.request_id, second_id),
            ).rowcount
            self.assertEqual(modified, 1)
            # The declared FK still points to a real row! Ordinary FK
            # checks alone do not detect that consent was reused.
            self.assertEqual(con.execute(
                "PRAGMA foreign_key_check(authorization_grants)"
            ).fetchall(), [])

        for inspected in (self.grant.grant_id, second_id):
            with self.subTest(grant_id=inspected):
                decision = self.review(grant_id=inspected)
                self.assertIs(decision.status, ReviewStatus.HOLD)
                self.assert_no_authority(decision)
                one_entry_batch = review_persisted_grant_batch(
                    self.path, (inspected,), reviewed_at=self.reviewed_at
                )
                self.assertIs(one_entry_batch.status, ReviewStatus.HOLD)
                self.assert_no_authority(one_entry_batch)

    def test_unreviewed_expired_grant_still_blocks_reused_approval(self):
        self.upgrade_synthetic_only()
        second_id = self._second_synthetic_grant("api.example.test")
        with sqlite3.connect(self.path) as con:
            changed = con.execute(
                "UPDATE authorization_grants "
                "SET approved_request_id=?, valid_until=? WHERE grant_id=?",
                (
                    self.request.request_id,
                    (self.now - timedelta(days=3)).isoformat(),
                    second_id,
                ),
            ).rowcount
            self.assertEqual(changed, 1)
        # A stale, expired record is still persisted approval reuse without
        # any authenticated replacement/revocation provenance.
        decision = self.review()
        self.assertIs(decision.status, ReviewStatus.HOLD)
        self.assert_no_authority(decision)

    def test_distinct_approved_requests_remain_review_only(self):
        self.upgrade_synthetic_only()
        second_id = self._second_synthetic_grant("api.example.test")
        first_decision = self.review()
        second_decision = self.review(grant_id=second_id)
        self.assertIs(first_decision.status, ReviewStatus.REVIEW_ONLY)
        self.assertIs(second_decision.status, ReviewStatus.REVIEW_ONLY)
        self.assert_no_authority(first_decision)
        self.assert_no_authority(second_decision)

    def test_atomic_persisted_batch_two_valid_is_still_review_only(self):
        self.upgrade_synthetic_only()
        second_id = self._second_synthetic_grant()
        result = review_persisted_grant_batch(
            self.path, (self.grant.grant_id, second_id),
            reviewed_at=self.reviewed_at,
        )
        self.assertIs(result.status, ReviewStatus.REVIEW_ONLY)
        self.assert_no_authority(result)

    def test_persisted_batch_scans_fk_consistency_once_per_snapshot(self):
        self.upgrade_synthetic_only()
        second_id = self._second_synthetic_grant()
        with patch.object(
            persisted_review, "_has_provenance_fk",
            wraps=persisted_review._has_provenance_fk,
        ) as inspected:
            review = review_persisted_grant_batch(
                self.path, (self.grant.grant_id, second_id),
                reviewed_at=self.reviewed_at,
            )
        self.assertIs(review.status, ReviewStatus.REVIEW_ONLY)
        self.assert_no_authority(review)
        self.assertEqual(inspected.call_count, 1)

    def test_fk_consistency_is_rechecked_each_independent_snapshot(self):
        self.upgrade_synthetic_only()
        second_id = self._second_synthetic_grant()
        candidate = (self.grant.grant_id, second_id)
        self.assertIs(
            review_persisted_grant_batch(
                self.path, candidate, reviewed_at=self.reviewed_at
            ).status, ReviewStatus.REVIEW_ONLY,
        )
        with sqlite3.connect(self.path) as con:
            con.execute("PRAGMA foreign_keys=OFF")
            self.assertEqual(con.execute(
                "UPDATE authorization_grants SET approved_request_id=? "
                "WHERE grant_id=?",
                ("orphaned-after-review", second_id),
            ).rowcount, 1)
        outcome = review_persisted_grant_batch(
            self.path, candidate, reviewed_at=self.reviewed_at
        )
        self.assertIs(outcome.status, ReviewStatus.HOLD)
        self.assert_no_authority(outcome)

    def test_offline_sqlite_vm_budget_interrupts_pathological_local_query(self):
        # Exercise the very same per-connection progress cap without creating
        # millions of real rows or contacting any external system.
        with sqlite3.connect(":memory:") as con:
            _bound_sqlite_work(con)
            with self.assertRaises(sqlite3.OperationalError):
                con.execute(
                    "WITH RECURSIVE counter(n) AS "
                    "(SELECT 0 UNION ALL SELECT n+1 FROM counter "
                    "WHERE n < 10000000) SELECT count(*) FROM counter"
                ).fetchone()

    def test_sqlite_progress_limit_does_not_break_small_genuine_snapshots(self):
        self.upgrade_synthetic_only()
        second = self._second_synthetic_grant()
        self.assertIs(self.review().status, ReviewStatus.REVIEW_ONLY)
        whole = review_persisted_grant_batch(
            self.path, (self.grant.grant_id, second),
            reviewed_at=self.reviewed_at,
        )
        self.assertIs(whole.status, ReviewStatus.REVIEW_ONLY)
        self.assert_no_authority(whole)

    def test_atomic_persisted_batch_denies_all_invalid_shapes(self):
        self.upgrade_synthetic_only()
        for ids in (
            (), [], None, ("",), ("wrong",), (self.grant.grant_id,) * 2,
            (self.grant.grant_id, 7), (self.grant.grant_id,) * 33,
        ):
            with self.subTest(ids_type=type(ids).__name__):
                result = review_persisted_grant_batch(
                    self.path, ids, reviewed_at=self.reviewed_at
                )
                self.assertIs(result.status, ReviewStatus.HOLD)
                self.assert_no_authority(result)

    def test_atomic_persisted_batch_denies_overlapping_effective_assets(self):
        self.upgrade_synthetic_only()
        second_id = self._second_synthetic_grant("app.example.test")
        # W12: even ONE selected grant can no longer hide an independently
        # approved overlapping grant for the same client and live target.
        for gid in (self.grant.grant_id, second_id):
            with self.subTest(grant_id=gid):
                solo = self.review(grant_id=gid)
                self.assertIs(solo.status, ReviewStatus.HOLD)
                self.assert_no_authority(solo)
        result = review_persisted_grant_batch(
            self.path, (self.grant.grant_id, second_id),
            reviewed_at=self.reviewed_at,
        )
        self.assertIs(result.status, ReviewStatus.HOLD)
        self.assert_no_authority(result)

    def test_single_ignores_same_asset_if_other_window_is_disjoint(self):
        self.upgrade_synthetic_only()
        second_id = self._second_synthetic_grant("app.example.test")
        future_start = self.now + timedelta(days=2)
        future_end = future_start + timedelta(days=1)
        with sqlite3.connect(self.path) as con:
            affected = con.execute(
                "UPDATE authorization_grants SET valid_from=?, valid_until=? "
                "WHERE grant_id=?",
                (future_start.isoformat(), future_end.isoformat(), second_id),
            ).rowcount
            self.assertEqual(affected, 1)
        review = self.review()
        self.assertIs(review.status, ReviewStatus.REVIEW_ONLY)
        self.assert_no_authority(review)

    def test_single_ignores_other_grant_asset_only_if_fully_excluded(self):
        self.upgrade_synthetic_only()
        second_id = self._second_synthetic_grant("app.example.test")
        with sqlite3.connect(self.path) as con:
            affected = con.execute(
                "UPDATE authorization_grants SET excluded_assets_json=? "
                "WHERE grant_id=?",
                ('["app.example.test"]', second_id),
            ).rowcount
            self.assertEqual(affected, 1)
        review = self.review()
        self.assertIs(review.status, ReviewStatus.REVIEW_ONLY)
        self.assert_no_authority(review)

    def test_unselected_same_tenant_grant_must_have_valid_exclusions_and_scope(self):
        # The *selected* grant is unchanged and covers app.example.test.
        # Historically an unrelated same-client grant with fabricated
        # excluded_assets_json / policy metadata could be silently skipped.
        corruptions = (
            ("excluded_assets_json", '["app.example.test"]'),
            ("excluded_assets_json", '["api.example.test","api.example.test"]'),
            ("excluded_assets_json", '["api.example.test",3]'),
            ("assets_json", '[]'),
            ("assets_json", '["api.example.test","api.example.test"]'),
            ("assets_json", '["api.example.test","INVALID.example.test"]'),
            ("allowed_capabilities_json", '["unsupported-capability"]'),
            ("allowed_capabilities_json", '[]'),
            ("max_risk", 4),
            ("recurring_retest_allowed", 1),
        )
        for index, (field, value) in enumerate(corruptions):
            with self.subTest(sibling_field=field, value=value):
                if index:
                    self._reset_fixture()
                self.upgrade_synthetic_only()
                other = self._second_synthetic_grant("api.example.test")
                self.assertIs(self.review().status, ReviewStatus.REVIEW_ONLY)
                self.update("authorization_grants", field, value, "grant_id", other)
                result = self.review()
                self.assertIs(result.status, ReviewStatus.HOLD)
                self.assert_no_authority(result)
                single_batch = review_persisted_grant_batch(
                    self.path, (self.grant.grant_id,), reviewed_at=self.reviewed_at,
                )
                self.assertIs(single_batch.status, ReviewStatus.HOLD)
                self.assert_no_authority(single_batch)

    def _other_tenant_authorized_grant(self):
        other = self.store.create_client(self.operator, "Independent synthetic tenant")
        member = AccessContext("other-client-requester", Role.CLIENT_MEMBER, other.client_id)
        request = self.store.submit_assessment_request(
            member, ("other.example.test",),
            AssessmentMode.AUTHORIZED_ASSESSMENT, RiskLevel.STANDARD,
        )
        request = self.store.review_assessment_request(
            self.operator, request.request_id, True,
        )
        engagement = self.store.create_engagement(
            self.operator, other.client_id, "Independent synthetic engagement",
        )
        grant = self.store.record_authorization_grant(
            self.operator, engagement.engagement_id, self.operator.user_id,
            "FICTIONAL-SECOND-TENANT",
            ScopeDefinition(
                assets=("other.example.test",),
                max_risk=RiskLevel.LOW_IMPACT,
                allowed_capabilities=("web-baseline",),
            ),
            self.valid_from, self.now + timedelta(days=1),
        )
        self.store.set_engagement_status(
            self.operator, engagement.engagement_id, EngagementStatus.AUTHORIZED,
        )
        with sqlite3.connect(self.path) as con:
            changed = con.execute(
                "UPDATE authorization_grants SET approved_request_id=? "
                "WHERE grant_id=?",
                (request.request_id, grant.grant_id),
            ).rowcount
            self.assertEqual(changed, 1)
        return request.request_id, engagement.engagement_id, grant.grant_id

    def test_unrelated_valid_tenant_does_not_block_single_grant(self):
        self.upgrade_synthetic_only()
        self._other_tenant_authorized_grant()
        reviewed = self.review()
        self.assertIs(reviewed.status, ReviewStatus.REVIEW_ONLY)
        self.assert_no_authority(reviewed)

    def test_unselected_other_tenant_impossible_time_or_status_holds(self):
        # Separate other-tenant approvals need coherent chronology as well,
        # even if the caller chose a completely different client's grant.
        faults = (
            ("assessment_requests", "created_at", "after-decision", "request_id"),
            ("assessment_requests", "decided_at", "after-grant", "request_id"),
            ("authorization_grants", "created_at", "before-request", "grant_id"),
            ("authorization_grants", "valid_from", "before-persistence", "grant_id"),
            ("authorization_grants", "valid_until", "empty-window", "grant_id"),
            ("engagements", "created_at", "after-grant", "engagement_id"),
            ("engagements", "status", "draft", "engagement_id"),
        )
        for index, (table, field, value, key) in enumerate(faults):
            with self.subTest(table=table, field=field, value=value):
                if index:
                    self._reset_fixture()
                self.upgrade_synthetic_only()
                req_id, eng_id, grant_id = self._other_tenant_authorized_grant()
                self.assertIs(self.review().status, ReviewStatus.REVIEW_ONLY)
                if value == "after-decision" or value == "after-grant":
                    value = (self.now + timedelta(days=2)).isoformat()
                elif value == "before-request":
                    value = (self.now - timedelta(days=2)).isoformat()
                elif value == "before-persistence":
                    value = (self.now - timedelta(days=1)).isoformat()
                elif value == "empty-window":
                    value = self.valid_from.isoformat()
                identity = {
                    "request_id": req_id,
                    "engagement_id": eng_id,
                    "grant_id": grant_id,
                }[key]
                with sqlite3.connect(self.path) as con:
                    changed = con.execute(
                        f"UPDATE {table} SET {field}=? WHERE {key}=?",
                        (value, identity),
                    ).rowcount
                    self.assertEqual(changed, 1)
                    self.assertEqual(
                        con.execute("PRAGMA foreign_key_check").fetchall(), [],
                    )
                decision = self.review()
                self.assertIs(decision.status, ReviewStatus.HOLD)
                self.assert_no_authority(decision)
                batch = review_persisted_grant_batch(
                    self.path, (self.grant.grant_id,),
                    reviewed_at=self.reviewed_at,
                )
                self.assertIs(batch.status, ReviewStatus.HOLD)
                self.assert_no_authority(batch)

    def test_unreviewed_other_tenant_lineage_corruption_blocks_snapshot(self):
        # A clean FK proves the request exists, NOT that it approved this
        # tenant, this engagement, or the claimed human decision-maker.
        cases = (
            ("authorization_grants", "client_id", "unrelated-client", "grant_id"),
            ("authorization_grants", "approved_by", "unrelated-operator", "grant_id"),
            ("authorization_grants", "engagement_id", "self-engagement", "grant_id"),
            ("assessment_requests", "client_id", "unrelated-client", "request_id"),
            ("assessment_requests", "requested_by", "self-approver", "request_id"),
            ("assessment_requests", "status", "rejected", "request_id"),
            ("assessment_requests", "requested_mode", "passive_discovery", "request_id"),
            ("engagements", "client_id", "unrelated-client", "engagement_id"),
        )
        for index, (table, field, value, key) in enumerate(cases):
            with self.subTest(other_tenant_field=field, value=value):
                if index:
                    self._reset_fixture()
                self.upgrade_synthetic_only()
                req_id, eng_id, grant_id = self._other_tenant_authorized_grant()
                self.assertIs(self.review().status, ReviewStatus.REVIEW_ONLY)
                target = {
                    "request_id": req_id, "engagement_id": eng_id,
                    "grant_id": grant_id,
                }[key]
                if value == "self-engagement":
                    value = self.engagement
                if value == "self-approver":
                    value = self.operator.user_id
                with sqlite3.connect(self.path) as con:
                    changed = con.execute(
                        f"UPDATE {table} SET {field}=? WHERE {key}=?",
                        (value, target),
                    ).rowcount
                    self.assertEqual(changed, 1)
                # No orphan FK: foreign_key_check still passes even with
                # invalid cross-table tenant or review-decision lineage.
                with sqlite3.connect(self.path) as con:
                    self.assertEqual(
                        con.execute("PRAGMA foreign_key_check").fetchall(), []
                    )
                result = self.review()
                self.assertIs(result.status, ReviewStatus.HOLD)
                self.assert_no_authority(result)
                batched = review_persisted_grant_batch(
                    self.path, (self.grant.grant_id,),
                    reviewed_at=self.reviewed_at,
                )
                self.assertIs(batched.status, ReviewStatus.HOLD)
                self.assert_no_authority(batched)

    def test_other_same_tenant_grant_can_only_exclude_its_own_asset(self):
        self.upgrade_synthetic_only()
        other = self._second_synthetic_grant("api.example.test")
        self.update(
            "authorization_grants", "excluded_assets_json",
            '["api.example.test"]', "grant_id", other,
        )
        result = self.review()
        self.assertIs(result.status, ReviewStatus.REVIEW_ONLY)
        self.assert_no_authority(result)

    def test_other_same_client_corrupt_window_holds_solo_snapshot(self):
        self.upgrade_synthetic_only()
        second_id = self._second_synthetic_grant("api.example.test")
        with sqlite3.connect(self.path) as con:
            affected = con.execute(
                "UPDATE authorization_grants SET valid_until=? WHERE grant_id=?",
                ("not-a-canonical-utc-instant", second_id),
            ).rowcount
            self.assertEqual(affected, 1)
        decision = self.review()
        self.assertIs(decision.status, ReviewStatus.HOLD)
        self.assert_no_authority(decision)

    def test_atomic_persisted_batch_denies_cross_tenant_despite_two_valid_grants(self):
        self.upgrade_synthetic_only()
        other = self.store.create_client(self.operator, "Second fictional client")
        second_member = AccessContext("second-member", Role.CLIENT_MEMBER, other.client_id)
        req = self.store.submit_assessment_request(
            second_member, ("api.example.test",),
            AssessmentMode.AUTHORIZED_ASSESSMENT, RiskLevel.STANDARD,
        )
        req = self.store.review_assessment_request(self.operator, req.request_id, True)
        eng = self.store.create_engagement(self.operator, other.client_id, "Other isolated engagement")
        grant2 = self.store.record_authorization_grant(
            self.operator, eng.engagement_id, self.operator.user_id,
            "OTHER-FICTIONAL-ONLY",
            ScopeDefinition(
                assets=("api.example.test",), max_risk=RiskLevel.LOW_IMPACT,
                allowed_capabilities=("web-baseline",),
            ),
            self.valid_from, self.now + timedelta(days=1),
        )
        self.store.set_engagement_status(self.operator, eng.engagement_id, EngagementStatus.AUTHORIZED)
        with sqlite3.connect(self.path) as con:
            con.execute(
                "UPDATE authorization_grants SET approved_request_id=? WHERE grant_id=?",
                (req.request_id, grant2.grant_id),
            )
        self.assertIs(self.review(grant_id=grant2.grant_id).status, ReviewStatus.REVIEW_ONLY)
        result = review_persisted_grant_batch(
            self.path, (self.grant.grant_id, grant2.grant_id),
            reviewed_at=self.reviewed_at,
        )
        self.assertIs(result.status, ReviewStatus.HOLD)
        self.assert_no_authority(result)

    def test_batch_only_existing_domain_schema_hold_and_no_create(self):
        result = review_persisted_grant_batch(
            self.path, (self.grant.grant_id,), reviewed_at=self.reviewed_at,
        )
        self.assertIs(result.status, ReviewStatus.HOLD)
        missing = self.path.parent / "missing-batch.sqlite3"
        result = review_persisted_grant_batch(
            missing, (self.grant.grant_id,), reviewed_at=self.reviewed_at,
        )
        self.assertIs(result.status, ReviewStatus.HOLD)
        self.assertFalse(missing.exists())

    def test_batch_atomic_snapshot_no_db_mutation_and_no_network(self):
        self.upgrade_synthetic_only()
        second_id = self._second_synthetic_grant()
        def state():
            with sqlite3.connect(self.path) as con:
                return tuple(
                    con.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()
                    for table in ("assessment_requests", "authorization_grants", "engagements")
                )
        before = state()
        with patch("socket.socket", side_effect=AssertionError("no network")):
            result = review_persisted_grant_batch(
                self.path, (self.grant.grant_id, second_id),
                reviewed_at=self.reviewed_at,
            )
        self.assertIs(result.status, ReviewStatus.REVIEW_ONLY)
        self.assert_no_authority(result)
        self.assertEqual(before, state())

    def test_bad_review_instant_and_path_fail_without_mutations(self):
        self.upgrade_synthetic_only()
        for instant in (None, 0, False, datetime.now(), datetime.now(timezone(timedelta(hours=1)))):
            with self.subTest(instant=instant):
                result = self.review(instant=instant)
                # helper intentionally uses None as default, test direct call:
                if instant is None:
                    result = review_persisted_request_grant(
                        self.path, self.grant.grant_id, reviewed_at=None
                    )
                self.assertIs(result.status, ReviewStatus.HOLD)
                self.assert_no_authority(result)
        self.assertIs(
            review_persisted_request_grant({}, self.grant.grant_id, reviewed_at=self.reviewed_at).status,
            ReviewStatus.HOLD,
        )


if __name__ == "__main__":
    unittest.main()
