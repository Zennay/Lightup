"""Actual in-memory SQLite and genuine LightUp model review controls (#1173)."""
import sqlite3
import tempfile
from pathlib import Path
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from lightup.ai.orchestration import (
    ParamKind, RunContext, ToolCall, ToolDefinition, ToolParameter,
)
from lightup.engagements import AssessmentMode, RiskLevel
from lightup.execution_policy import InteractionKind
from lightup.lab_approval_candidate_ledger import LabApprovalCandidateLedger
from lightup.lab_candidate_dispatch_review import review_lab_candidate_dispatch


def role(actor, action):
    return actor == "operator" and action in ("issue", "revoke", "freeze")


class LabCandidateDispatchReviewTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.ledger = LabApprovalCandidateLedger(self.db)
        self.defaults = dict(
            run_id="run-1", client_id="client-1", engagement_id="eng-1",
            asset="isolated-lab", capability_id="lab-tool",
            tool_id="noop-check", actor="operator", operator_gate=role,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        self.ledger.issue(**self.defaults)
        self.context = RunContext.for_lab("run-1", "eng-1", "client-1")
        self.call = ToolCall(tool_id="noop-check", asset="isolated-lab")
        self.definition = ToolDefinition(
            tool_id="noop-check", capability_id="lab-tool",
            interaction=InteractionKind.LAB_ACTIVE,
            min_risk=RiskLevel.DESTRUCTIVE_LAB_ONLY,
            description="synthetic, does not execute",
        )

    def tearDown(self):
        self.db.close()

    def review(self, context=None, call=None, definition=None, ledger=None):
        return review_lab_candidate_dispatch(
            self.ledger if ledger is None else ledger,
            self.context if context is None else context,
            self.call if call is None else call,
            self.definition if definition is None else definition,
        )

    def assertHeld(self, result):
        self.assertEqual(result["status"], "HOLD")
        for flag in ("authorization_verified", "permit_issued",
                     "execution_enabled", "merge_approved", "release_approved"):
            self.assertIs(result[flag], False)

    def test_canonical_matching_preview_stays_non_authorizing(self):
        result = self.review()
        self.assertEqual(result["status"], "REVIEW_ONLY")
        for flag in ("authorization_verified", "permit_issued",
                     "execution_enabled", "merge_approved", "release_approved"):
            self.assertIs(result[flag], False)

    def test_run_identity_mismatch_holds(self):
        self.assertHeld(self.review(context=replace(self.context, run_id="run-2")))

    def test_cross_tenant_mismatch_holds(self):
        self.assertHeld(self.review(context=replace(self.context, client_id="client-2")))

    def test_engagement_identity_mismatch_holds(self):
        self.assertHeld(self.review(context=replace(self.context, engagement_id="eng-2")))

    def test_asset_identity_mismatch_holds(self):
        self.assertHeld(self.review(call=replace(self.call, asset="other-lab")))

    def test_capability_identity_mismatch_holds(self):
        self.assertHeld(self.review(definition=replace(
            self.definition, capability_id="different-capability")))

    def test_tool_identity_mismatch_holds(self):
        self.assertHeld(self.review(call=replace(self.call, tool_id="different-tool")))

    def test_parameterized_definition_holds(self):
        self.assertHeld(self.review(definition=replace(
            self.definition,
            parameters=(ToolParameter("other_host", ParamKind.STRING),),
        )))

    def test_parameterized_call_holds(self):
        self.assertHeld(self.review(call=replace(
            self.call, arguments=(("other_host", "outside-target"),),
        )))

    def test_non_lab_mode_holds(self):
        self.assertHeld(self.review(context=replace(
            self.context, mode=AssessmentMode.AUTHORIZED_ASSESSMENT)))

    def test_truthy_fake_lab_identity_holds(self):
        self.assertHeld(self.review(context=replace(self.context, is_lab=1)))

    def test_raw_numeric_risk_holds(self):
        self.assertHeld(self.review(definition=replace(self.definition, min_risk=5)))
        self.assertHeld(self.review(context=replace(self.context, approved_risk=5)))

    def test_wrong_interaction_holds(self):
        self.assertHeld(self.review(definition=replace(
            self.definition, interaction=InteractionKind.TARGET_ACTIVE)))

    def test_context_with_any_authorization_holds(self):
        self.assertHeld(self.review(context=replace(self.context, authorization=object())))

    def test_context_older_than_approval_holds(self):
        stale = replace(
            self.context, created_at=datetime.now(timezone.utc) - timedelta(hours=3))
        self.assertHeld(self.review(context=stale))

    def test_naive_and_future_context_times_hold(self):
        self.assertHeld(self.review(context=replace(
            self.context, created_at=datetime.now())))
        self.assertHeld(self.review(context=replace(
            self.context, created_at=datetime.now(timezone.utc) + timedelta(days=1))))

    def test_subclassed_datetime_context_holds(self):
        class AttackerTime(datetime):
            pass
        self.assertHeld(self.review(context=replace(
            self.context, created_at=AttackerTime.now(timezone.utc))))

    def test_revoked_candidate_holds(self):
        self.ledger.revoke(
            run_id="run-1", client_id="client-1",
            actor="operator", operator_gate=role)
        self.assertHeld(self.review())

    def test_frozen_engagement_holds(self):
        self.ledger.freeze_engagement(
            client_id="client-1", engagement_id="eng-1",
            actor="operator", operator_gate=role)
        self.assertHeld(self.review())

    def test_frozen_tenant_holds(self):
        self.ledger.freeze_tenant(
            client_id="client-1", actor="operator", operator_gate=role)
        self.assertHeld(self.review())

    def test_corrupt_stored_candidate_holds(self):
        self.db.execute(
            "UPDATE lab_stepup_candidates_v1 SET expires_at=? WHERE run_id=?",
            ("9999-12-31T23:59:59+00:00", "run-1"))
        self.db.commit()
        self.assertHeld(self.review())

    def test_polymorphic_outer_envelopes_hold_without_property_reads(self):
        class FakeContext:
            @property
            def run_id(self):
                raise AssertionError("must not dereference")
        class ForeignCall(ToolCall):
            pass
        self.assertHeld(self.review(context=FakeContext()))
        self.assertHeld(self.review(call=ForeignCall("noop-check", "isolated-lab")))
        self.assertHeld(self.review(ledger=object()))

    def test_canonical_preview_never_calls_network_or_executor(self):
        with patch("socket.socket", side_effect=AssertionError("network not allowed")):
            self.assertEqual(self.review()["status"], "REVIEW_ONLY")

    def test_single_preview_releases_its_own_read_transaction(self):
        before = self.db.total_changes
        result = self.review()
        self.assertEqual(result["status"], "REVIEW_ONLY")
        self.assertFalse(self.db.in_transaction)
        self.assertEqual(self.db.total_changes, before)

    def test_single_preview_releases_transaction_after_hold(self):
        before = self.db.total_changes
        result = self.review(call=replace(self.call, asset="invalid-asset"))
        self.assertHeld(result)
        self.assertFalse(self.db.in_transaction)
        self.assertEqual(self.db.total_changes, before)

    def test_existing_caller_transaction_is_not_rolled_back(self):
        self.db.execute("CREATE TABLE external (value TEXT)")
        self.db.execute("BEGIN IMMEDIATE")
        self.db.execute("INSERT INTO external VALUES ('retain')")
        result = self.review()
        self.assertEqual(result["status"], "REVIEW_ONLY")
        self.assertTrue(self.db.in_transaction)
        self.assertEqual(self.db.execute(
            "SELECT value FROM external").fetchone(), ("retain",))
        self.db.rollback()

    def test_closed_sqlite_connection_holds(self):
        self.db.close()
        self.assertHeld(self.review())

    def test_replaced_connection_holds(self):
        original = self.ledger._db
        try:
            self.ledger._db = object()
            self.assertHeld(self.review())
        finally:
            self.ledger._db = original

    def test_repeated_unmodified_snapshots_stay_review_only(self):
        first = self.review()
        second = self.review()
        self.assertEqual(first["status"], "REVIEW_ONLY")
        self.assertEqual(second["status"], "REVIEW_ONLY")
        self.assertFalse(self.db.in_transaction)
        for flag in ("authorization_verified", "permit_issued",
                     "execution_enabled", "merge_approved", "release_approved"):
            self.assertIs(first[flag], False)

    def _assert_external_change_during_single_review_holds(self, mutate):
        with tempfile.TemporaryDirectory() as folder:
            filename = Path(folder) / "single-preview.db"
            reader = sqlite3.connect(filename)
            reader.execute("PRAGMA journal_mode=WAL")
            writer = sqlite3.connect(filename)
            prior_db, prior_ledger, prior_context = (
                self.db, self.ledger, self.context,
            )
            self.db = reader
            self.ledger = LabApprovalCandidateLedger(reader)
            self.ledger.issue(**self.defaults)
            self.context = RunContext.for_lab("run-1", "eng-1", "client-1")
            writer_ledger = LabApprovalCandidateLedger(writer)
            original_inspect = LabApprovalCandidateLedger.inspect
            saw = 0

            def inspect_then_write(instance, run_id, *, client_id):
                nonlocal saw
                record = original_inspect(instance, run_id, client_id=client_id)
                if instance is self.ledger and saw == 0:
                    saw += 1
                    mutate(writer, writer_ledger)
                return record

            try:
                with patch.object(LabApprovalCandidateLedger, "inspect",
                                  new=inspect_then_write):
                    result = self.review()
                self.assertEqual(saw, 1)
                self.assertHeld(result)
                self.assertFalse(reader.in_transaction)
            finally:
                self.db, self.ledger, self.context = (
                    prior_db, prior_ledger, prior_context,
                )
                writer.close()
                reader.close()

    def test_concurrent_sqlite_revocation_cannot_yield_review_only(self):
        def revoke(writer, ledger):
            ledger.revoke(
                run_id="run-1", client_id="client-1",
                actor="operator", operator_gate=role,
            )
        self._assert_external_change_during_single_review_holds(revoke)

    def test_concurrent_engagement_freeze_cannot_yield_review_only(self):
        def freeze(writer, ledger):
            ledger.freeze_engagement(
                client_id="client-1", engagement_id="eng-1",
                actor="operator", operator_gate=role,
            )
        self._assert_external_change_during_single_review_holds(freeze)

    def test_unrelated_sqlite_external_write_is_conservative_hold(self):
        def unrelated(writer, ledger):
            writer.execute(
                """INSERT INTO lab_stepup_tenant_freezes_v1
                (client_id,frozen_at,frozen_by)
                VALUES ('outside', '2026-10-14T00:00:00+00:00', 'operator')"""
            )
            writer.commit()
        self._assert_external_change_during_single_review_holds(unrelated)

    def test_single_preview_is_non_authorizing_inside_caller_snapshot(self):
        self.db.execute("BEGIN")
        try:
            result = self.review()
            self.assertEqual(result["status"], "REVIEW_ONLY")
            self.assertIs(result["authorization_verified"], False)
            self.assertIs(result["execution_enabled"], False)
        finally:
            self.assertTrue(self.db.in_transaction)
            self.db.rollback()

