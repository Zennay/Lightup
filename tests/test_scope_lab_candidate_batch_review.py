"""Genuine SQLite/LightUp-model all-or-none local lab review tests."""
import sqlite3
import tempfile
from pathlib import Path
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
import lightup.lab_candidate_batch_review as batch_module

from lightup.ai.orchestration import RunContext, ToolCall, ToolDefinition, ToolParameter, ParamKind
from lightup.engagements import RiskLevel
from lightup.execution_policy import InteractionKind
from lightup.lab_approval_candidate_ledger import LabApprovalCandidateLedger
from lightup.lab_candidate_batch_review import (
    LabCandidateReviewItem, review_lab_candidate_batch,
)


class CandidateBatchReviewTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.ledger = LabApprovalCandidateLedger(self.db)

    def tearDown(self):
        self.db.close()

    def item(self, run, asset, client="client-1", engagement="engagement-1"):
        self.ledger.issue(
            run_id=run, client_id=client, engagement_id=engagement,
            asset=asset, capability_id="lab-cap", tool_id="noop-lab",
            actor="operator", operator_gate=lambda *_: True,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        return LabCandidateReviewItem(
            context=RunContext.for_lab(run, engagement, client),
            call=ToolCall("noop-lab", asset),
            definition=ToolDefinition(
                "noop-lab", "lab-cap", InteractionKind.LAB_ACTIVE,
                RiskLevel.DESTRUCTIVE_LAB_ONLY, "never executed",
            ),
        )

    def reviewed(self, *items):
        return review_lab_candidate_batch(self.ledger, tuple(items))

    def assertFalseFlags(self, receipt):
        for flag in ("authorization_verified", "permit_issued",
                     "execution_enabled", "merge_approved", "release_approved"):
            self.assertIs(receipt[flag], False)

    def test_one_consistent_is_non_authorizing(self):
        receipt = self.reviewed(self.item("run-1", "lab-1"))
        self.assertEqual(receipt["status"], "REVIEW_ONLY")
        self.assertEqual(receipt["reviewable_items"], 1)
        self.assertFalseFlags(receipt)

    def test_two_consistent_nonconflicting_items_are_review_only(self):
        receipt = self.reviewed(self.item("run-1", "lab-1"),
                                self.item("run-2", "lab-2"))
        self.assertEqual(receipt["status"], "REVIEW_ONLY")
        self.assertEqual(receipt["reviewable_items"], 2)
        self.assertFalseFlags(receipt)

    def test_one_invalid_last_item_holds_entire_packet(self):
        first = self.item("run-1", "lab-1")
        second = self.item("run-2", "lab-2")
        invalid = replace(second, call=replace(second.call, asset="other"))
        result = self.reviewed(first, invalid)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reviewable_items"], 0)
        self.assertFalseFlags(result)

    def test_duplicate_run_cannot_double_count(self):
        entry = self.item("run-1", "lab-1")
        result = self.reviewed(entry, entry)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reviewable_items"], 0)

    def test_empty_list_invalid(self):
        result = self.reviewed()
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reviewable_items"], 0)

    def test_list_input_rejected_even_if_values_valid(self):
        entry = self.item("run-1", "lab-1")
        result = review_lab_candidate_batch(self.ledger, [entry])
        self.assertEqual(result["status"], "HOLD")

    def test_33rd_item_rejected_without_exposing_partial_count(self):
        entries = tuple(self.item(f"run-{i}", f"lab-{i}") for i in range(33))
        result = review_lab_candidate_batch(self.ledger, entries)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reviewable_items"], 0)

    def test_cross_tenant_duplicate_asset_holds_whole_packet(self):
        first = self.item("run-1", "shared-lab", "client-1")
        other = self.item("run-2", "shared-lab", "client-2")
        result = self.reviewed(first, other)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reviewable_items"], 0)
        self.assertFalseFlags(result)

    def test_cross_tenant_casefold_asset_alias_holds(self):
        first = self.item("run-1", "SharedLab", "client-1")
        second = self.item("run-2", "sharedlab", "client-2")
        result = self.reviewed(first, second)
        self.assertEqual(result["status"], "HOLD")

    def test_disjoint_tenant_assets_remain_review_only(self):
        first = self.item("run-1", "lab-1", "client-1")
        second = self.item("run-2", "lab-2", "client-2")
        result = self.reviewed(first, second)
        self.assertEqual(result["status"], "REVIEW_ONLY")
        self.assertEqual(result["reviewable_items"], 2)
        self.assertFalseFlags(result)

    def test_invalid_middle_tool_arguments_hold_everything(self):
        first = self.item("run-1", "lab-1")
        second = self.item("run-2", "lab-2")
        third = self.item("run-3", "lab-3")
        changed = replace(second, call=replace(second.call, arguments=(("host", "unsafe"),)))
        result = self.reviewed(first, changed, third)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reviewable_items"], 0)

    def test_canonical_frozen_engagement_holds_whole_packet(self):
        first = self.item("run-1", "lab-1")
        second = self.item("run-2", "lab-2", engagement="other-eng")
        self.ledger.freeze_engagement(
            client_id="client-1", engagement_id="other-eng",
            actor="operator", operator_gate=lambda *_: True)
        result = self.reviewed(first, second)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reviewable_items"], 0)

    def test_revoked_second_run_holds_whole_packet(self):
        first = self.item("run-1", "lab-1")
        second = self.item("run-2", "lab-2")
        self.ledger.revoke(
            run_id="run-2", client_id="client-1", actor="operator",
            operator_gate=lambda *_: True)
        self.assertEqual(self.reviewed(first, second)["status"], "HOLD")

    def test_polymorphic_batch_item_holds(self):
        class FakeItem(LabCandidateReviewItem):
            pass
        a = self.item("run-1", "lab-1")
        forged = FakeItem(a.context, a.call, a.definition)
        self.assertEqual(self.reviewed(forged)["status"], "HOLD")

    def test_parameterized_definition_in_packet_holds(self):
        first = self.item("run-1", "lab-1")
        second = self.item("run-2", "lab-2")
        changed = replace(second, definition=replace(
            second.definition,
            parameters=(ToolParameter("target", ParamKind.STRING),),
        ))
        self.assertEqual(self.reviewed(first, changed)["status"], "HOLD")

    def test_every_success_is_network_and_handler_free(self):
        a = self.item("run-1", "lab-1")
        b = self.item("run-2", "lab-2")
        with patch("socket.socket", side_effect=AssertionError("network disallowed")):
            result = self.reviewed(a, b)
        self.assertEqual(result["status"], "REVIEW_ONLY")
        self.assertIs(result["execution_enabled"], False)


    def test_batch_read_transaction_released_after_positive_result(self):
        entry = self.item("run-1", "lab-1")
        before = self.db.total_changes
        self.assertFalse(self.db.in_transaction)
        self.assertEqual(self.reviewed(entry)["status"], "REVIEW_ONLY")
        self.assertFalse(self.db.in_transaction)
        self.assertEqual(self.db.total_changes, before)

    def test_batch_read_transaction_released_after_denial(self):
        entry = self.item("run-1", "lab-1")
        invalid = replace(entry, call=replace(entry.call, asset="other-lab"))
        before = self.db.total_changes
        self.assertEqual(self.reviewed(invalid)["status"], "HOLD")
        self.assertFalse(self.db.in_transaction)
        self.assertEqual(self.db.total_changes, before)

    def test_caller_owned_transaction_is_not_rolled_back(self):
        entry = self.item("run-1", "lab-1")
        self.db.execute("CREATE TABLE outside_changes (note TEXT)")
        self.db.execute("BEGIN IMMEDIATE")
        self.db.execute("INSERT INTO outside_changes VALUES ('retain')")
        result = self.reviewed(entry)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reviewable_items"], 0)
        self.assertTrue(self.db.in_transaction)
        self.assertEqual(
            self.db.execute("SELECT note FROM outside_changes").fetchone(),
            ("retain",),
        )
        self.db.rollback()

    def test_caller_read_transaction_is_not_silently_consumed(self):
        entry = self.item("run-1", "lab-1")
        self.db.execute("BEGIN")
        self.assertEqual(self.reviewed(entry)["status"], "HOLD")
        self.assertTrue(self.db.in_transaction)
        self.db.rollback()

    def test_closed_database_connection_is_fail_closed(self):
        entry = self.item("run-1", "lab-1")
        self.db.close()
        self.assertEqual(self.reviewed(entry)["status"], "HOLD")

    def test_replaced_database_connection_is_fail_closed(self):
        entry = self.item("run-1", "lab-1")
        original = self.ledger._db
        try:
            self.ledger._db = object()
            result = self.reviewed(entry)
            self.assertEqual(result["status"], "HOLD")
            self.assertEqual(result["reviewable_items"], 0)
            self.assertFalseFlags(result)
        finally:
            self.ledger._db = original

    def _verify_concurrent_writer_denied(self, mutate):
        # A WAL writer can commit while the batch holds a read snapshot.
        # This verifies detection of cross-connection changes before result.
        with tempfile.TemporaryDirectory() as folder:
            filename = Path(folder) / "candidate-snapshot.db"
            reader = sqlite3.connect(filename)
            reader.execute("PRAGMA journal_mode=WAL")
            writer = sqlite3.connect(filename)
            previous_db, previous_ledger = self.db, self.ledger
            self.db = reader
            self.ledger = LabApprovalCandidateLedger(reader)
            try:
                first = self.item("run-1", "lab-1")
                second = self.item("run-2", "lab-2")
                real = batch_module.review_lab_candidate_dispatch
                calls = 0

                def first_read_then_commit(*args):
                    nonlocal calls
                    decision = real(*args)
                    calls += 1
                    if calls == 1:
                        mutate(writer)
                    return decision

                with patch.object(
                    batch_module, "review_lab_candidate_dispatch",
                    side_effect=first_read_then_commit,
                ):
                    result = self.reviewed(first, second)
                self.assertEqual(calls, 2)
                self.assertEqual(result["status"], "HOLD")
                self.assertEqual(result["reviewable_items"], 0)
                self.assertFalseFlags(result)
                self.assertFalse(reader.in_transaction)
            finally:
                self.db, self.ledger = previous_db, previous_ledger
                writer.close()
                reader.close()

    def test_concurrent_other_connection_revocation_holds_entire_packet(self):
        def revoke_second(writer):
            writer.execute(
                """UPDATE lab_stepup_candidates_v1
                   SET revoked_at=?, revoked_by=?
                   WHERE run_id='run-2'""",
                (datetime.now(timezone.utc).isoformat(), "operator"),
            )
            writer.commit()

        self._verify_concurrent_writer_denied(revoke_second)

    def test_concurrent_other_connection_freeze_holds_entire_packet(self):
        def freeze_engagement(writer):
            LabApprovalCandidateLedger(writer).freeze_engagement(
                client_id="client-1",
                engagement_id="engagement-1",
                actor="operator",
                operator_gate=lambda *_: True,
            )

        self._verify_concurrent_writer_denied(freeze_engagement)

    def test_concurrent_unrelated_candidate_write_also_holds(self):
        def insert_unrelated(writer):
            writer.execute(
                """INSERT INTO lab_stepup_tenant_freezes_v1
                   (client_id, frozen_at, frozen_by)
                   VALUES ('unrelated', '2026-10-14T00:00:00+00:00', 'operator')"""
            )
            writer.commit()

        self._verify_concurrent_writer_denied(insert_unrelated)

    def test_no_external_change_allows_consecutive_consistent_snapshots(self):
        first = self.item("run-1", "lab-1")
        second = self.item("run-2", "lab-2")
        result_a = self.reviewed(first, second)
        result_b = self.reviewed(first, second)
        self.assertEqual(result_a["status"], "REVIEW_ONLY")
        self.assertEqual(result_b["status"], "REVIEW_ONLY")
        self.assertEqual(result_a["reviewable_items"], 2)
        self.assertFalseFlags(result_b)
        self.assertFalse(self.db.in_transaction)
