"""Genuine SQLite/LightUp-model all-or-none local lab review tests."""
import sqlite3
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

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
