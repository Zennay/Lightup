"""Atomic read-only batch preview for synthetic analyst plans (#1307)."""
from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

from lightup.ai.orchestration import (
    RunContext, ToolCall, ToolDefinition, ToolExecutor, ToolOutput, ToolRegistry,
)
from lightup.engagements import AssessmentMode, RiskLevel
from lightup.execution_policy import InteractionKind
from lightup.offline_executor_boundary_preview_optin import (
    OfflineAdmissionDenied, OfflineBoundaryBatchReceipt, OfflineExecutorBoundaryPreview,
)
from lightup.state import StateStore


class GetterCanary:
    def __getattr__(self, name):
        raise AssertionError("untrusted batch item was inspected")


class BatchPreview1307(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="lightup-batch-1307-")
        self.addCleanup(self.tmp.cleanup)
        self.store = StateStore(Path(self.tmp.name) / "synthetic.sqlite")
        run_id = self.store.create_run("synthetic.invalid", activation_mode="plan_only")
        self.calls = []
        self.registry = ToolRegistry()
        for tool_id in ("inert-one-1307", "inert-two-1307"):
            self.registry.register(
                ToolDefinition(
                    tool_id, "network-services",
                    InteractionKind.ANALYSIS, RiskLevel.ANALYSIS_ONLY, "synthetic"
                ), self._handler
            )
        self.executor = ToolExecutor(self.registry, self.store)
        self.preview = OfflineExecutorBoundaryPreview.capture(self.executor)
        self.context = RunContext(
            run_id, "synthetic-client", "synthetic-engagement",
            AssessmentMode.ANALYSIS_ONLY, RiskLevel.ANALYSIS_ONLY,
            None, False, datetime.now(timezone.utc),
        )
        self.first = ToolCall("inert-one-1307", "synthetic.invalid")
        self.second = ToolCall("inert-two-1307", "synthetic.invalid")

    def _handler(self, context, arguments):
        self.calls.append((context, arguments))
        return ToolOutput("unused", "test", b"would be unsafe if called")

    def _evidence(self):
        with self.store.connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]

    def _no_effect(self):
        self.assertEqual(self.calls, [])
        self.assertEqual(self._evidence(), 0)

    def test_positive_two_tool_batch_only_returns_minimal_frozen_receipt(self):
        receipt = self.preview.preview_batch(self.context, (self.first, self.second))
        self.assertEqual(receipt, OfflineBoundaryBatchReceipt(2, 2))
        self.assertFalse(receipt.permit_issued)
        self.assertFalse(receipt.execution_enabled)
        self.assertFalse(receipt.authorization_verified)
        with self.assertRaises((AttributeError, FrozenInstanceError)):
            receipt.tools_reviewed = 99
        self._no_effect()

    def test_single_tool_batch_is_allowed_but_does_not_dispatch(self):
        receipt = self.preview.preview_batch(self.context, (self.first,))
        self.assertEqual(receipt.tools_reviewed, 1)
        self._no_effect()

    def test_late_invalid_tool_refuses_whole_batch_with_no_receipt(self):
        invalid = ToolCall("unregistered-1307", "synthetic.invalid")
        with self.assertRaises(OfflineAdmissionDenied):
            self.preview.preview_batch(self.context, (self.first, invalid))
        self._no_effect()

    def test_late_real_target_refuses_whole_batch(self):
        with self.assertRaises(OfflineAdmissionDenied):
            self.preview.preview_batch(
                self.context, (self.first, replace(self.second, asset="www.example.com"))
            )
        self._no_effect()

    def test_duplicate_tool_is_denied_even_with_two_canonical_instances(self):
        with self.assertRaises(OfflineAdmissionDenied):
            self.preview.preview_batch(self.context, (self.first, self.first))
        self._no_effect()

    def test_cannot_use_list_empty_or_more_than_sixty_four_calls(self):
        for calls in ([], [self.first], (), tuple(self.first for _ in range(65))):
            with self.subTest(kind=type(calls).__name__,size=len(calls)):
                with self.assertRaises(OfflineAdmissionDenied):
                    self.preview.preview_batch(self.context, calls)
        self._no_effect()

    def test_bad_call_outer_shape_denied_before_getter(self):
        for batch in ((GetterCanary(),), (self.first, GetterCanary())):
            with self.assertRaises(OfflineAdmissionDenied):
                self.preview.preview_batch(self.context, batch)
        self._no_effect()

    def test_batch_rejects_caller_supplied_grant_or_active_mode(self):
        for context in (
            replace(self.context, authorization=object()),
            replace(self.context, mode=AssessmentMode.AUTHORIZED_ASSESSMENT),
            replace(self.context, approved_risk=RiskLevel.ELEVATED),
        ):
            with self.assertRaises(OfflineAdmissionDenied):
                self.preview.preview_batch(context, (self.first, self.second))
        self._no_effect()

    def test_late_registry_binding_swap_denied_without_partial_receipt(self):
        self.executor.registry = ToolRegistry()
        with self.assertRaises(OfflineAdmissionDenied):
            self.preview.preview_batch(self.context, (self.first, self.second))
        self._no_effect()

    def test_batch_is_repeatable_without_mutating_or_authorizing(self):
        for _ in range(50):
            receipt = self.preview.preview_batch(self.context, (self.first, self.second))
            self.assertEqual(receipt.tools_reviewed, 2)
            self.assertFalse(receipt.execution_enabled)
        self._no_effect()


if __name__ == "__main__":
    unittest.main()
