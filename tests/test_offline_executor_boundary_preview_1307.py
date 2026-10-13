"""Opt-in offline executor admission tests. Synthetic SQLite; no execution."""
from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
import tempfile
import unittest

from lightup.ai.orchestration import (
    ParamKind, RunContext, ToolCall, ToolDefinition, ToolExecutor,
    ToolOutput, ToolParameter, ToolRegistry,
)
from lightup.engagements import AssessmentMode, RiskLevel
from lightup.execution_policy import ExecutionPolicy, InteractionKind
from lightup.offline_executor_boundary_preview_optin import (
    OfflineAdmissionDenied, OfflineBoundaryReceipt, OfflineExecutorBoundaryPreview,
)
from lightup.state import StateStore


class Canary:
    def __getattr__(self, name):
        raise AssertionError("untrusted user getter invoked: " + name)


class CallSubclass(ToolCall):
    pass


class ContextSubclass(RunContext):
    pass


class RegistrySubclass(ToolRegistry):
    pass


class PolicySubclass(ExecutionPolicy):
    pass


class OfflineExecutorPreview1307(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="lightup-1307-")
        self.addCleanup(tmp.cleanup)
        self.state = StateStore(Path(tmp.name) / "synthetic.sqlite")
        self.run_id = self.state.create_run(
            target="synthetic.invalid", activation_mode="plan_only"
        )
        self.calls = []
        self.registry = ToolRegistry()
        self.definition = ToolDefinition(
            "offline-1307", "network-services", InteractionKind.ANALYSIS,
            RiskLevel.ANALYSIS_ONLY, "inert",
            (ToolParameter("query", ParamKind.STRING),),
        )
        self.registry.register(self.definition, self._handler)
        self.policy = ExecutionPolicy()
        self.executor = ToolExecutor(self.registry, self.state, self.policy)
        self.context = RunContext(
            self.run_id, "synthetic-client", "synthetic-engagement",
            AssessmentMode.ANALYSIS_ONLY, RiskLevel.ANALYSIS_ONLY, None, False,
            datetime.now(timezone.utc),
        )
        self.call = ToolCall(
            "offline-1307", "synthetic.invalid", (("query", "offline"),)
        )

    def _handler(self, context, arguments):
        self.calls.append((context, arguments))
        return ToolOutput("should never run", "test", b"unsafe-if-called")

    def _evidence(self):
        with self.state.connect() as db:
            return db.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]

    def _refuse(self, context=None, call=None, preview=None):
        if preview is None:
            preview = OfflineExecutorBoundaryPreview.capture(self.executor)
        before = self._evidence()
        with self.assertRaisesRegex(OfflineAdmissionDenied, "^offline boundary preview refused$"):
            preview.preview(
                self.context if context is None else context,
                self.call if call is None else call,
            )
        self.assertEqual(self._evidence(), before)
        self.assertEqual(self.calls, [])

    def test_valid_offline_receipt_is_frozen_and_never_authorizes(self):
        receipt = OfflineExecutorBoundaryPreview.capture(self.executor).preview(
            self.context, self.call
        )
        self.assertEqual(receipt, OfflineBoundaryReceipt(1))
        self.assertEqual(receipt.contracts_checked, 7)
        self.assertIs(receipt.permit_issued, False)
        self.assertIs(receipt.execution_enabled, False)
        self.assertIs(receipt.authorization_verified, False)
        with self.assertRaises((FrozenInstanceError, AttributeError)):
            receipt.execution_enabled = True
        self.assertEqual(self.calls, [])
        self.assertEqual(self._evidence(), 0)

    def test_repeated_preview_is_deterministic_and_does_not_call_policy(self):
        preview = OfflineExecutorBoundaryPreview.capture(self.executor)
        with patch.object(ExecutionPolicy, "decide", side_effect=AssertionError("policy invoked")):
            first = preview.preview(self.context, self.call)
            self.assertEqual(first, preview.preview(self.context, self.call))
        self.assertEqual(self._evidence(), 0)
        self.assertEqual(self.calls, [])

    def test_canary_outer_executor_is_never_read(self):
        with self.assertRaises(OfflineAdmissionDenied):
            OfflineExecutorBoundaryPreview.capture(Canary())

    def test_canary_context_and_call_are_denied_before_getters(self):
        self._refuse(context=Canary())
        self._refuse(call=Canary())

    def test_outer_subclasses_are_denied(self):
        self._refuse(context=ContextSubclass(**vars(self.context)))
        self._refuse(call=CallSubclass(**vars(self.call)))

    def test_executor_registry_replacement_after_capture_is_denied(self):
        preview = OfflineExecutorBoundaryPreview.capture(self.executor)
        self.executor.registry = ToolRegistry()
        self._refuse(preview=preview)

    def test_executor_policy_replacement_after_capture_is_denied(self):
        preview = OfflineExecutorBoundaryPreview.capture(self.executor)
        self.executor.policy = ExecutionPolicy()
        self._refuse(preview=preview)

    def test_executor_state_replacement_after_capture_is_denied(self):
        preview = OfflineExecutorBoundaryPreview.capture(self.executor)
        self.executor.state = StateStore(self.state.db_path)
        self._refuse(preview=preview)

    def test_executor_resolver_replacement_after_capture_is_denied(self):
        preview = OfflineExecutorBoundaryPreview.capture(self.executor)
        self.executor.authorization_resolver = lambda grant: grant
        self._refuse(preview=preview)

    def test_policy_decide_shadow_at_capture_is_denied(self):
        self.policy.decide = lambda request: True
        with self.assertRaises(OfflineAdmissionDenied):
            OfflineExecutorBoundaryPreview.capture(self.executor)

    def test_policy_decide_shadow_after_capture_is_denied(self):
        preview = OfflineExecutorBoundaryPreview.capture(self.executor)
        self.policy.decide = lambda request: True
        self._refuse(preview=preview)

    def test_polymorphic_registry_or_policy_rejected_at_capture(self):
        bad_registry = ToolExecutor(RegistrySubclass(), self.state)
        bad_policy = ToolExecutor(self.registry, self.state, PolicySubclass())
        with self.assertRaises(OfflineAdmissionDenied):
            OfflineExecutorBoundaryPreview.capture(bad_registry)
        with self.assertRaises(OfflineAdmissionDenied):
            OfflineExecutorBoundaryPreview.capture(bad_policy)

    def test_registry_handler_swap_after_capture_is_denied(self):
        preview = OfflineExecutorBoundaryPreview.capture(self.executor)
        self.registry._tools["offline-1307"] = (
            self.definition, lambda context, arguments: None
        )
        self._refuse(preview=preview)

    def test_registry_tool_added_after_capture_is_denied(self):
        preview = OfflineExecutorBoundaryPreview.capture(self.executor)
        self.registry.register(
            ToolDefinition(
                "second-1307", "network-services", InteractionKind.ANALYSIS,
                RiskLevel.ANALYSIS_ONLY, "inert"
            ), self._handler
        )
        self._refuse(preview=preview)

    def test_registry_definition_mutated_after_capture_is_denied(self):
        preview = OfflineExecutorBoundaryPreview.capture(self.executor)
        object.__setattr__(self.definition, "min_risk", RiskLevel.STANDARD)
        self._refuse(preview=preview)

    def test_registry_parameter_mutated_after_capture_is_denied(self):
        preview = OfflineExecutorBoundaryPreview.capture(self.executor)
        object.__setattr__(self.definition.parameters[0], "required", False)
        self._refuse(preview=preview)

    def test_unknown_tool_and_active_definition_denied(self):
        self._refuse(call=replace(self.call, tool_id="missing-1307"))
        new_def = replace(self.definition, interaction=InteractionKind.TARGET_ACTIVE)
        self.registry._tools["offline-1307"] = (new_def, self._handler)
        self._refuse()

    def test_authorization_and_active_mode_never_become_a_receipt(self):
        self._refuse(context=replace(self.context, authorization=object()))
        self._refuse(context=replace(self.context, mode=AssessmentMode.AUTHORIZED_ASSESSMENT))
        self._refuse(context=replace(self.context, approved_risk=RiskLevel.LOW_IMPACT))
        self._refuse(context=replace(self.context, is_lab=True))

    def test_only_reserved_synthetic_invalid_asset_admitted(self):
        for target in ("localhost", "127.0.0.1", "https://synthetic.invalid", "example.com"):
            with self.subTest(target=target):
                self._refuse(call=replace(self.call, asset=target))

    def test_argument_keys_shape_and_types_are_exact(self):
        bad = (
            (("query", "offline"), ("query", "other")),
            (("other", "offline"),),
            (("query", True),),
            (("query", 1),),
            ((str.__new__(str, "query"), "offline"),),  # ordinary str control
            ("query", "offline"),
            [(("query", "offline"))],
        )
        for arguments in bad:
            if isinstance(arguments, tuple) and arguments == (("query", "offline"),):
                continue
            with self.subTest(arguments=repr(arguments)):
                self._refuse(call=replace(self.call, arguments=arguments))

    def test_invalid_time_or_identity_fails_without_leaks(self):
        self._refuse(context=replace(self.context, created_at=datetime(2026, 1, 1)))
        self._refuse(context=replace(self.context, client_id="bad client"))
        self._refuse(context=replace(self.context, run_id=""))
        self._refuse(context=replace(self.context, run_id=Canary()))

    def test_no_handler_or_evidence_side_effect_even_with_many_previews(self):
        preview = OfflineExecutorBoundaryPreview.capture(self.executor)
        for _ in range(50):
            self.assertFalse(preview.preview(self.context, self.call).execution_enabled)
        self.assertEqual(self.calls, [])
        self.assertEqual(self._evidence(), 0)


if __name__ == "__main__":
    unittest.main()
