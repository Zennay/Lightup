"""Offline real-ToolExecutor acceptance for opt-in destructive-lab step-up.

No network adapter, deployed service, real target, or destructive action is
registered. The only handler returns an in-memory synthetic evidence marker.
"""
from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lightup.ai.orchestration import (
    RunContext, ToolCall, ToolDefinition, ToolDenied, ToolExecutor,
    ToolOutput, ToolRegistry,
)
from lightup.destructive_lab_step_up import (
    DestructiveLabApproval, DestructiveLabStepUpExecutor,
    destructive_lab_approval_matches,
)
from lightup.engagements import AssessmentMode, RiskLevel
from lightup.execution_policy import InteractionKind
from lightup.state import StateStore


class DestructiveLabStepUpIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.registry = ToolRegistry()
        self.invocations = []
        self.destructive = ToolDefinition(
            tool_id="synthetic-lab-destructive",
            capability_id="wireless-lab",
            interaction=InteractionKind.LAB_ACTIVE,
            min_risk=RiskLevel.DESTRUCTIVE_LAB_ONLY,
            description="Offline no-op marker only",
        )
        self.low_risk = ToolDefinition(
            tool_id="synthetic-lab-baseline",
            capability_id="wireless-lab",
            interaction=InteractionKind.LAB_ACTIVE,
            min_risk=RiskLevel.LOW_IMPACT,
            description="Offline no-op marker only",
        )
        def handler(context, arguments):
            self.invocations.append(context.run_id)
            return ToolOutput(
                summary="synthetic no-op",
                evidence_kind="synthetic",
                evidence_payload=b"no network or action",
            )
        self.registry.register(self.destructive, handler)
        self.registry.register(self.low_risk, handler)
        self.executor = ToolExecutor(
            self.registry, StateStore(Path(self.tmp.name) / "state.sqlite")
        )
        self.now = datetime.now(timezone.utc)
        self.context = RunContext(
            run_id="run-lab-a",
            client_id="client-lab-a",
            engagement_id="engagement-lab-a",
            mode=AssessmentMode.LAB_AUTONOMOUS,
            approved_risk=RiskLevel.DESTRUCTIVE_LAB_ONLY,
            authorization=None,
            is_lab=True,
            created_at=self.now - timedelta(minutes=1),
        )
        self.call = ToolCall(
            tool_id=self.destructive.tool_id,
            asset="isolated-simulator-one",
        )
        self.approval = DestructiveLabApproval(
            approval_id="approved-operator-step-up-1",
            run_id=self.context.run_id,
            client_id=self.context.client_id,
            engagement_id=self.context.engagement_id,
            asset=self.call.asset,
            capability_id=self.destructive.capability_id,
            tool_id=self.destructive.tool_id,
            approved_by="operator-step-up-reviewer",
            approved_at=self.now - timedelta(minutes=2),
            expires_at=self.now + timedelta(minutes=30),
        )
        self.live_record = self.approval

    def wrapper(self):
        return DestructiveLabStepUpExecutor(
            self.executor, lambda run_id: self.live_record
        )

    def assert_denied_without_effect(self, wrapper=None, *, context=None, call=None):
        app = wrapper or self.wrapper()
        before = len(self.invocations)
        with self.assertRaises(ToolDenied):
            app.execute(context or self.context, call or self.call)
        self.assertEqual(len(self.invocations), before)

    def test_no_resolver_always_denies_destructive_lab_tool(self):
        self.assert_denied_without_effect(DestructiveLabStepUpExecutor(self.executor))

    def test_trusted_approval_allows_synthetic_noop_and_writes_evidence(self):
        result = self.wrapper().execute(self.context, self.call)
        self.assertEqual(result.tool_id, self.call.tool_id)
        self.assertEqual(result.capability_id, "wireless-lab")
        self.assertEqual(len(self.invocations), 1)

    def test_lab_run_risk_five_is_not_itself_operator_approval(self):
        self.live_record = None
        self.assert_denied_without_effect()

    def test_revocation_is_checked_again_on_each_dispatch(self):
        wrapper = self.wrapper()
        wrapper.execute(self.context, self.call)
        self.live_record = replace(self.approval, revoked=True)
        self.assert_denied_without_effect(wrapper)
        self.assertEqual(len(self.invocations), 1)

    def test_wrong_run_tenant_engagement_asset_or_capability_denied(self):
        for key, other in (
            ("run_id", "other-run"),
            ("client_id", "other-client"),
            ("engagement_id", "other-engagement"),
            ("asset", "other-simulator"),
            ("capability_id", "other-capability"),
            ("tool_id", "other-tool"),
        ):
            with self.subTest(field=key):
                self.live_record = replace(self.approval, **{key: other})
                self.assert_denied_without_effect()

    def test_invalid_or_noncanonical_approval_metadata_denied(self):
        for key, other in (
            ("approval_id", ""),
            ("approved_by", " operator "),
            ("revoked", 0),
            ("expires_at", self.now - timedelta(seconds=1)),
                        ("approved_at", self.now),
            ("approved_at", self.context.created_at + timedelta(seconds=1)),
            ("approved_at", datetime.now()),
            ("expires_at", datetime.now()),
        ):
            with self.subTest(field=key, value=str(other)):
                self.live_record = replace(self.approval, **{key: other})
                self.assert_denied_without_effect()

    def test_longer_future_expiry_remains_allowed_if_operator_approved(self):
        self.live_record = replace(self.approval, expires_at=self.now + timedelta(hours=2))
        result = self.wrapper().execute(self.context, self.call)
        self.assertEqual(result.tool_id, self.call.tool_id)

    def test_expired_session_or_preapproval_run_denied(self):
        older = replace(
            self.context, created_at=self.approval.approved_at - timedelta(seconds=1)
        )
        self.assert_denied_without_effect(context=older)
        stale = replace(self.context, created_at=self.now - timedelta(hours=2))
        self.assert_denied_without_effect(context=stale)

    def test_wrong_mode_lab_marker_and_risk_do_not_bypass(self):
        for changes in (
            {"mode": AssessmentMode.AUTHORIZED_ASSESSMENT},
            {"is_lab": False},
            {"is_lab": "true"},
            {"approved_risk": RiskLevel.STANDARD},
            {"approved_risk": 5},
        ):
            with self.subTest(changes=changes):
                self.assert_denied_without_effect(
                    context=replace(self.context, **changes)
                )

    def test_resolver_errors_and_untrusted_shapes_fail_closed(self):
        fail = DestructiveLabStepUpExecutor(
            self.executor,
            lambda run_id: (_ for _ in ()).throw(RuntimeError("DB unavailable")),
        )
        self.assert_denied_without_effect(fail)

        class LooksLikeApproval:
            def __getattr__(self, key):
                raise AssertionError("duck approval evaluated")
        self.live_record = LooksLikeApproval()
        self.assert_denied_without_effect()

    def test_low_risk_lab_tool_remains_available_without_stepup(self):
        app = DestructiveLabStepUpExecutor(self.executor)
        result = app.execute(
            self.context,
            ToolCall(tool_id=self.low_risk.tool_id, asset="isolated-simulator-one")
        )
        self.assertEqual(result.tool_id, self.low_risk.tool_id)
        self.assertEqual(len(self.invocations), 1)

    def test_noncanonical_run_and_call_denied_before_handler(self):
        class ForeignContext:
            run_id = "run-lab-a"
        class ForeignCall:
            tool_id = "synthetic-lab-destructive"
        self.assert_denied_without_effect(context=ForeignContext())
        self.assert_denied_without_effect(call=ForeignCall())


if __name__ == "__main__":
    unittest.main()
