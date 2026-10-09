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
    ToolOutput, ToolRegistry, ToolParameter, ParamKind,
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

    @unittest.expectedFailure
    def test_red_default_raw_executor_has_no_destructive_stepup_gate_yet(self):
        # RED integration canary, intentionally NOT a passing safety guarantee.
        # Production owner #107 must require verified step-up at every entry.
        with self.assertRaises(ToolDenied):
            self.executor.execute(self.context, self.call)

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

    def test_same_capability_different_tool_cannot_reuse_approval(self):
        alternate = ToolDefinition(
            tool_id="synthetic-lab-destructive-alternate",
            capability_id=self.destructive.capability_id,
            interaction=InteractionKind.LAB_ACTIVE,
            min_risk=RiskLevel.DESTRUCTIVE_LAB_ONLY,
            description="Independent offline no-op tool",
        )
        self.registry.register(
            alternate,
            lambda context, arguments: ToolOutput(
                "synthetic alternate", "note", b"synthetic"
            ),
        )
        self.assert_denied_without_effect(
            call=ToolCall(tool_id=alternate.tool_id, asset=self.call.asset)
        )

    def test_current_approval_revoked_after_initial_success_cannot_replay(self):
        wrapper = self.wrapper()
        first = wrapper.execute(self.context, self.call)
        self.assertEqual(first.run_id, self.context.run_id)
        self.live_record = replace(self.approval, expires_at=self.now - timedelta(seconds=1))
        self.assert_denied_without_effect(wrapper)
        self.live_record = replace(self.approval, asset="different-lab")
        self.assert_denied_without_effect(wrapper)
        self.assertEqual(len(self.invocations), 1)

    def test_approval_and_context_fields_refuse_noncanonical_subclasses(self):
        class PretendStr(str):
            pass

        self.live_record = replace(
            self.approval, asset=PretendStr(self.call.asset)
        )
        self.assert_denied_without_effect()
        self.live_record = self.approval
        self.assert_denied_without_effect(
            context=replace(self.context, client_id=PretendStr(self.context.client_id))
        )

    def test_noncanonical_run_and_call_denied_before_handler(self):
        class ForeignContext:
            run_id = "run-lab-a"
        class ForeignCall:
            tool_id = "synthetic-lab-destructive"
        self.assert_denied_without_effect(context=ForeignContext())
        self.assert_denied_without_effect(call=ForeignCall())

    def test_noncanonical_registered_tool_risk_and_kind_are_denied(self):
        original = self.registry._tools[self.destructive.tool_id]
        definition, handler = original
        try:
            for fields in (
                {"min_risk": 5},
                {"min_risk": True},
                {"min_risk": "5"},
                {"interaction": "lab_active"},
                {"tool_id": "other-tool"},
                {"capability_id": " compromised "},
            ):
                with self.subTest(fields=fields):
                    self.registry._tools[self.destructive.tool_id] = (
                        replace(definition, **fields), handler,
                    )
                    self.assert_denied_without_effect()
        finally:
            self.registry._tools[self.destructive.tool_id] = original

    def test_lab_context_cannot_mix_external_authorization_with_destructive_approval(self):
        # The lab label must not borrow authority from an unrelated grant.
        self.assert_denied_without_effect(
            context=replace(self.context, authorization=object())
        )

    def test_approval_resolver_cannot_replace_registered_handler_during_admission(self):
        definition, _ = self.registry.get(self.destructive.tool_id)
        calls = []
        def substituted(context, arguments):
            calls.append("changed")
            return ToolOutput("untrusted", "note", b"untrusted")

        def mutate(run_id):
            self.registry._tools[self.destructive.tool_id] = (definition, substituted)
            return self.approval

        wrapper = DestructiveLabStepUpExecutor(self.executor, mutate)
        self.assert_denied_without_effect(wrapper)
        self.assertEqual(calls, [])

    def test_approval_resolver_cannot_replace_identical_definition_object(self):
        definition, handler = self.registry.get(self.destructive.tool_id)
        def mutate(run_id):
            self.registry._tools[self.destructive.tool_id] = (
                replace(definition), handler,
            )
            return self.approval
        self.assert_denied_without_effect(
            DestructiveLabStepUpExecutor(self.executor, mutate)
        )

    def test_approval_resolver_cannot_swap_entire_registry(self):
        def mutate(run_id):
            self.executor.registry = ToolRegistry()
            return self.approval
        self.assert_denied_without_effect(
            DestructiveLabStepUpExecutor(self.executor, mutate)
        )

    def test_resolver_private_exception_is_not_chained_to_public_denial(self):
        def private_failure(run_id):
            raise RuntimeError("PRIVATE_OPERATOR_APPROVAL_DB_DETAIL")

        wrapper = DestructiveLabStepUpExecutor(self.executor, private_failure)
        with self.assertRaises(ToolDenied) as caught:
            wrapper.execute(self.context, self.call)
        self.assertEqual(str(caught.exception), "destructive-lab approval unavailable")
        self.assertIsNone(caught.exception.__cause__)
        self.assertTrue(caught.exception.__suppress_context__)
        self.assertEqual(self.invocations, [])

    def test_operator_approval_is_bounded_to_at_most_one_day(self):
        exact = replace(
            self.approval,
            expires_at=self.approval.approved_at + timedelta(hours=24),
        )
        self.assertTrue(destructive_lab_approval_matches(
            exact, self.context, self.call, self.destructive, now=self.now
        ))
        overlong = replace(
            exact, expires_at=exact.expires_at + timedelta(microseconds=1)
        )
        self.live_record = overlong
        self.assert_denied_without_effect()

    def test_control_chars_and_oversized_approval_identifiers_denied(self):
        for value in (
            "operator\nother", "operator\radmin", "operator\troot",
            "operator\x00root", "operator\x7froot", "x" * 257,
            "operator-☃",
        ):
            with self.subTest(identity=value):
                self.live_record = replace(self.approval, approved_by=value)
                self.assert_denied_without_effect()
        self.live_record = self.approval
        self.assert_denied_without_effect(
            context=replace(self.context, run_id="run\x00forged")
        )
        self.assert_denied_without_effect(
            call=ToolCall(self.call.tool_id, "lab\nother")
        )

    def test_direct_approval_match_cannot_bind_unrelated_definition_tool(self):
        unrelated = replace(self.destructive, tool_id="another-noop-tool")
        self.assertFalse(destructive_lab_approval_matches(
            self.approval, self.context, self.call, unrelated, now=self.now
        ))

    def test_authorization_expires_exclusively_at_boundary(self):
        boundary = replace(self.approval, expires_at=self.now)
        self.assertFalse(destructive_lab_approval_matches(
            boundary, self.context, self.call, self.destructive, now=self.now
        ))

    def test_parameterized_destructive_lab_tool_cannot_choose_another_destination(self):
        # The current registry cannot express which argument names select
        # network or filesystem destinations. A per-asset approval is not
        # authorization for an arbitrary host value in model arguments.
        def handler(context, arguments):
            self.invocations.append("bad-handler")
            return ToolOutput("bad handler", "note", b"bad-handler")

        param_tool = ToolDefinition(
            tool_id="synthetic-lab-param-tool",
            capability_id="wireless-lab",
            interaction=InteractionKind.LAB_ACTIVE,
            min_risk=RiskLevel.DESTRUCTIVE_LAB_ONLY,
            description="Offline only; argument is never inspected by a tool",
            parameters=(ToolParameter("host", ParamKind.STRING, required=True),),
        )
        self.registry.register(param_tool, handler)
        self.live_record = replace(self.approval, tool_id=param_tool.tool_id)
        self.assert_denied_without_effect(call=ToolCall(
            tool_id=param_tool.tool_id,
            asset=self.call.asset,
            arguments=(("host", "outside-lab.example.test"),),
        ))
        self.assert_denied_without_effect(call=ToolCall(
            tool_id=param_tool.tool_id,
            asset=self.call.asset,
        ))
        self.assertNotIn("bad-handler", self.invocations)

    def test_unexpected_arguments_on_risk_five_no_param_tool_rejected(self):
        self.assert_denied_without_effect(call=ToolCall(
            tool_id=self.call.tool_id,
            asset=self.call.asset,
            arguments=(("host", "outside-lab.example.test"),),
        ))

    def test_low_risk_parameterized_lab_contract_remains_delegated(self):
        def handler(context, arguments):
            self.invocations.append(arguments["label"])
            return ToolOutput("ok", "note", b"safe")
        low_param = ToolDefinition(
            tool_id="synthetic-lab-low-risk-param",
            capability_id="wireless-lab",
            interaction=InteractionKind.LAB_ACTIVE,
            min_risk=RiskLevel.LOW_IMPACT,
            description="No-op labelled lab proof",
            parameters=(ToolParameter("label", ParamKind.STRING),),
        )
        self.registry.register(low_param, handler)
        result = DestructiveLabStepUpExecutor(self.executor).execute(
            self.context,
            ToolCall(low_param.tool_id, self.call.asset, (("label", "safe"),)),
        )
        self.assertEqual(result.tool_id, low_param.tool_id)
        self.assertEqual(self.invocations, ["safe"])


if __name__ == "__main__":
    unittest.main()
