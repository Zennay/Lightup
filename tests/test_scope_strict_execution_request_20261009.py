"""Offline real-ToolExecutor tests for the optional strict request admission."""
from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from enum import IntEnum
from pathlib import Path

from lightup.ai.orchestration import (
    RunContext, ToolCall, ToolDefinition, ToolDenied, ToolExecutor,
    ToolOutput, ToolRegistry,
)
from lightup.engagements import (
    AssessmentMode, AuthorizationGrant, RiskLevel, ScopeDefinition,
)
from lightup.execution_policy import ExecutionRequest, InteractionKind
from lightup.state import StateStore
from lightup.strict_request_policy import StrictExecutionRequestPolicy


def grant() -> AuthorizationGrant:
    now = datetime.now(timezone.utc)
    return AuthorizationGrant(
        grant_id="synthetic-grant", client_id="synthetic-client",
        engagement_id="synthetic-engagement", approved_by="fixture-operator",
        reference="fixture-only",
        scope=ScopeDefinition(
            assets=("safe.example.test",), max_risk=RiskLevel.LOW_IMPACT,
            allowed_capabilities=("web-baseline",),
        ),
        valid_from=now - timedelta(minutes=5),
        valid_until=now + timedelta(minutes=5),
    )


def request(**changes) -> ExecutionRequest:
    return replace(ExecutionRequest(
        interaction=InteractionKind.TARGET_ACTIVE,
        asset="safe.example.test",
        capability_id="web-baseline",
        requested_risk=RiskLevel.LOW_IMPACT,
        authorization=grant(),
        is_lab=False,
    ), **changes)


class WeirdText(str):
    pass


class WeirdGrant(AuthorizationGrant):
    pass


class ImpostorRisk(IntEnum):
    LOW_IMPACT = 2


class StrictEnvelopeUnitTests(unittest.TestCase):
    def setUp(self):
        self.policy = StrictExecutionRequestPolicy()

    def test_genuine_exact_request_is_admitted_only_with_scope(self):
        self.assertTrue(self.policy.decide(request()).allowed)
        self.assertFalse(self.policy.decide(request(asset="outside.example.test")).allowed)
        self.assertFalse(self.policy.decide(request(authorization=None)).allowed)

    def test_interaction_lookalikes_are_denied(self):
        for value in ("target_active", "lab_active", "analysis", None, 3, True):
            with self.subTest(value=value):
                self.assertFalse(self.policy.decide(request(interaction=value)).allowed)

    def test_risk_coercion_is_denied(self):
        for value in (2, True, 2.0, "2", ImpostorRisk.LOW_IMPACT, None):
            with self.subTest(value=value):
                self.assertFalse(self.policy.decide(request(requested_risk=value)).allowed)

    def test_lab_marker_requires_exact_bool_and_cannot_mask_target_active(self):
        for value in (1, 0, "false", "true", None, WeirdText("false")):
            with self.subTest(value=value):
                self.assertFalse(self.policy.decide(request(is_lab=value)).allowed)
        self.assertFalse(self.policy.decide(request(is_lab=True)).allowed)

    def test_exact_authority_text_rejects_polymorphism_controls_and_padding(self):
        for value in ("", " ", "safe.example.test ", "safe.example.test\n",
                      "safe.example.test\x00", WeirdText("safe.example.test"), 12):
            with self.subTest(value=value):
                self.assertFalse(self.policy.decide(request(asset=value)).allowed)
        for value in ("", " web-baseline", "web-baseline\r",
                      WeirdText("web-baseline"), False):
            with self.subTest(value=value):
                self.assertFalse(self.policy.decide(request(capability_id=value)).allowed)

    def test_grant_subclass_and_wrong_outer_request_types_rejected(self):
        self.assertFalse(self.policy.decide(request(authorization=WeirdGrant(**grant().__dict__))).allowed)
        class SubRequest(ExecutionRequest):
            pass
        self.assertFalse(self.policy.decide(SubRequest(**request().__dict__)).allowed)
        self.assertFalse(self.policy.decide(object()).allowed)

    def test_grant_scope_duck_typing_cannot_grant_authority(self):
        class FakeScope:
            max_risk = RiskLevel.DESTRUCTIVE_LAB_ONLY

            def allows_asset(self, _asset):
                return True

            def allows_capability(self, _capability):
                return True

        fabricated = replace(grant(), scope=FakeScope())
        self.assertFalse(self.policy.decide(request(authorization=fabricated)).allowed)

    def test_grant_nested_types_fail_closed(self):
        genuine = grant()
        bad_scopes = (
            replace(genuine.scope, assets=["safe.example.test"]),
            replace(genuine.scope, allowed_capabilities=("web-baseline", WeirdText("other"))),
            replace(genuine.scope, excluded_assets=("outside.example.test\n",)),
            replace(genuine.scope, max_risk=2),
        )
        for scope in bad_scopes:
            with self.subTest(scope=repr(scope)):
                self.assertFalse(self.policy.decide(request(
                    authorization=replace(genuine, scope=scope),
                )).allowed)
        self.assertFalse(self.policy.decide(request(
            authorization=replace(genuine, recurring_retest_allowed="false"),
        )).allowed)
        self.assertFalse(self.policy.decide(request(
            authorization=replace(genuine, client_id=WeirdText("synthetic-client")),
        )).allowed)

    def test_naive_inverted_and_bad_grant_windows_are_denied(self):
        genuine = grant()
        for modified in (
            replace(genuine, valid_from=datetime(2026, 1, 1)),
            replace(genuine, valid_until=datetime(2027, 1, 1)),
            replace(genuine, valid_from=genuine.valid_until + timedelta(seconds=1)),
            replace(genuine, valid_until="tomorrow"),
        ):
            with self.subTest(grant=repr(modified)):
                self.assertFalse(self.policy.decide(request(authorization=modified)).allowed)

    def test_lab_positive_and_missing_lab_marker_negative(self):
        r = request(
            interaction=InteractionKind.LAB_ACTIVE,
            requested_risk=RiskLevel.LOW_IMPACT,
            authorization=None,
            is_lab=True,
        )
        self.assertTrue(self.policy.decide(r).allowed)
        self.assertFalse(self.policy.decide(replace(r, is_lab=False)).allowed)

    def test_never_elevates_risk_or_extends_expired_grant(self):
        self.assertFalse(self.policy.decide(request(requested_risk=RiskLevel.ELEVATED)).allowed)
        expired = replace(grant(), valid_until=datetime.now(timezone.utc) - timedelta(seconds=1))
        self.assertFalse(self.policy.decide(request(authorization=expired)).allowed)


class StrictEnvelopeRealExecutorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = StateStore(Path(self.tmp.name) / "scope-guard.db")
        self.registry = ToolRegistry()
        self.handled = []
        self.executor = ToolExecutor(self.registry, self.state, policy=StrictExecutionRequestPolicy())
        self.context = RunContext(
            run_id="strict-offline-run", client_id="synthetic-client",
            engagement_id="synthetic-engagement",
            mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            approved_risk=RiskLevel.LOW_IMPACT,
            authorization=grant(), is_lab=False,
            created_at=datetime.now(timezone.utc),
        )

    def register(self, tool_id="synthetic", interaction=InteractionKind.TARGET_ACTIVE,
                 risk=RiskLevel.LOW_IMPACT, capability="web-baseline"):
        def handler(_context, _args):
            self.handled.append("handled")
            return ToolOutput("offline synthetic result", "unit", b"not-target-evidence")
        self.registry.register(
            ToolDefinition(tool_id, capability, interaction, risk, "pure synthetic"),
            handler,
        )

    def evidence_count(self):
        with self.state.connect() as connection:
            return connection.execute("SELECT count(*) FROM evidence").fetchone()[0]

    def test_real_executor_positive_control_still_writes_evidence(self):
        self.register()
        result = self.executor.execute(self.context, ToolCall("synthetic", "safe.example.test"))
        self.assertTrue(result.evidence_id)
        self.assertEqual(self.handled, ["handled"])
        self.assertEqual(self.evidence_count(), 1)

    def test_real_executor_rejects_lookalike_interaction_before_effects(self):
        self.register(interaction="target_active")
        with self.assertRaises(ToolDenied):
            self.executor.execute(self.context, ToolCall("synthetic", "safe.example.test"))
        self.assertEqual(self.handled, [])
        self.assertEqual(self.evidence_count(), 0)

    def test_real_executor_rejects_int_risk_before_effects(self):
        self.register(risk=2)
        with self.assertRaises(ToolDenied):
            self.executor.execute(self.context, ToolCall("synthetic", "safe.example.test"))
        self.assertEqual(self.handled, [])
        self.assertEqual(self.evidence_count(), 0)

    def test_real_executor_rejects_polymorphic_asset_before_effects(self):
        self.register()
        with self.assertRaises(ToolDenied):
            self.executor.execute(self.context, ToolCall("synthetic", WeirdText("safe.example.test")))
        self.assertEqual(self.handled, [])
        self.assertEqual(self.evidence_count(), 0)


if __name__ == "__main__":
    unittest.main()
