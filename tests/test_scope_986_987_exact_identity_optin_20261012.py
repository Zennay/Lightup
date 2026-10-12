"""Synthetic, side-effect-checked acceptance for opt-in enum identity gate.

No live targets. Test handlers only return fixed in-memory evidence bytes.
Production source owners #100/#107 retain installed policy/executor ownership.
"""
from __future__ import annotations

import tempfile
from dataclasses import replace
import unittest
from datetime import datetime, timedelta, timezone
from enum import IntEnum
from pathlib import Path
from uuid import uuid4

from lightup.ai.orchestration import (
    RunContext, ToolCall, ToolDefinition, ToolDenied, ToolExecutor,
    ToolOutput, ToolRegistry,
)
from lightup.engagements import (
    AssessmentMode, AuthorizationGrant, RiskLevel, ScopeDefinition,
)
from lightup.execution_policy import ExecutionRequest, InteractionKind
from lightup.scope_exact_identity_policy import StrictIdentityExecutionPolicy
from lightup.state import StateStore


class ForeignRisk(IntEnum):
    PASSIVE = 1
    LOW_IMPACT = 2


def _grant() -> AuthorizationGrant:
    now = datetime.now(timezone.utc)
    return AuthorizationGrant(
        grant_id="synthetic-identity-grant",
        client_id="synthetic-client",
        engagement_id="synthetic-engagement",
        approved_by="synthetic-operator",
        reference="offline-contract",
        scope=ScopeDefinition(
            assets=("asset.example.test",),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=("web-baseline",),
        ),
        valid_from=now - timedelta(minutes=1),
        valid_until=now + timedelta(minutes=30),
    )


def _request(interaction, risk, authorization=None) -> ExecutionRequest:
    return ExecutionRequest(
        interaction=interaction,
        asset="asset.example.test",
        capability_id="web-baseline",
        requested_risk=risk,
        authorization=authorization,
    )


class ExactIdentityPolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = StrictIdentityExecutionPolicy()

    def test_canonical_passive_and_analysis_controls(self):
        for interaction, risk in (
            (InteractionKind.ANALYSIS, RiskLevel.ANALYSIS_ONLY),
            (InteractionKind.PASSIVE_PUBLIC, RiskLevel.PASSIVE),
        ):
            with self.subTest(interaction=interaction):
                self.assertTrue(self.policy.decide(_request(interaction, risk)).allowed)

    def test_canonical_authorized_active_control(self):
        self.assertTrue(
            self.policy.decide(
                _request(InteractionKind.TARGET_ACTIVE, RiskLevel.LOW_IMPACT, _grant())
            ).allowed
        )

    def test_malformed_interaction_never_inherits_valid_active_grant(self):
        for bad in (None, True, False, 0, 1, "target_active", b"target_active", object()):
            with self.subTest(bad_type=type(bad).__name__, value=repr(bad)):
                decision = self.policy.decide(
                    _request(bad, RiskLevel.LOW_IMPACT, _grant())
                )
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, "noncanonical interaction kind")

    def test_malformed_passive_risk_is_not_numeric_authority(self):
        for bad in (None, True, False, 0, 1, -1, "1", ForeignRisk.PASSIVE):
            with self.subTest(bad_type=type(bad).__name__, value=repr(bad)):
                decision = self.policy.decide(
                    _request(InteractionKind.PASSIVE_PUBLIC, bad)
                )
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, "noncanonical requested risk")

    def test_malformed_active_risk_is_denied_even_with_grant(self):
        for bad in (True, False, 1, 2, ForeignRisk.LOW_IMPACT, "2"):
            with self.subTest(bad_type=type(bad).__name__, value=repr(bad)):
                self.assertFalse(
                    self.policy.decide(
                        _request(InteractionKind.TARGET_ACTIVE, bad, _grant())
                    ).allowed
                )

    def test_canonical_grant_constraints_remain_authoritative(self):
        self.assertFalse(
            self.policy.decide(
                _request(InteractionKind.TARGET_ACTIVE, RiskLevel.LOW_IMPACT)
            ).allowed
        )
        self.assertFalse(
            self.policy.decide(
                ExecutionRequest(
                    interaction=InteractionKind.TARGET_ACTIVE,
                    asset="different.example.test",
                    capability_id="web-baseline",
                    requested_risk=RiskLevel.LOW_IMPACT,
                    authorization=_grant(),
                )
            ).allowed
        )
        self.assertFalse(
            self.policy.decide(
                _request(InteractionKind.TARGET_ACTIVE, RiskLevel.ELEVATED, _grant())
            ).allowed
        )


    def test_canonical_mode_risk_matrix_preserves_inherited_decisions(self):
        from lightup.execution_policy import ExecutionPolicy

        original = ExecutionPolicy()
        # Full 4 x 6 x 2 x 2 synthetic matrix: strictly typed inputs must
        # produce exactly the unchanged production policy's decision.
        for interaction in InteractionKind:
            for risk in RiskLevel:
                for is_lab in (False, True):
                    for grant in (None, _grant()):
                        with self.subTest(
                            interaction=interaction.name,
                            risk=risk.name,
                            lab=is_lab,
                            grant=grant is not None,
                        ):
                            request = ExecutionRequest(
                                interaction=interaction,
                                asset="asset.example.test",
                                capability_id="web-baseline",
                                requested_risk=risk,
                                authorization=grant,
                                is_lab=is_lab,
                            )
                            self.assertEqual(
                                self.policy.decide(request),
                                original.decide(request),
                            )

    def test_invalid_interaction_does_not_consult_poison_grant(self):
        class PoisonGrant:
            def is_current(self):
                raise AssertionError("invalid interaction reached grant")

            @property
            def scope(self):
                raise AssertionError("invalid interaction reached scope")

        for bad in (None, "target_active", 1, True):
            with self.subTest(value=str(bad)):
                result = self.policy.decide(
                    _request(bad, RiskLevel.STANDARD, PoisonGrant())
                )
                self.assertFalse(result.allowed)
                self.assertEqual(result.reason, "noncanonical interaction kind")

    def test_invalid_risk_does_not_consult_poison_grant(self):
        class PoisonGrant:
            def is_current(self):
                raise AssertionError("invalid risk reached grant")

            @property
            def scope(self):
                raise AssertionError("invalid risk reached scope")

        for bad in (True, 1, ForeignRisk.LOW_IMPACT, "2", None):
            with self.subTest(value=str(bad)):
                result = self.policy.decide(
                    _request(InteractionKind.TARGET_ACTIVE, bad, PoisonGrant())
                )
                self.assertFalse(result.allowed)
                self.assertEqual(result.reason, "noncanonical requested risk")

    def test_canonical_expired_and_not_yet_valid_grants_remain_denied(self):
        now = datetime.now(timezone.utc)
        grant = _grant()
        expired = replace(
            grant,
            valid_from=now - timedelta(days=2),
            valid_until=now - timedelta(days=1),
        )
        future = replace(
            grant,
            valid_from=now + timedelta(days=1),
            valid_until=now + timedelta(days=2),
        )
        for rejected in (expired, future):
            with self.subTest(grant_window=rejected.valid_from.isoformat()):
                self.assertFalse(
                    self.policy.decide(
                        _request(
                            InteractionKind.TARGET_ACTIVE,
                            RiskLevel.LOW_IMPACT,
                            rejected,
                        )
                    ).allowed
                )

    def test_canonical_disallowed_capability_remains_denied(self):
        request = ExecutionRequest(
            interaction=InteractionKind.TARGET_ACTIVE,
            asset="asset.example.test",
            capability_id="identity-access",
            requested_risk=RiskLevel.LOW_IMPACT,
            authorization=_grant(),
        )
        self.assertFalse(self.policy.decide(request).allowed)

    def test_invalid_interaction_takes_precedence_over_invalid_risk(self):
        result = self.policy.decide(_request("target_active", True, _grant()))
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "noncanonical interaction kind")



class RealToolExecutorIdentityTests(unittest.TestCase):
    """Real ToolExecutor, registry and disposable SQLite; zero target I/O."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = StateStore(Path(self.tmp.name) / "offline.db")
        self.registry = ToolRegistry()
        self.handler_calls = 0

    def _handler(self, context, arguments):
        self.handler_calls += 1
        return ToolOutput("synthetic only", "synthetic", b"no target interaction")

    def _register(self, tool_id, interaction, risk):
        self.registry.register(
            ToolDefinition(
                tool_id=tool_id,
                capability_id="web-baseline",
                interaction=interaction,
                min_risk=risk,
                description="offline identity control",
            ),
            self._handler,
        )

    def _context(self, mode, risk, grant=None):
        return RunContext(
            run_id=str(uuid4()),
            client_id="synthetic-client",
            engagement_id="synthetic-engagement",
            mode=mode,
            approved_risk=risk,
            authorization=grant,
            is_lab=False,
            created_at=datetime.now(timezone.utc),
        )

    def _evidence_count(self):
        with self.state.connect() as con:
            return con.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]

    def test_unknown_interaction_reaches_no_handler_or_evidence(self):
        context = self._context(
            AssessmentMode.AUTHORIZED_ASSESSMENT,
            RiskLevel.STANDARD,
            _grant(),
        )
        for idx, bad in enumerate((None, "target_active", 1, True)):
            with self.subTest(value=repr(bad)):
                tool_id = f"bad-interaction-{idx}"
                self._register(tool_id, bad, RiskLevel.LOW_IMPACT)
                executor = ToolExecutor(
                    self.registry, self.state, policy=StrictIdentityExecutionPolicy()
                )
                with self.assertRaises(ToolDenied):
                    executor.execute(context, ToolCall(tool_id, "asset.example.test"))
                self.assertEqual(self.handler_calls, 0)
                self.assertEqual(self._evidence_count(), 0)

    def test_noncanonical_passive_risk_has_no_handler_or_evidence(self):
        context = self._context(AssessmentMode.PASSIVE_DISCOVERY, RiskLevel.PASSIVE)
        for idx, bad in enumerate((True, False, 0, 1, ForeignRisk.PASSIVE)):
            with self.subTest(value=repr(bad)):
                tool_id = f"bad-passive-risk-{idx}"
                self._register(tool_id, InteractionKind.PASSIVE_PUBLIC, bad)
                executor = ToolExecutor(
                    self.registry, self.state, policy=StrictIdentityExecutionPolicy()
                )
                with self.assertRaises(ToolDenied):
                    executor.execute(context, ToolCall(tool_id, "asset.example.test"))
                self.assertEqual(self.handler_calls, 0)
                self.assertEqual(self._evidence_count(), 0)

    def test_real_executor_canonical_passive_positive(self):
        self._register(
            "valid-passive", InteractionKind.PASSIVE_PUBLIC, RiskLevel.PASSIVE
        )
        executor = ToolExecutor(
            self.registry, self.state, policy=StrictIdentityExecutionPolicy()
        )
        result = executor.execute(
            self._context(AssessmentMode.PASSIVE_DISCOVERY, RiskLevel.PASSIVE),
            ToolCall("valid-passive", "asset.example.test"),
        )
        self.assertEqual(result.policy_reason, "public passive discovery")
        self.assertEqual(self.handler_calls, 1)
        self.assertEqual(self._evidence_count(), 1)


    def test_canonical_active_real_executor_positive_is_synthetic(self):
        self._register(
            "valid-active", InteractionKind.TARGET_ACTIVE, RiskLevel.LOW_IMPACT
        )
        executor = ToolExecutor(
            self.registry, self.state, policy=StrictIdentityExecutionPolicy()
        )
        result = executor.execute(
            self._context(
                AssessmentMode.AUTHORIZED_ASSESSMENT, RiskLevel.STANDARD, _grant()
            ),
            ToolCall("valid-active", "asset.example.test"),
        )
        self.assertEqual(result.policy_reason, "authorized active assessment")
        self.assertEqual(self.handler_calls, 1)
        self.assertEqual(self._evidence_count(), 1)

    def test_canonical_active_grant_refusals_do_not_dispatch(self):
        self._register(
            "active-denial", InteractionKind.TARGET_ACTIVE, RiskLevel.LOW_IMPACT
        )
        executor = ToolExecutor(
            self.registry, self.state, policy=StrictIdentityExecutionPolicy()
        )
        context_without_grant = self._context(
            AssessmentMode.AUTHORIZED_ASSESSMENT, RiskLevel.STANDARD
        )
        context_with_grant = self._context(
            AssessmentMode.AUTHORIZED_ASSESSMENT, RiskLevel.STANDARD, _grant()
        )
        for context, asset in (
            (context_without_grant, "asset.example.test"),
            (context_with_grant, "outside.example.test"),
        ):
            with self.subTest(asset=asset, grant=context.authorization is not None):
                with self.assertRaises(ToolDenied):
                    executor.execute(context, ToolCall("active-denial", asset))
                self.assertEqual(self.handler_calls, 0)
                self.assertEqual(self._evidence_count(), 0)

    def test_noncanonical_active_risk_does_not_dispatch(self):
        self._register("bad-active-risk", InteractionKind.TARGET_ACTIVE, True)
        executor = ToolExecutor(
            self.registry, self.state, policy=StrictIdentityExecutionPolicy()
        )
        with self.assertRaises(ToolDenied):
            executor.execute(
                self._context(
                    AssessmentMode.AUTHORIZED_ASSESSMENT, RiskLevel.STANDARD, _grant()
                ),
                ToolCall("bad-active-risk", "asset.example.test"),
            )
        self.assertEqual(self.handler_calls, 0)
        self.assertEqual(self._evidence_count(), 0)

    def test_default_executor_has_not_installed_the_reference_gate(self):
        from lightup.execution_policy import ExecutionPolicy

        default_executor = ToolExecutor(self.registry, self.state)
        self.assertIs(
            type(default_executor.policy), ExecutionPolicy,
            "an opt-in reference is not authorization in the installed default",
        )


    def test_rejected_call_does_not_mutate_preexisting_evidence(self):
        self._register(
            "existing-passive", InteractionKind.PASSIVE_PUBLIC, RiskLevel.PASSIVE
        )
        executor = ToolExecutor(
            self.registry, self.state, policy=StrictIdentityExecutionPolicy()
        )
        context = self._context(AssessmentMode.PASSIVE_DISCOVERY, RiskLevel.PASSIVE)
        first = executor.execute(
            context, ToolCall("existing-passive", "asset.example.test")
        )
        self.assertEqual(self._evidence_count(), 1)
        with self.state.connect() as con:
            original = tuple(
                con.execute(
                    "SELECT evidence_id, run_id, kind, source, payload_hash "
                    "FROM evidence ORDER BY evidence_id"
                )
            )
        self._register("rejected-passive", InteractionKind.PASSIVE_PUBLIC, True)
        with self.assertRaises(ToolDenied):
            executor.execute(
                context, ToolCall("rejected-passive", "asset.example.test")
            )
        with self.state.connect() as con:
            after = tuple(
                con.execute(
                    "SELECT evidence_id, run_id, kind, source, payload_hash "
                    "FROM evidence ORDER BY evidence_id"
                )
            )
        self.assertEqual([tuple(row) for row in original],
                         [tuple(row) for row in after])
        self.assertEqual(first.evidence_id, original[0]["evidence_id"])
        self.assertEqual(self.handler_calls, 1)


if __name__ == "__main__":
    unittest.main()
