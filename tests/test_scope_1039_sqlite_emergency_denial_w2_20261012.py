"""Real disposable SQLite evidence acceptance for the uninstalled emergency STOP gate.

All handlers are in-memory; target strings are inert. The two expected-RED
canaries characterize source-owner #100's *unrepaired main-branch* tenant/
engagement lineage hole, not a repaired or authorized execution path.
"""
from __future__ import annotations

import hashlib
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from lightup.ai.orchestration import (
    RiskElevationRequired, RunContext, ToolCall, ToolDefinition,
    ToolDenied, ToolExecutor, ToolOutput, ToolRegistry,
)
from lightup.emergency_dispatch_optin import execute_with_emergency_gate
from lightup.engagements import AssessmentMode, AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.execution_policy import ExecutionPolicy, InteractionKind
from lightup.state import StateStore


class SQLiteEmergencyStopAcceptance(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = StateStore(Path(self.tmp.name) / "disposable.db")
        self.run_id = self.state.create_run(target="127.0.0.1")
        self.handler = Mock(return_value=ToolOutput(
            summary="synthetic in-memory handler",
            evidence_kind="offline_fixture",
            evidence_payload=b"no network request or client information",
        ))
        self.registry = ToolRegistry()
        self.registry.register(
            ToolDefinition(
                tool_id="synthetic-offline-capability",
                capability_id="web-baseline",
                interaction=InteractionKind.TARGET_ACTIVE,
                min_risk=RiskLevel.STANDARD,
                description="only a synthetic mock function; not a scanner",
            ),
            self.handler,
        )
        self.executor = ToolExecutor(self.registry, self.state, ExecutionPolicy())
        now = datetime.now(timezone.utc)
        self.grant = AuthorizationGrant(
            grant_id="synthetic-only",
            client_id="fixture-client",
            engagement_id="fixture-engagement",
            approved_by="fixture-operator",
            reference="NOT-A-CONSENT-RECEIPT",
            scope=ScopeDefinition(
                assets=("127.0.0.1",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("web-baseline",),
            ),
            valid_from=now - timedelta(minutes=5),
            valid_until=now + timedelta(minutes=5),
        )
        self.context = RunContext(
            run_id=self.run_id,
            client_id="fixture-client",
            engagement_id="fixture-engagement",
            mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            approved_risk=RiskLevel.STANDARD,
            authorization=self.grant,
            is_lab=False,
            created_at=now,
        )
        self.call = ToolCall(tool_id="synthetic-offline-capability", asset="127.0.0.1")

    def evidence_count(self):
        with self.state.connect() as con:
            return con.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]

    def run_count(self):
        with self.state.connect() as con:
            return con.execute("SELECT COUNT(*) FROM runs").fetchone()[0]

    def invoke(self, *, stop=False, override=False, context=None, call=None):
        with patch("socket.socket", side_effect=AssertionError("no network")):
            return execute_with_emergency_gate(
                self.executor,
                context if context is not None else self.context,
                call if call is not None else self.call,
                stop_active=stop,
                override_requested=override,
            )

    def assert_unchanged_denial(self):
        self.assertEqual(self.evidence_count(), 0)
        self.assertEqual(self.run_count(), 1)
        self.handler.assert_not_called()

    def test_positive_synthetic_handler_writes_one_real_evidence_record(self):
        result = self.invoke()
        self.assertEqual(self.evidence_count(), 1)
        self.assertEqual(self.run_count(), 1)
        self.handler.assert_called_once()
        record = self.state.get_evidence(result.evidence_id)
        self.assertEqual(record.run_id, self.run_id)
        self.assertEqual(record.capability_id, "web-baseline")
        self.assertEqual(
            record.sha256,
            hashlib.sha256(b"no network request or client information").hexdigest(),
        )
        self.assertIn(("client_id", "fixture-client"), record.metadata)

    def test_stop_denies_valid_grant_without_durable_effects(self):
        for override in (False, True):
            with self.subTest(override=override):
                with self.assertRaisesRegex(ToolDenied, "emergency STOP"):
                    self.invoke(stop=True, override=override)
                self.assert_unchanged_denial()

    def test_stop_reason_dominates_malformed_override(self):
        for invalid in (None, 1, "false", [], object()):
            with self.subTest(type=type(invalid).__name__):
                with self.assertRaisesRegex(ToolDenied, "emergency STOP"):
                    self.invoke(stop=True, override=invalid)
                self.assert_unchanged_denial()

    def test_invalid_inputs_never_persist_evidence(self):
        class TruthTrap:
            def __bool__(self):
                raise AssertionError("truth coercion is unsafe")
        for override in (None, 0, 1, "false", TruthTrap()):
            with self.subTest(type=type(override).__name__):
                with self.assertRaises(ToolDenied):
                    self.invoke(override=override)
                self.assert_unchanged_denial()
        for stop in ("false", "true", None, 1, TruthTrap()):
            with self.subTest(type=type(stop).__name__):
                with self.assertRaises(ToolDenied):
                    self.invoke(stop=stop)
                self.assert_unchanged_denial()

    def test_override_cannot_mint_missing_grant(self):
        with self.assertRaises(ToolDenied):
            self.invoke(override=True, context=replace(self.context, authorization=None))
        self.assert_unchanged_denial()

    def test_override_cannot_resurrect_expired_grant(self):
        old = replace(self.grant, valid_from=datetime(2001, 1, 1, tzinfo=timezone.utc),
                      valid_until=datetime(2001, 1, 2, tzinfo=timezone.utc))
        with self.assertRaises(ToolDenied):
            self.invoke(override=True, context=replace(self.context, authorization=old))
        self.assert_unchanged_denial()

    def test_override_cannot_reach_other_asset(self):
        with self.assertRaises(ToolDenied):
            self.invoke(override=True, call=replace(self.call, asset="127.0.0.2"))
        self.assert_unchanged_denial()

    def test_override_cannot_extend_capability_scope(self):
        narrower = replace(self.grant.scope, allowed_capabilities=("network-services",))
        with self.assertRaises(ToolDenied):
            self.invoke(override=True, context=replace(
                self.context, authorization=replace(self.grant, scope=narrower)))
        self.assert_unchanged_denial()

    def test_override_cannot_increase_run_risk_ceiling(self):
        with self.assertRaises(RiskElevationRequired):
            self.invoke(override=True, context=replace(
                self.context, approved_risk=RiskLevel.PASSIVE))
        self.assert_unchanged_denial()

    def test_override_cannot_activate_passive_run(self):
        with self.assertRaises(ToolDenied):
            self.invoke(override=True, context=replace(
                self.context, mode=AssessmentMode.PASSIVE_DISCOVERY))
        self.assert_unchanged_denial()

    def test_stop_outweighs_correct_but_out_of_scope_call(self):
        with self.assertRaisesRegex(ToolDenied, "emergency STOP"):
            self.invoke(stop=True, override=True, call=replace(self.call, asset="127.0.0.2"))
        self.assert_unchanged_denial()

    @unittest.expectedFailure
    def test_current_main_foreign_client_lineage_is_expected_red(self):
        # Unfixed main #100: ExecutionRequest lacks tenant fields. Do not turn
        # this canary green by accepting cross-client dispatch as "correct".
        foreign = replace(self.context, client_id="foreign-client")
        with self.assertRaises(ToolDenied):
            self.invoke(override=True, context=foreign)
        self.assert_unchanged_denial()

    @unittest.expectedFailure
    def test_current_main_foreign_engagement_lineage_is_expected_red(self):
        # Source-owner #100 must deny before handler/evidence; opt-in STOP alone
        # cannot repair tenant/engagement binding in unchanged main.
        foreign = replace(self.context, engagement_id="foreign-engagement")
        with self.assertRaises(ToolDenied):
            self.invoke(override=True, context=foreign)
        self.assert_unchanged_denial()


if __name__ == "__main__":
    unittest.main()
