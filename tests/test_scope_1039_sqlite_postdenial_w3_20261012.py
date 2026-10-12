"""W3: durable evidence non-mutation after an opt-in emergency STOP (synthetic).

This tests in-process SQLite and inert callbacks only. STOP is a caller-provided
bool, not a persisted control or proof of pre-I/O revocation in real workers.
"""
from __future__ import annotations

import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from lightup.ai.orchestration import (
    RunContext, ToolCall, ToolDefinition, ToolDenied, ToolExecutor, ToolOutput, ToolRegistry,
)
from lightup.emergency_dispatch_optin import execute_with_emergency_gate
from lightup.engagements import AssessmentMode, AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.execution_policy import ExecutionPolicy, InteractionKind
from lightup.state import StateStore


class EmergencyStopSQLitePostDenialW3(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = StateStore(Path(self.tmp.name) / "synthetic.db")
        self.run_id = self.store.create_run("127.0.0.1")
        self.handler = Mock(return_value=ToolOutput(
            summary="fixture only", evidence_kind="offline", evidence_payload=b"redacted fixture",
        ))
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                tool_id="offline-only", capability_id="web-baseline",
                interaction=InteractionKind.TARGET_ACTIVE,
                min_risk=RiskLevel.STANDARD,
                description="mock callback only, never real network I/O",
            ),
            self.handler,
        )
        self.executor = ToolExecutor(registry, self.store, ExecutionPolicy())
        now = datetime.now(timezone.utc)
        grant = AuthorizationGrant(
            grant_id="fixture-not-real", client_id="fixture-client",
            engagement_id="fixture-engagement", approved_by="fixture",
            reference="SYNTHETIC-ONLY",
            scope=ScopeDefinition(
                assets=("127.0.0.1",),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=("web-baseline",),
            ),
            valid_from=now - timedelta(minutes=1),
            valid_until=now + timedelta(minutes=10),
        )
        self.context = RunContext(
            run_id=self.run_id, client_id="fixture-client",
            engagement_id="fixture-engagement",
            mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
            approved_risk=RiskLevel.STANDARD,
            authorization=grant,
            is_lab=False, created_at=now,
        )
        self.call = ToolCall(tool_id="offline-only", asset="127.0.0.1")

    def execute(self, *, stop, override=False, context=None, call=None):
        return execute_with_emergency_gate(
            self.executor,
            self.context if context is None else context,
            self.call if call is None else call,
            stop_active=stop,
            override_requested=override,
        )

    def snapshot(self):
        with self.store.connect() as con:
            return (
                tuple(tuple(row) for row in con.execute(
                    "SELECT evidence_id,run_id,capability_id,kind,source,sha256,"
                    "metadata_json,created_at FROM evidence ORDER BY evidence_id")),
                tuple(tuple(row) for row in con.execute(
                    "SELECT run_id,target,authorization_ref,activation_mode,status,created_at "
                    "FROM runs ORDER BY run_id")),
                tuple(tuple(row) for row in con.execute(
                    "SELECT run_id,capability_id,worker_id,expires_at "
                    "FROM capability_leases ORDER BY run_id,capability_id")),
            )

    def baseline(self):
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            result = self.execute(stop=False)
        self.assertTrue(result.evidence_id)
        self.assertEqual(len(self.snapshot()[0]), 1)
        self.handler.assert_called_once()
        return self.snapshot()

    def test_stop_after_one_valid_synthetic_write_preserves_all_tables(self):
        before = self.baseline()
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            with self.assertRaisesRegex(ToolDenied, "emergency STOP"):
                self.execute(stop=True, override=True)
        self.assertEqual(self.snapshot(), before)
        self.handler.assert_called_once()

    def test_malformed_override_after_synthetic_write_never_changes_store(self):
        before = self.baseline()
        class Trap:
            def __bool__(self):
                raise AssertionError("do not coerce override")
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            with self.assertRaises(ToolDenied):
                self.execute(stop=False, override=Trap())
        self.assertEqual(self.snapshot(), before)
        self.handler.assert_called_once()

    def test_stop_before_missing_registry_tool_no_data_written(self):
        before = self.snapshot()
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            with self.assertRaisesRegex(ToolDenied, "emergency STOP"):
                self.execute(stop=True, call=ToolCall("unregistered-tool", "127.0.0.1"))
        self.assertEqual(self.snapshot(), before)
        self.handler.assert_not_called()

    def test_stop_before_malformed_context_is_ever_read(self):
        before = self.snapshot()
        class BadContext:
            def __getattribute__(self, attr):
                raise AssertionError("never read attacker-controlled context")
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            with self.assertRaisesRegex(ToolDenied, "emergency STOP"):
                self.execute(stop=True, context=BadContext(), call=BadContext())
        self.assertEqual(self.snapshot(), before)
        self.handler.assert_not_called()

    def test_stop_cannot_format_secret_from_malformed_override(self):
        before = self.snapshot()
        class Secret:
            def __repr__(self):
                raise AssertionError("secret repr must never be logged")
            def __bool__(self):
                raise AssertionError("secret bool must never be coerced")
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            with self.assertRaisesRegex(ToolDenied, "emergency STOP"):
                self.execute(stop=True, override=Secret())
        self.assertEqual(self.snapshot(), before)
        self.handler.assert_not_called()

    def test_parallel_stopped_calls_leave_preexisting_evidence_unchanged(self):
        before = self.baseline()
        def denied(i):
            try:
                self.execute(stop=True, override=bool(i % 2))
            except ToolDenied:
                return True
            return False
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            with ThreadPoolExecutor(max_workers=4) as pool:
                results = list(pool.map(denied, range(32)))
        self.assertEqual(results, [True] * 32)
        self.assertEqual(self.snapshot(), before)
        self.handler.assert_called_once()


if __name__ == "__main__":
    unittest.main()
