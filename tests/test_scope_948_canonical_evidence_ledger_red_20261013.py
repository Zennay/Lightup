"""Issue #948: execution evidence ledger must be exact and construction-bound.

Real PR #107 ToolExecutor, local-only ANALYSIS tool handler, disposable SQLite.
Intentional expected failures are security acceptance debt, NOT implementation.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

from lightup.ai.orchestration import (
    RunContext, ToolCall, ToolDefinition, ToolExecutor, ToolOutput, ToolRegistry,
    OrchestrationError, ToolDenied,
)
from lightup.engagements import AssessmentMode, RiskLevel
from lightup.execution_policy import InteractionKind
from lightup.state import StateStore


class ForgingLedger:
    def __init__(self):
        self.writes = []

    def add_evidence(self, **kwargs):
        self.writes.append(kwargs)
        return "forge-not-persisted"


class ForgingLedgerSubclass(StateStore):
    def add_evidence(self, **kwargs):
        return "forge-not-persisted"


class EvidenceLedgerIntegrity948(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="lightup-scope-948-")
        self.addCleanup(temporary.cleanup)
        self.state = StateStore(Path(temporary.name) / "authentic.sqlite")
        self.run_id = self.state.create_run(
            target="synthetic.invalid", activation_mode="plan_only"
        )
        self.registry = ToolRegistry()
        self.invoked = []
        self.registry.register(
            ToolDefinition(
                tool_id="synthetic-analysis-ledger-948",
                capability_id="network-services",
                interaction=InteractionKind.ANALYSIS,
                min_risk=RiskLevel.ANALYSIS_ONLY,
                description="inert no-I/O synthetic handler",
            ),
            self._handler,
        )
        self.context = RunContext(
            run_id=self.run_id, client_id="synthetic-client",
            engagement_id="synthetic-engagement",
            mode=AssessmentMode.ANALYSIS_ONLY,
            approved_risk=RiskLevel.ANALYSIS_ONLY,
            authorization=None, is_lab=False,
            created_at=datetime.now(timezone.utc),
        )
        self.call = ToolCall("synthetic-analysis-ledger-948", "synthetic.invalid")

    def _handler(self, context, args):
        self.invoked.append(context.run_id)
        return ToolOutput("offline only", "synthetic", b"offline only")

    def _rows(self):
        with self.state.connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]

    def _reject_constructor(self, fake):
        before = self._rows()
        try:
            exe = ToolExecutor(self.registry, fake)
            exe.execute(self.context, self.call)
        except (OrchestrationError, ToolDenied, TypeError, AttributeError):
            pass
        else:
            self.fail("noncanonical evidence ledger accepted and executed")
        self.assertEqual(self.invoked, [], "untrusted ledger must deny before handler")
        self.assertEqual(self._rows(), before)

    @unittest.expectedFailure  # noncanonical duck accepted on original PR #107
    def test_duck_ledger_rejected_before_dispatch(self):
        self._reject_constructor(ForgingLedger())

    @unittest.expectedFailure  # subclass can suppress persistence
    def test_ledger_subclass_rejected_before_dispatch(self):
        with tempfile.TemporaryDirectory(prefix="lightup-948-alt-") as folder:
            fake = ForgingLedgerSubclass(Path(folder) / "forgery.sqlite")
            self._reject_constructor(fake)

    @unittest.expectedFailure  # public ledger binding can be replaced
    def test_direct_assignment_cannot_swap_canonical_ledger(self):
        self._reject_rebinding(lambda exe, forged: setattr(exe, "state", forged))

    @unittest.expectedFailure  # object setattr cannot shadow evidence source
    def test_object_setattr_cannot_swap_canonical_ledger(self):
        self._reject_rebinding(
            lambda exe, forged: object.__setattr__(exe, "state", forged)
        )

    @unittest.expectedFailure  # mutable instance dict can shadow ledger
    def test_instance_dict_cannot_swap_canonical_ledger(self):
        self._reject_rebinding(
            lambda exe, forged: vars(exe).__setitem__("state", forged)
        )

    @unittest.expectedFailure  # deleting binding must not lose trusted ledger
    def test_deletion_cannot_remove_canonical_ledger(self):
        self._reject_rebinding(lambda exe, forged: delattr(exe, "state"))

    def _reject_rebinding(self, mutation):
        exe = ToolExecutor(self.registry, self.state)
        before = self._rows()
        try:
            mutation(exe, ForgingLedger())
        except (AttributeError, TypeError, KeyError):
            pass
        self.assertIs(exe.state, self.state,
                      "constructor-selected evidence ledger must remain bound")
        self.assertEqual(self.invoked, [])
        self.assertEqual(self._rows(), before)

    def test_canonical_ledger_persists_real_evidence(self):
        result = ToolExecutor(self.registry, self.state).execute(
            self.context, self.call
        )
        self.assertEqual(self.invoked, [self.run_id])
        self.assertEqual(self._rows(), 1)
        row = self.state.get_evidence(result.evidence_id)
        self.assertEqual(row.run_id, self.run_id)
        self.assertEqual(row.source, "synthetic-analysis-ledger-948")

    def test_none_ledger_denied_before_handler(self):
        with self.assertRaises(OrchestrationError):
            ToolExecutor(self.registry, None)
        self.assertEqual(self.invoked, [])
        self.assertEqual(self._rows(), 0)

    def test_missing_run_foreign_key_cannot_persist_evidence(self):
        other_context = RunContext(
            run_id="missing-synthetic-run-948", client_id="synthetic-client",
            engagement_id="synthetic-engagement",
            mode=AssessmentMode.ANALYSIS_ONLY,
            approved_risk=RiskLevel.ANALYSIS_ONLY,
            authorization=None, is_lab=False,
            created_at=datetime.now(timezone.utc),
        )
        import sqlite3
        with self.assertRaises(sqlite3.IntegrityError):
            ToolExecutor(self.registry, self.state).execute(other_context, self.call)
        self.assertEqual(self._rows(), 0)

    def test_no_execution_on_unregistered_tool(self):
        with self.assertRaises(OrchestrationError):
            ToolExecutor(self.registry, self.state).execute(
                self.context, ToolCall("unknown-synthetic-948", "synthetic.invalid")
            )
        self.assertEqual(self.invoked, [])
        self.assertEqual(self._rows(), 0)


if __name__ == "__main__":
    unittest.main()
