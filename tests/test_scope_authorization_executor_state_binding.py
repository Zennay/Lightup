from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from lightup.ai.orchestration import (
    OrchestrationError,
    RunContext,
    ToolCall,
    ToolDefinition,
    ToolExecutor,
    ToolOutput,
    ToolRegistry,
)
from lightup.engagements import AssessmentMode, RiskLevel
from lightup.execution_policy import InteractionKind
from lightup.state import StateStore


class _DuckState:
    def __init__(self):
        self.added = []

    def add_evidence(self, **kwargs):
        self.added.append(kwargs)
        return "forged-evidence-id"


class _StateStoreSubclass(StateStore):
    pass


class ToolExecutorEvidenceLedgerBindingTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = StateStore(Path(self.tmp.name) / "state.db")
        self.registry = ToolRegistry()
        self.handler_calls = []
        self.registry.register(
            ToolDefinition(
                "public-records",
                "external-attack-surface",
                InteractionKind.PASSIVE_PUBLIC,
                RiskLevel.PASSIVE,
                "Public records lookup",
            ),
            self._handler,
        )

    def _handler(self, context, arguments):
        self.handler_calls.append(context.run_id)
        return ToolOutput("ok", "note", b"canonical-evidence")

    def _context(self):
        run_id = self.state.create_run(
            "example.test",
            activation_mode=AssessmentMode.PASSIVE_DISCOVERY.value,
        )
        return RunContext(
            run_id=run_id,
            client_id="client-1",
            engagement_id="engagement-1",
            mode=AssessmentMode.PASSIVE_DISCOVERY,
            approved_risk=RiskLevel.PASSIVE,
            authorization=None,
            is_lab=False,
            created_at=datetime.now(timezone.utc),
        )

    def test_exact_state_store_is_accepted_and_receives_evidence(self):
        executor = ToolExecutor(self.registry, self.state)
        context = self._context()

        result = executor.execute(
            context,
            ToolCall("public-records", "example.test"),
        )

        stored = self.state.get_evidence(result.evidence_id)
        self.assertEqual(stored.run_id, context.run_id)
        self.assertEqual(stored.capability_id, "external-attack-surface")
        self.assertEqual(self.handler_calls, [context.run_id])

    def test_duck_ledger_is_rejected_at_construction(self):
        duck = _DuckState()

        with self.assertRaisesRegex(
            OrchestrationError,
            "evidence ledger must be an exact StateStore",
        ):
            ToolExecutor(self.registry, duck)

        self.assertEqual(self.handler_calls, [])
        self.assertEqual(duck.added, [])

    def test_state_store_subclass_is_rejected_at_construction(self):
        subclass = _StateStoreSubclass(Path(self.tmp.name) / "subclass.db")

        with self.assertRaisesRegex(
            OrchestrationError,
            "evidence ledger must be an exact StateStore",
        ):
            ToolExecutor(self.registry, subclass)

        self.assertEqual(self.handler_calls, [])

    def test_bound_evidence_ledger_cannot_be_replaced_after_construction(self):
        executor = ToolExecutor(self.registry, self.state)
        replacement = _DuckState()

        with self.assertRaises((AttributeError, OrchestrationError)):
            executor.state = replacement

        self.assertIs(executor.state, self.state)
        self.assertEqual(replacement.added, [])
        self.assertEqual(self.handler_calls, [])


if __name__ == "__main__":
    unittest.main()
