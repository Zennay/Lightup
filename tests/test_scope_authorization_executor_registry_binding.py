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
    ToolDenied,
    ToolExecutor,
    ToolOutput,
    ToolRegistry,
)
from lightup.engagements import AssessmentMode, RiskLevel
from lightup.execution_policy import InteractionKind
from lightup.state import StateStore


class _DuckRegistry:
    def get(self, tool_id):
        return (
            ToolDefinition(
                tool_id,
                "network-services",
                InteractionKind.ANALYSIS,
                RiskLevel.ANALYSIS_ONLY,
                "duck registry definition",
            ),
            lambda context, arguments: ToolOutput("duck", "test", b"duck"),
        )


class _RegistrySubclass(ToolRegistry):
    pass


class ToolExecutorRegistryBindingTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = StateStore(Path(self.tmp.name) / "state.db")

    def context(self) -> RunContext:
        return RunContext(
            run_id="run-registry-binding",
            client_id="client-1",
            engagement_id="engagement-1",
            mode=AssessmentMode.ANALYSIS_ONLY,
            approved_risk=RiskLevel.ANALYSIS_ONLY,
            authorization=None,
            is_lab=False,
            created_at=datetime.now(timezone.utc),
        )

    def test_exact_tool_registry_remains_accepted(self):
        registry = ToolRegistry()

        executor = ToolExecutor(registry, self.state)

        self.assertIs(executor.registry, registry)
        self.assertIs(type(executor.registry), ToolRegistry)

    def test_duck_registry_is_rejected_at_construction(self):
        with self.assertRaises(OrchestrationError):
            ToolExecutor(_DuckRegistry(), self.state)

    def test_tool_registry_subclass_is_rejected_at_construction(self):
        with self.assertRaises(OrchestrationError):
            ToolExecutor(_RegistrySubclass(), self.state)

    def test_registry_binding_rejects_post_construction_replacement(self):
        executor = ToolExecutor(ToolRegistry(), self.state)

        with self.assertRaises((AttributeError, TypeError)):
            executor.registry = ToolRegistry()

    def test_registry_replacement_cannot_reclassify_active_handler_as_analysis(self):
        calls: list[str] = []
        original = ToolRegistry()
        original.register(
            ToolDefinition(
                "registry-binding-probe",
                "network-services",
                InteractionKind.TARGET_ACTIVE,
                RiskLevel.STANDARD,
                "target-active definition",
            ),
            lambda context, arguments: (
                calls.append("original")
                or ToolOutput("original", "test", b"original")
            ),
        )
        replacement = ToolRegistry()
        replacement.register(
            ToolDefinition(
                "registry-binding-probe",
                "network-services",
                InteractionKind.ANALYSIS,
                RiskLevel.ANALYSIS_ONLY,
                "reclassified analysis definition",
            ),
            lambda context, arguments: (
                calls.append("replacement")
                or ToolOutput("replacement", "test", b"replacement")
            ),
        )
        executor = ToolExecutor(original, self.state)

        with self.assertRaises(ToolDenied):
            executor.execute(
                self.context(),
                ToolCall("registry-binding-probe", "offline.test"),
            )
        self.assertEqual(calls, [])

        try:
            executor.registry = replacement
        except (AttributeError, TypeError):
            pass

        with self.assertRaises(ToolDenied):
            executor.execute(
                self.context(),
                ToolCall("registry-binding-probe", "offline.test"),
            )

        self.assertEqual(calls, [])
        with self.state.connect() as connection:
            evidence_count = connection.execute(
                "SELECT COUNT(*) FROM evidence WHERE run_id=?",
                ("run-registry-binding",),
            ).fetchone()[0]
        self.assertEqual(evidence_count, 0)


if __name__ == "__main__":
    unittest.main()
