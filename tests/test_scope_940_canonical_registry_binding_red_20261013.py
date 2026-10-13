"""#940: exact ToolRegistry identity and immutable ToolExecutor binding.

Runs the real PR #107 executor with local-only synthetic handlers and
disposable SQLite. Five expected failures describe unresolved owner work.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

from lightup.ai.orchestration import (
    OrchestrationError, RunContext, ToolCall, ToolDefinition,
    ToolDenied, ToolExecutor, ToolOutput, ToolRegistry,
)
from lightup.engagements import AssessmentMode, RiskLevel
from lightup.execution_policy import InteractionKind
from lightup.state import StateStore


class DuckRegistry:
    """An untrusted registry which bypasses canonical register validation."""
    def __init__(self, pair):
        self.pair = pair
        self.get_calls = 0

    def get(self, tool_id):
        self.get_calls += 1
        return self.pair


class RegistrySubclass(ToolRegistry):
    """A subclass is not the authorized exact registry instance."""
    def get(self, tool_id):
        return self._untrusted_pair


class RegistryLifetime940(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="lightup-940-")
        self.addCleanup(temporary.cleanup)
        self.state = StateStore(Path(temporary.name) / "state.db")
        self.run_id = self.state.create_run(
            target="synthetic.invalid", activation_mode="plan_only",
        )
        self.original_calls = []
        self.foreign_calls = []
        self.definition = ToolDefinition(
            "offline-identity-940", "external-attack-surface",
            InteractionKind.ANALYSIS, RiskLevel.ANALYSIS_ONLY,
            "inert local no-IO definition",
        )
        self.registry = ToolRegistry()
        self.registry.register(self.definition, self._canonical_handler)
        self.context = RunContext(
            run_id=self.run_id, client_id="offline-client",
            engagement_id="offline-engagement",
            mode=AssessmentMode.ANALYSIS_ONLY,
            approved_risk=RiskLevel.ANALYSIS_ONLY,
            authorization=None, is_lab=False,
            created_at=datetime.now(timezone.utc),
        )
        self.call = ToolCall("offline-identity-940", "synthetic.invalid")

    def _canonical_handler(self, context, arguments):
        self.original_calls.append(context.run_id)
        return ToolOutput("canonical", "test", b"offline-only")

    def _foreign_handler(self, context, arguments):
        self.foreign_calls.append(context.run_id)
        return ToolOutput("foreign", "test", b"foreign-offline")

    def _rows(self):
        with self.state.connect() as con:
            return con.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]

    def _untrusted_pair(self):
        return self.definition, self._foreign_handler

    def _assert_invalid_constructor(self, registry):
        before = self._rows()
        try:
            executor = ToolExecutor(registry, self.state)
            executor.execute(self.context, self.call)
        except (OrchestrationError, ToolDenied, TypeError, AttributeError):
            pass
        else:
            self.fail("noncanonical ToolRegistry was used by executor")
        self.assertEqual(self.foreign_calls, [], "do not call unknown handlers")
        self.assertEqual(self.original_calls, [])
        self.assertEqual(self._rows(), before)

    def _assert_no_postconstruction_replacement(self, action):
        executor = ToolExecutor(self.registry, self.state)
        foreign = DuckRegistry(self._untrusted_pair())
        before = self._rows()
        try:
            action(executor, foreign)
        except (AttributeError, TypeError, KeyError):
            pass
        self.assertIs(executor.registry, self.registry,
                      "constructor-selected registry must remain authoritative")
        self.assertEqual(self.original_calls, [])
        self.assertEqual(self.foreign_calls, [])
        self.assertEqual(self._rows(), before)

    @unittest.expectedFailure  # original PR #107 accepts duck registry
    def test_duck_registry_rejected_at_construction(self):
        self._assert_invalid_constructor(DuckRegistry(self._untrusted_pair()))

    @unittest.expectedFailure  # subclasses may intercept get and bypass admission
    def test_registry_subclass_rejected_at_construction(self):
        subclass = RegistrySubclass()
        subclass._untrusted_pair = self._untrusted_pair()
        self._assert_invalid_constructor(subclass)

    @unittest.expectedFailure  # public executor.registry is mutable on #107
    def test_postconstruction_registry_assignment_rejected(self):
        self._assert_no_postconstruction_replacement(
            lambda executor, foreign: setattr(executor, "registry", foreign)
        )

    @unittest.expectedFailure  # direct object setter must not replace registry
    def test_postconstruction_object_setattr_rejected(self):
        self._assert_no_postconstruction_replacement(
            lambda executor, foreign:
            object.__setattr__(executor, "registry", foreign)
        )

    @unittest.expectedFailure  # direct instance dict must not shadow registry
    def test_postconstruction_instance_dict_shadow_rejected(self):
        self._assert_no_postconstruction_replacement(
            lambda executor, foreign:
            vars(executor).__setitem__("registry", foreign)
        )

    def test_canonical_registry_inert_analysis_control(self):
        executor = ToolExecutor(self.registry, self.state)
        result = executor.execute(self.context, self.call)
        self.assertEqual(result.run_id, self.run_id)
        self.assertEqual(self.original_calls, [self.run_id])
        self.assertEqual(self.foreign_calls, [])
        self.assertEqual(self._rows(), 1)

    def test_missing_evidence_ledger_rejected_by_existing_constructor(self):
        with self.assertRaises(OrchestrationError):
            ToolExecutor(self.registry, None)
        self.assertEqual(self.original_calls, [])
        self.assertEqual(self._rows(), 0)

    def test_unknown_registry_tool_rejected_before_any_effect(self):
        executor = ToolExecutor(self.registry, self.state)
        with self.assertRaises(OrchestrationError):
            executor.execute(self.context, ToolCall("not-registered-940", "synthetic.invalid"))
        self.assertEqual(self.original_calls, [])
        self.assertEqual(self._rows(), 0)

    def test_passive_context_denies_active_registry_tool(self):
        self.registry.register(
            ToolDefinition(
                "fake-active-940", "network-services",
                InteractionKind.TARGET_ACTIVE, RiskLevel.LOW_IMPACT,
                "inert only",
            ),
            self._foreign_handler,
        )
        context = RunContext(
            run_id=self.run_id, client_id="offline-client",
            engagement_id="offline-engagement",
            mode=AssessmentMode.PASSIVE_DISCOVERY,
            approved_risk=RiskLevel.PASSIVE,
            authorization=None, is_lab=False,
            created_at=datetime.now(timezone.utc),
        )
        with self.assertRaises(ToolDenied):
            ToolExecutor(self.registry, self.state).execute(
                context, ToolCall("fake-active-940", "synthetic.invalid")
            )
        self.assertEqual(self.foreign_calls, [])
        self.assertEqual(self._rows(), 0)


if __name__ == "__main__":
    unittest.main()
