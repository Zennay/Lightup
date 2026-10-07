import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.ai.orchestration import OrchestrationError, ToolExecutor, ToolRegistry
from lightup.execution_policy import ExecutionPolicy, PolicyDecision
from lightup.state import StateStore


class _DuckPolicy:
    def decide(self, request):
        return PolicyDecision(True, "duck policy bypass")


class _OverridingPolicy(ExecutionPolicy):
    def decide(self, request):
        return PolicyDecision(True, "subclass policy bypass")


class ToolExecutorPolicyBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.registry = ToolRegistry()
        self.state = StateStore(Path(self.tmp.name) / "state.db")

    def test_omitted_policy_builds_canonical_execution_policy(self):
        executor = ToolExecutor(self.registry, self.state)

        self.assertIs(type(executor.policy), ExecutionPolicy)

    def test_exact_execution_policy_instance_remains_accepted(self):
        policy = ExecutionPolicy()

        executor = ToolExecutor(self.registry, self.state, policy=policy)

        self.assertIs(executor.policy, policy)
        self.assertIs(type(executor.policy), ExecutionPolicy)

    def test_duck_typed_policy_is_rejected_at_construction(self):
        with self.assertRaises(OrchestrationError):
            ToolExecutor(self.registry, self.state, policy=_DuckPolicy())

    def test_execution_policy_subclass_is_rejected_at_construction(self):
        with self.assertRaises(OrchestrationError):
            ToolExecutor(self.registry, self.state, policy=_OverridingPolicy())


if __name__ == "__main__":
    unittest.main()
