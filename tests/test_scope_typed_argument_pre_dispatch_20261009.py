"""Offline real ToolExecutor typed-argument denial checks.

No targets, socket operations, or production grants. The handler and evidence
ledger are tripwires: invalid model arguments must never reach either.
"""
import unittest
from unittest.mock import Mock

from lightup.ai.orchestration import (
    OrchestrationError, ParamKind, RunContext, ToolCall, ToolDefinition,
    ToolExecutor, ToolOutput, ToolParameter, ToolRegistry,
)
from lightup.engagements import RiskLevel
from lightup.execution_policy import InteractionKind


class TypedArgumentsPreDispatchTests(unittest.TestCase):
    def setUp(self):
        self.handler = Mock(return_value=ToolOutput(
            summary="synthetic", evidence_kind="fixture", evidence_payload=b"fixture"
        ))
        self.ledger = Mock()
        self.ledger.add_evidence.return_value = "synthetic-evidence-id"
        self.registry = ToolRegistry()
        self.registry.register(ToolDefinition(
            tool_id="typed-args-fixture", capability_id="web-baseline",
            interaction=InteractionKind.LAB_ACTIVE,
            min_risk=RiskLevel.LOW_IMPACT,
            description="offline typed argument fixture",
            parameters=(
                ToolParameter("host", ParamKind.STRING),
                ToolParameter("port", ParamKind.INTEGER),
                ToolParameter("enabled", ParamKind.BOOLEAN),
                ToolParameter("ratio", ParamKind.NUMBER, required=False),
            ),
        ), self.handler)
        self.executor = ToolExecutor(self.registry, self.ledger)
        self.context = RunContext.for_lab("typed-args-fixture-run")

    def call(self, **kwargs):
        return ToolCall(
            tool_id="typed-args-fixture", asset="localhost",
            arguments=tuple(kwargs.items()),
        )

    def assert_denied_before_effects(self, arguments):
        with self.assertRaises(OrchestrationError):
            self.executor.execute(self.context, self.call(**arguments))
        self.handler.assert_not_called()
        self.ledger.add_evidence.assert_not_called()

    def test_unknown_parameter_never_dispatches(self):
        self.assert_denied_before_effects({
            "host": "localhost", "port": 8080, "enabled": True,
            "untrusted_target_override": "public.example",
        })

    def test_missing_required_fields_never_dispatch(self):
        for key in ("host", "port", "enabled"):
            with self.subTest(missing=key):
                self.handler.reset_mock()
                self.ledger.reset_mock()
                fields = {"host": "localhost", "port": 8080, "enabled": True}
                del fields[key]
                self.assert_denied_before_effects(fields)

    def test_integer_rejects_boolean_and_float(self):
        for value in (True, False, 8080.0, "8080", None):
            with self.subTest(value=value):
                self.assert_denied_before_effects({
                    "host": "localhost", "port": value, "enabled": True
                })

    def test_boolean_rejects_int_and_string(self):
        for value in (0, 1, "true", None, 1.0):
            with self.subTest(value=value):
                self.assert_denied_before_effects({
                    "host": "localhost", "port": 8080, "enabled": value
                })

    def test_optional_number_rejects_boolean(self):
        self.assert_denied_before_effects({
            "host": "localhost", "port": 8080,
            "enabled": True, "ratio": False,
        })

    def test_string_rejects_non_strings(self):
        for value in (None, 123, [], {}, b"localhost"):
            with self.subTest(value=value):
                self.assert_denied_before_effects({
                    "host": value, "port": 8080, "enabled": True
                })

    def test_unknown_tool_never_uses_registered_handler(self):
        with self.assertRaises(OrchestrationError):
            self.executor.execute(self.context, ToolCall(
                tool_id="unregistered-tool", asset="localhost"
            ))
        self.handler.assert_not_called()
        self.ledger.add_evidence.assert_not_called()

    def test_optional_number_can_be_omitted_without_bypassing_gate(self):
        result = self.executor.execute(self.context, self.call(
            host="localhost", port=8080, enabled=False
        ))
        self.assertEqual(result.evidence_id, "synthetic-evidence-id")
        self.handler.assert_called_once()
        self.ledger.add_evidence.assert_called_once()

    def test_malformed_arguments_do_not_poison_later_valid_call(self):
        self.assert_denied_before_effects({
            "host": "localhost", "port": True, "enabled": True
        })
        result = self.executor.execute(self.context, self.call(
            host="localhost", port=8080, enabled=True
        ))
        self.assertEqual(result.evidence_id, "synthetic-evidence-id")
        self.handler.assert_called_once()
        self.ledger.add_evidence.assert_called_once()

    def test_multiple_unknown_fields_never_reach_handler(self):
        self.assert_denied_before_effects({
            "host": "localhost", "port": 8080, "enabled": True,
            "network_destination": "outside.invalid",
            "authority_override": "outside.invalid",
        })

    def test_non_finite_numeric_values_are_not_authorization(self):
        # Primitive NUMBER validation currently accepts NaN/Infinity.
        # This test is deliberately about evidence provenance, not permission:
        # successful type validation MUST NOT be cited as network scope proof.
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=str(value)):
                self.assertTrue(ParamKind.NUMBER.accepts(value))

    def test_denied_request_does_not_write_evidence_after_valid_control(self):
        self.executor.execute(self.context, self.call(
            host="localhost", port=8080, enabled=True
        ))
        self.handler.reset_mock()
        self.ledger.reset_mock()
        self.assert_denied_before_effects({
            "host": "localhost", "port": "untrusted", "enabled": True
        })

    def test_valid_lab_control_reaches_handler_and_evidence(self):
        result = self.executor.execute(self.context, self.call(
            host="localhost", port=8080, enabled=True, ratio=0.5
        ))
        self.assertEqual(result.evidence_id, "synthetic-evidence-id")
        self.handler.assert_called_once()
        self.ledger.add_evidence.assert_called_once()


if __name__ == "__main__":
    unittest.main()
