"""Issue #1095: actual ToolExecutor typed-value admission (offline, intentionally RED).

Only synthetic ANALYSIS_ONLY calls and disposable SQLite. No real target, network,
authorization issuance or original registry/source modifications. The expected
failures characterize current gaps; they are NOT passing security guarantees.
"""
from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from enum import IntEnum
from itertools import permutations
from pathlib import Path
from uuid import uuid4

from lightup.ai.orchestration import (
    OrchestrationError, ParamKind, RunContext, ToolCall, ToolDefinition,
    ToolExecutor, ToolOutput, ToolParameter, ToolRegistry,
)
from lightup.engagements import AssessmentMode, RiskLevel
from lightup.execution_policy import InteractionKind
from lightup.state import StateStore


class SubclassText(str):
    pass


class SubclassInt(int):
    pass


class SubclassFloat(float):
    pass


class NumericEnum(IntEnum):
    ONE = 1


class CallbackString(str):
    """Synthetic attacker-controlled subtype, local observation only."""

    def __new__(cls, text, hits):
        value = super().__new__(cls, text)
        value.hits = hits
        return value

    def __str__(self):
        self.hits.append("callback-in-handler")
        return super().__str__()


class PretendInteger:
    def __int__(self):
        raise AssertionError("type admission must never coerce values")


class PrimitiveAdmissibilityTests(unittest.TestCase):
    def test_exact_builtin_positive_controls(self):
        for kind, values in (
            (ParamKind.STRING, ("safe", "")),
            (ParamKind.INTEGER, (0, -1, 12)),
            (ParamKind.NUMBER, (0, -3, 1.25, 0.0)),
            (ParamKind.BOOLEAN, (True, False)),
        ):
            for value in values:
                with self.subTest(kind=kind.value, value=repr(value)):
                    self.assertTrue(kind.accepts(value))

    def test_unrelated_builtin_types_rejected(self):
        for kind, values in (
            (ParamKind.STRING, (None, 1, b"text", True, [])),
            (ParamKind.INTEGER, (None, True, False, 1.0, "1")),
            (ParamKind.NUMBER, (None, True, False, "1", 1j)),
            (ParamKind.BOOLEAN, (None, 0, 1, "true")),
        ):
            for value in values:
                with self.subTest(kind=kind.value, value=repr(value)):
                    self.assertFalse(kind.accepts(value))

    def test_fake_numeric_protocol_does_not_invoke_conversion(self):
        self.assertFalse(ParamKind.INTEGER.accepts(PretendInteger()))
        self.assertFalse(ParamKind.NUMBER.accepts(PretendInteger()))

    @unittest.expectedFailure
    def test_red_string_subclass_rejected(self):
        self.assertFalse(ParamKind.STRING.accepts(SubclassText("safe")))

    @unittest.expectedFailure
    def test_red_integer_subclass_rejected(self):
        self.assertFalse(ParamKind.INTEGER.accepts(SubclassInt(3)))

    @unittest.expectedFailure
    def test_red_integer_enum_rejected(self):
        self.assertFalse(ParamKind.INTEGER.accepts(NumericEnum.ONE))

    @unittest.expectedFailure
    def test_red_number_integer_subclass_rejected(self):
        self.assertFalse(ParamKind.NUMBER.accepts(SubclassInt(3)))

    @unittest.expectedFailure
    def test_red_number_float_subclass_rejected(self):
        self.assertFalse(ParamKind.NUMBER.accepts(SubclassFloat(1.25)))

    @unittest.expectedFailure
    def test_red_number_enum_rejected(self):
        self.assertFalse(ParamKind.NUMBER.accepts(NumericEnum.ONE))

    @unittest.expectedFailure
    def test_red_definition_must_refuse_polymorphic_text(self):
        definition = ToolDefinition(
            "synthetic-text", "external-attack-surface",
            InteractionKind.ANALYSIS, RiskLevel.ANALYSIS_ONLY, "offline",
            (ToolParameter("value", ParamKind.STRING),),
        )
        with self.assertRaises(OrchestrationError):
            definition.validate_arguments({"value": SubclassText("safe")})


class ActualExecutorAdmissionTests(unittest.TestCase):
    """No mocked executor or handler bypass: real policy and real SQLite ledger."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = StateStore(Path(self.temp.name) / "scope-1095.db")
        self.handler_calls = []
        self.registry = ToolRegistry()
        for name, kind in (
            ("text", ParamKind.STRING),
            ("integer", ParamKind.INTEGER),
            ("number", ParamKind.NUMBER),
            ("boolean", ParamKind.BOOLEAN),
        ):
            self.registry.register(
                ToolDefinition(
                    "synthetic-" + name, "external-attack-surface",
                    InteractionKind.ANALYSIS, RiskLevel.ANALYSIS_ONLY,
                    "Synthetic analysis-only primitive gate",
                    (ToolParameter("value", kind),),
                ),
                self._handler,
            )
        self.registry.register(
            ToolDefinition(
                "synthetic-mixed-values", "external-attack-surface",
                InteractionKind.ANALYSIS, RiskLevel.ANALYSIS_ONLY,
                "Offline multi-field primitive type admission only",
                (
                    ToolParameter("label", ParamKind.STRING),
                    ToolParameter("count", ParamKind.INTEGER),
                    ToolParameter("measure", ParamKind.NUMBER),
                    ToolParameter("enabled", ParamKind.BOOLEAN),
                ),
            ),
            self._handler,
        )
        self.registry.register(
            ToolDefinition(
                "synthetic-string-format", "external-attack-surface",
                InteractionKind.ANALYSIS, RiskLevel.ANALYSIS_ONLY,
                "Locally render a synthetic string to expose subtype callback",
                (ToolParameter("value", ParamKind.STRING),),
            ),
            self._rendering_handler,
        )
        self.executor = ToolExecutor(self.registry, self.state)
        self.context = RunContext(
            run_id=str(uuid4()), client_id="offline-tenant",
            engagement_id="offline-engagement",
            mode=AssessmentMode.ANALYSIS_ONLY,
            approved_risk=RiskLevel.ANALYSIS_ONLY,
            authorization=None, is_lab=False,
            created_at=datetime.now(timezone.utc),
        )

    def _handler(self, context, arguments):
        self.handler_calls.append(dict(arguments))
        return ToolOutput("offline shape control", "synthetic", b"no target data")

    def _rendering_handler(self, context, arguments):
        # This is a deliberately side-effect-observable offline synthetic
        # handler, not a network or target-facing real tool.
        str(arguments["value"])
        self.handler_calls.append(dict(arguments))
        return ToolOutput("offline formatting control", "synthetic", b"no target")

    def _evidence_count(self):
        with self.state.connect() as con:
            return con.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]

    def _execute(self, primitive, value):
        return self.executor.execute(
            self.context,
            ToolCall("synthetic-" + primitive, "synthetic.invalid",
                     arguments=(("value", value),)),
        )

    def _assert_rejected_without_effects(self, primitive, value):
        before_calls = len(self.handler_calls)
        before_rows = self._evidence_count()
        denied = False
        try:
            self._execute(primitive, value)
        except OrchestrationError:
            denied = True
        self.assertEqual(len(self.handler_calls), before_calls,
                         "typed rejection must happen BEFORE handler invocation")
        self.assertEqual(self._evidence_count(), before_rows,
                         "typed rejection must leave durable evidence unchanged")
        self.assertTrue(denied, "invalid input must raise OrchestrationError")

    def test_all_exact_primitive_types_reach_synthetic_analysis_handler(self):
        for primitive, value in (
            ("text", "safe"), ("integer", 3),
            ("number", -2), ("number", 1.5),
            ("boolean", False),
        ):
            with self.subTest(primitive=primitive, value=repr(value)):
                before = self._evidence_count()
                self._execute(primitive, value)
                self.assertEqual(self._evidence_count(), before + 1)
        self.assertEqual(len(self.handler_calls), 5)

    def test_canonical_mismatch_is_rejected_without_handler_or_evidence(self):
        for primitive, value in (
            ("text", 42), ("integer", True), ("integer", 1.5),
            ("number", False), ("number", "1.5"), ("boolean", 0),
        ):
            with self.subTest(primitive=primitive, value=repr(value)):
                self._assert_rejected_without_effects(primitive, value)

    def test_numeric_protocol_objects_are_never_coerced(self):
        self._assert_rejected_without_effects("integer", PretendInteger())
        self._assert_rejected_without_effects("number", PretendInteger())

    def _execute_mixed(self, arguments):
        return self.executor.execute(
            self.context,
            ToolCall("synthetic-mixed-values", "synthetic.invalid",
                     arguments=tuple(arguments.items())),
        )

    def _assert_mixed_rejected_without_effects(self, arguments):
        before_calls = len(self.handler_calls)
        before_rows = self._evidence_count()
        denied = False
        try:
            self._execute_mixed(arguments)
        except OrchestrationError:
            denied = True
        self.assertEqual(len(self.handler_calls), before_calls,
                         "bad late typed field must not invoke the mixed handler")
        self.assertEqual(self._evidence_count(), before_rows,
                         "mixed malformed arguments must not persist partial evidence")
        self.assertTrue(denied, "mixed malformed value must raise OrchestrationError")

    @staticmethod
    def _permuted_mixed_payloads(overrides=None):
        """All 24 four-field orders; no randomness or external input."""
        fields = {
            "label": "synthetic", "count": 2, "measure": 1.25,
            "enabled": False,
        }
        if overrides:
            fields.update(overrides)
        for ordered in permutations(tuple(fields.items())):
            yield dict(ordered)

    def test_all_24_mixed_builtin_key_orders_dispatch_only_canonical_values(self):
        initial_rows = self._evidence_count()
        initial_calls = len(self.handler_calls)
        for payload in self._permuted_mixed_payloads():
            with self.subTest(keys=tuple(payload)):
                self._execute_mixed(payload)
                self.assertEqual(self.handler_calls[-1], payload)
        self.assertEqual(len(self.handler_calls) - initial_calls, 24)
        self.assertEqual(self._evidence_count() - initial_rows, 24)

    def test_all_24_orders_refuse_each_canonical_mismatch_before_any_effect(self):
        # False is a builtin bool, but NOT an INTEGER or NUMBER.
        for field, invalid in (
            ("label", 3),
            ("count", False),
            ("measure", "1.25"),
            ("enabled", 1),
        ):
            for payload in self._permuted_mixed_payloads({field: invalid}):
                with self.subTest(field=field, keys=tuple(payload)):
                    self._assert_mixed_rejected_without_effects(payload)
        self.assertEqual(len(self.handler_calls), 0)
        self.assertEqual(self._evidence_count(), 0)

    def _assert_polymorphic_rejected_in_all_24_orders(self, field, value):
        forbidden_dispatches = []
        initial_calls = len(self.handler_calls)
        initial_rows = self._evidence_count()
        for payload in self._permuted_mixed_payloads({field: value}):
            try:
                self._execute_mixed(payload)
            except OrchestrationError:
                pass
            else:
                forbidden_dispatches.append(tuple(payload))
        self.assertEqual(
            forbidden_dispatches, [],
            "noncanonical subtype must be rejected for ALL input field orders",
        )
        self.assertEqual(len(self.handler_calls), initial_calls)
        self.assertEqual(self._evidence_count(), initial_rows)

    @unittest.expectedFailure
    def test_red_all_24_orders_reject_polymorphic_string(self):
        self._assert_polymorphic_rejected_in_all_24_orders(
            "label", SubclassText("synthetic")
        )

    @unittest.expectedFailure
    def test_red_all_24_orders_reject_polymorphic_integer_enum(self):
        self._assert_polymorphic_rejected_in_all_24_orders(
            "count", NumericEnum.ONE
        )

    @unittest.expectedFailure
    def test_red_all_24_orders_reject_polymorphic_float(self):
        self._assert_polymorphic_rejected_in_all_24_orders(
            "measure", SubclassFloat(1.25)
        )

    def test_mixed_builtin_primitive_values_dispatch_once(self):
        before = self._evidence_count()
        self._execute_mixed({
            "label": "synthetic", "count": 2, "measure": 1.25,
            "enabled": False,
        })
        self.assertEqual(self._evidence_count(), before + 1)
        self.assertEqual(self.handler_calls[-1], {
            "label": "synthetic", "count": 2, "measure": 1.25,
            "enabled": False,
        })

    def test_mixed_late_canonical_mismatch_denies_atomically(self):
        self._assert_mixed_rejected_without_effects({
            "label": "synthetic", "count": 2, "measure": "not-a-number",
            "enabled": False,
        })
        self._assert_mixed_rejected_without_effects({
            "label": "synthetic", "count": 2, "measure": 1.25,
            "enabled": "false",
        })

    @unittest.expectedFailure
    def test_red_mixed_text_subclass_before_valid_fields_must_deny(self):
        self._assert_mixed_rejected_without_effects({
            "label": SubclassText("synthetic"), "count": 2,
            "measure": 1.25, "enabled": False,
        })

    @unittest.expectedFailure
    def test_red_mixed_enum_after_valid_text_must_deny(self):
        self._assert_mixed_rejected_without_effects({
            "label": "synthetic", "count": NumericEnum.ONE,
            "measure": 1.25, "enabled": False,
        })

    @unittest.expectedFailure
    def test_red_mixed_float_subclass_after_valid_prefix_must_deny(self):
        self._assert_mixed_rejected_without_effects({
            "label": "synthetic", "count": 2,
            "measure": SubclassFloat(1.25), "enabled": False,
        })

    @unittest.expectedFailure
    def test_red_mixed_after_prior_valid_dispatch_preserves_previous_evidence(self):
        self._execute_mixed({
            "label": "synthetic", "count": 2, "measure": 1.25,
            "enabled": False,
        })
        self.assertEqual(len(self.handler_calls), 1)
        self.assertEqual(self._evidence_count(), 1)
        self._assert_mixed_rejected_without_effects({
            "label": "synthetic", "count": 2,
            "measure": SubclassFloat(1.25), "enabled": False,
        })

    def test_exact_builtin_string_renders_in_synthetic_handler(self):
        before = self._evidence_count()
        self.executor.execute(
            self.context,
            ToolCall("synthetic-string-format", "synthetic.invalid",
                     arguments=(("value", "safe"),)),
        )
        self.assertEqual(self.handler_calls[-1], {"value": "safe"})
        self.assertEqual(self._evidence_count(), before + 1)

    @unittest.expectedFailure
    def test_red_subclass_string_callback_must_never_reach_rendering_handler(self):
        hits = []
        forged_text = CallbackString("synthetic", hits)
        before_calls = len(self.handler_calls)
        before_rows = self._evidence_count()
        denied = False
        try:
            self.executor.execute(
                self.context,
                ToolCall("synthetic-string-format", "synthetic.invalid",
                         arguments=(("value", forged_text),)),
            )
        except OrchestrationError:
            denied = True
        self.assertEqual(hits, [], "caller subtype __str__ executed in synthetic handler")
        self.assertEqual(len(self.handler_calls), before_calls,
                         "invalid string must never invoke handler")
        self.assertEqual(self._evidence_count(), before_rows,
                         "invalid subtype must not write evidence")
        self.assertTrue(denied, "invalid string subclass must be refused")

    @unittest.expectedFailure
    def test_red_real_executor_string_subclass_must_have_zero_effects(self):
        self._assert_rejected_without_effects("text", SubclassText("safe"))

    @unittest.expectedFailure
    def test_red_real_executor_int_subclass_must_have_zero_effects(self):
        self._assert_rejected_without_effects("integer", SubclassInt(3))

    @unittest.expectedFailure
    def test_red_real_executor_intenum_must_have_zero_effects(self):
        self._assert_rejected_without_effects("integer", NumericEnum.ONE)

    @unittest.expectedFailure
    def test_red_real_executor_number_float_subclass_must_have_zero_effects(self):
        self._assert_rejected_without_effects("number", SubclassFloat(1.25))

    @unittest.expectedFailure
    def test_red_real_executor_number_int_subclass_must_have_zero_effects(self):
        self._assert_rejected_without_effects("number", SubclassInt(3))

    @unittest.expectedFailure
    def test_red_real_executor_number_enum_must_have_zero_effects(self):
        self._assert_rejected_without_effects("number", NumericEnum.ONE)

    @unittest.expectedFailure
    def test_red_polymorphic_input_after_valid_call_keeps_ledger_unchanged(self):
        self._execute("text", "safe")
        self.assertEqual(self._evidence_count(), 1)
        self._assert_rejected_without_effects("text", SubclassText("unsafe"))


class ExpectedRedWitnessIntegrityTests(unittest.TestCase):
    """Avoid false confidence: unittest.expectedFailure also masks crashes.

    Re-run ONLY the RED witness methods in a private unittest result and
    distinguish intentional security assertion failures from arbitrary
    exceptions; never invoke a target, network, scan, grant or real handler.
    """

    @staticmethod
    def _unexpected_red_outcomes(result, expected_count):
        problems = []
        if result.testsRun != expected_count:
            problems.append("RED witness count changed during nested run")
        if result.errors:
            problems.append("unmasked nested runtime error")
        if result.failures:
            problems.append("unmasked nested assertion failure")
        if result.unexpectedSuccesses:
            problems.append("RED converted to XPASS; convert to ordinary PASS")
        if len(result.expectedFailures) != expected_count:
            problems.append("a RED witness did not produce an expected failure")
        for test, traceback_text in result.expectedFailures:
            final_line = traceback_text.rstrip().splitlines()[-1]
            # A raised TypeError, ValueError, network failure, etc. is NOT
            # legitimate evidence of a primitive-admission assertion.
            if not final_line.startswith("AssertionError:"):
                problems.append(
                    "non-assertion RED exception in " + test.id() + ": " + final_line
                )
            if "self.assert" not in traceback_text:
                problems.append("RED witness did not fail at a unittest assertion: " + test.id())
        return problems

    def test_red_exception_classifier_rejects_crashes_and_unexpected_success(self):
        @unittest.expectedFailure
        def _assertion_red(self):
            self.assertFalse(True, "genuine synthetic type refusal")

        @unittest.expectedFailure
        def _crash_red(case):
            raise TypeError("unrelated synthetic test crash")

        @unittest.expectedFailure
        def _fixed_red(case):
            case.assertTrue(True)

        class SyntheticWitnesses(unittest.TestCase):
            test_assertion_red = _assertion_red
            test_crash_red = _crash_red
            test_fixed_red = _fixed_red

        expected = unittest.TestSuite((
            SyntheticWitnesses("test_assertion_red"),
            SyntheticWitnesses("test_crash_red"),
            SyntheticWitnesses("test_fixed_red"),
        ))
        results = unittest.TestResult()
        expected.run(results)
        self.assertEqual(results.testsRun, 3)
        detected = self._unexpected_red_outcomes(results, 3)
        self.assertTrue(any("non-assertion RED exception" in entry for entry in detected))
        self.assertTrue(any("XPASS" in entry for entry in detected))

        # Positive classifier control: a failed unittest assertion is a
        # legitimate expected security RED, unlike a swallowed TypeError.
        positive = unittest.TestResult()
        unittest.TestSuite((SyntheticWitnesses("test_assertion_red"),)).run(positive)
        self.assertEqual(self._unexpected_red_outcomes(positive, 1), [])

    def test_all_registered_source_reds_are_specific_assertion_failures(self):
        witnesses = []
        for klass in (PrimitiveAdmissibilityTests, ActualExecutorAdmissionTests):
            for name in unittest.defaultTestLoader.getTestCaseNames(klass):
                if getattr(getattr(klass, name), "__unittest_expecting_failure__", False):
                    witnesses.append(klass(name))
        self.assertGreater(len(witnesses), 0, "source-RED witness inventory vanished")
        result = unittest.TestResult()
        unittest.TestSuite(witnesses).run(result)
        problems = self._unexpected_red_outcomes(result, len(witnesses))
        self.assertEqual(
            problems, [],
            "XFAIL status cannot hide crashes or accidental passing tests: " + repr(problems),
        )


if __name__ == "__main__":
    unittest.main()
