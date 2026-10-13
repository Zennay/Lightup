"""Actual in-process optional ToolCall identity admission tests (#1094).

Inert analysis handler + disposable SQLite only. Never dispatches target/lab work.
"""

from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from lightup.ai.orchestration import (
    RunContext,
    ToolCall,
    ToolDefinition,
    ToolDenied,
    ToolExecutor,
    ToolOutput,
    ToolParameter,
    ToolRegistry,
    ParamKind,
)
from lightup.engagements import AssessmentMode, RiskLevel
from lightup.execution_policy import InteractionKind
from lightup.state import StateStore
from lightup.strict_toolcall_identity_optin import (
    StrictFieldIdentityExecutor,
    require_canonical_toolcall,
)


class EvilString(str):
    def __hash__(self):
        raise AssertionError("untrusted string subclass __hash__ invoked")

    def __eq__(self, other):
        raise AssertionError("untrusted string subclass __eq__ invoked")


class ToolCallSubclass(ToolCall):
    pass


class StrictFieldIdentityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = StateStore(Path(self.tmp.name) / "state.sqlite")
        run_id = self.state.create_run("synthetic.local")
        self.context = RunContext(
            run_id=run_id,
            client_id="synthetic",
            engagement_id="synthetic",
            mode=AssessmentMode.ANALYSIS_ONLY,
            approved_risk=RiskLevel.ANALYSIS_ONLY,
            authorization=None,
            is_lab=False,
            created_at=datetime.now(timezone.utc),
        )
        self.seen = []
        self.registry = ToolRegistry()

        def inert_analysis(_context, arguments):
            self.seen.append(arguments["message"])
            return ToolOutput("offline only", "note", b"synthetic analysis")

        self.registry.register(
            ToolDefinition(
                "offline-note", "web-baseline", InteractionKind.ANALYSIS,
                RiskLevel.ANALYSIS_ONLY, "offline inert test handler",
                (ToolParameter("message", ParamKind.STRING),),
            ),
            inert_analysis,
        )
        self.raw = ToolExecutor(self.registry, self.state)
        self.strict = StrictFieldIdentityExecutor(self.raw)

    def call(self, **changes):
        return replace(
            ToolCall("offline-note", "synthetic.local", (("message", "ok"),)),
            **changes,
        )

    def evidence_count(self):
        with self.state.connect() as con:
            return con.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]

    def assert_denied_without_effects(self, call):
        before = self.evidence_count()
        with patch.object(self.raw, "execute", wraps=self.raw.execute) as delegated:
            with self.assertRaisesRegex(ToolDenied, "noncanonical tool-call identity"):
                self.strict.execute(self.context, call)
            delegated.assert_not_called()
        self.assertEqual(self.seen, [])
        self.assertEqual(self.evidence_count(), before)

    def test_exact_builtin_names_reach_real_analysis_executor(self):
        result = self.strict.execute(self.context, self.call())
        self.assertEqual(result.capability_id, "web-baseline")
        self.assertEqual(self.seen, ["ok"])
        self.assertEqual(self.evidence_count(), 1)

    def test_safe_snapshot_is_a_normal_original_toolcall(self):
        source = self.call()
        checked = require_canonical_toolcall(source)
        self.assertIs(type(checked), ToolCall)
        self.assertIsNot(checked, source)
        self.assertEqual(checked, source)
        self.assertIs(type(checked.arguments), tuple)

    def test_reject_tool_id_subclass_without_hash_or_equality(self):
        self.assert_denied_without_effects(self.call(tool_id=EvilString("offline-note")))

    def test_reject_argument_key_subclass_without_hash_or_equality(self):
        self.assert_denied_without_effects(
            self.call(arguments=((EvilString("message"), "ok"),))
        )

    def test_reject_polymorphic_outer_call(self):
        self.assert_denied_without_effects(
            ToolCallSubclass("offline-note", "synthetic.local", (("message", "ok"),))
        )

    def test_reject_non_string_tool_ids(self):
        for value in (None, False, b"offline-note", 4):
            with self.subTest(value=value):
                self.assert_denied_without_effects(self.call(tool_id=value))

    def test_reject_non_string_argument_keys(self):
        for value in (None, False, b"message", 4):
            with self.subTest(value=value):
                self.assert_denied_without_effects(
                    self.call(arguments=((value, "ok"),))
                )

    def test_reject_ambiguous_tool_names(self):
        for value in ("", " offline-note", "offline-note ", "off\nline-note",
                      "offline／note", "☁", "4offline", "a" * 129):
            with self.subTest(value=value):
                self.assert_denied_without_effects(self.call(tool_id=value))

    def test_reject_ambiguous_argument_names(self):
        for value in ("", " message", "message ", "mess\tage", "ｍessage",
                      "4message", "a" * 129):
            with self.subTest(value=value):
                self.assert_denied_without_effects(
                    self.call(arguments=((value, "ok"),))
                )

    def test_reject_malformed_argument_container_before_projection(self):
        for value in ([("message", "ok")], "message", None, {}):
            with self.subTest(shape=type(value).__name__):
                self.assert_denied_without_effects(self.call(arguments=value))

    def test_reject_malformed_pairs_before_projection(self):
        for value in ((["message", "ok"],), (("message",),),
                      (("message", "ok", "extra"),), (None,)):
            with self.subTest(value=str(value)):
                self.assert_denied_without_effects(self.call(arguments=value))

    def test_reject_duplicate_argument_names_without_losing_first_value(self):
        self.assert_denied_without_effects(
            self.call(arguments=(("message", "first"), ("message", "second")))
        )

    def test_name_validation_never_evaluates_argument_value(self):
        class AdversarialValue:
            def __str__(self):
                raise AssertionError("value inspected as text")

            def __bool__(self):
                raise AssertionError("value coerced")

        bad_value = AdversarialValue()
        self.assert_denied_without_effects(
            self.call(arguments=((EvilString("message"), bad_value),))
        )

    def test_existing_parameter_schema_still_refuses_invalid_value(self):
        from lightup.ai.orchestration import OrchestrationError

        with self.assertRaises(OrchestrationError):
            self.strict.execute(
                self.context, self.call(arguments=(("message", 123),))
            )
        self.assertEqual(self.seen, [])
        self.assertEqual(self.evidence_count(), 0)

    def test_other_default_tools_remain_unavailable(self):
        with self.assertRaises(OrchestrationError):
            from lightup.ai.orchestration import OrchestrationError
            self.strict.execute(
                self.context, self.call(tool_id="nonexistent-tool")
            )
        self.assertEqual(self.evidence_count(), 0)


if __name__ == "__main__":
    unittest.main()
