"""Real ToolExecutor finite-number tripwire on a synthetic local lab."""
from __future__ import annotations
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from lightup.ai.orchestration import (
    OrchestrationError, ParamKind, RunContext, ToolCall, ToolDefinition,
    ToolExecutor, ToolOutput, ToolParameter, ToolRegistry,
)
from lightup.ai.typed_argument_integrity import validate_unambiguous_arguments
from lightup.engagements import RiskLevel
from lightup.execution_policy import InteractionKind
from lightup.state import StateStore


class OfflineExecutorNumberTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = StateStore(Path(self.temp.name) / "lab.sqlite3")
        self.calls = []
        self.registry = ToolRegistry()
        definition = ToolDefinition(
            "number-lab-only", "web-baseline", InteractionKind.LAB_ACTIVE,
            RiskLevel.DESTRUCTIVE_LAB_ONLY, "Offline fixture",
            (ToolParameter("value", ParamKind.NUMBER),),
        )

        def handler(context, arguments):
            self.calls.append(arguments["value"])
            return ToolOutput("local fixture", "fixture", b"local-evidence")

        self.registry.register(definition, handler)
        self.executor = ToolExecutor(self.registry, self.state)
        self.context = RunContext.for_lab(run_id="number-only-lab")

    def invoke(self, value):
        return self.executor.execute(
            self.context,
            ToolCall("number-lab-only", "127.0.0.1", (("value", value),)),
        )

    def evidence_count(self):
        with self.state.connect() as db:
            return db.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]

    def test_finite_control_dispatches_once_with_evidence(self):
        result = self.invoke(2.5)
        self.assertEqual(self.calls, [2.5])
        self.assertEqual(self.evidence_count(), 1)
        self.assertTrue(result.evidence_id)

    def test_boolean_denied_before_handler_and_evidence(self):
        with self.assertRaises(OrchestrationError):
            self.invoke(True)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.evidence_count(), 0)

    def test_missing_number_argument_does_not_dispatch_or_write_evidence(self):
        with self.assertRaises(OrchestrationError):
            self.executor.execute(
                self.context, ToolCall("number-lab-only", "127.0.0.1")
            )
        self.assertEqual(self.calls, [])
        self.assertEqual(self.evidence_count(), 0)

    def test_unknown_argument_does_not_dispatch_or_write_evidence(self):
        with self.assertRaises(OrchestrationError):
            self.executor.execute(
                self.context,
                ToolCall("number-lab-only", "127.0.0.1",
                         (("value", 1.0), ("untrusted_extra", 1))),
            )
        self.assertEqual(self.calls, [])
        self.assertEqual(self.evidence_count(), 0)

    def test_denial_after_success_does_not_add_evidence(self):
        self.invoke(1.5)
        before_calls, before_evidence = len(self.calls), self.evidence_count()
        with self.assertRaises(OrchestrationError):
            self.invoke(False)
        self.assertEqual(len(self.calls), before_calls)
        self.assertEqual(self.evidence_count(), before_evidence)

    def test_string_value_denied_before_handler_and_evidence(self):
        with self.assertRaises(OrchestrationError):
            self.invoke("2.5")
        self.assertEqual(self.calls, [])
        self.assertEqual(self.evidence_count(), 0)

    def test_none_value_denied_before_handler_and_evidence(self):
        with self.assertRaises(OrchestrationError):
            self.invoke(None)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.evidence_count(), 0)

    def test_required_number_argument_cannot_be_replaced_by_unknown_key(self):
        with self.assertRaises(OrchestrationError):
            self.executor.execute(
                self.context,
                ToolCall("number-lab-only", "127.0.0.1", (("limit", 2.5),)),
            )
        self.assertEqual(self.calls, [])
        self.assertEqual(self.evidence_count(), 0)

    def test_fixture_has_no_dns_or_network_side_effects(self):
        """Even the positive control must never resolve or open a socket."""
        with (
            patch("socket.getaddrinfo", side_effect=AssertionError("DNS forbidden")) as dns,
            patch("socket.create_connection", side_effect=AssertionError("TCP forbidden")) as tcp,
            patch("socket.socket", side_effect=AssertionError("socket forbidden")) as raw,
        ):
            self.invoke(1.25)
            with self.assertRaises(OrchestrationError):
                self.invoke("not-a-number")
        dns.assert_not_called()
        tcp.assert_not_called()
        raw.assert_not_called()
        self.assertEqual(self.calls, [1.25])
        self.assertEqual(self.evidence_count(), 1)

    def test_repeated_malformed_calls_do_not_accumulate_evidence(self):
        """Denial-only attempts must not inflate the durable lab ledger."""
        for index in range(20):
            with self.subTest(index=index):
                with self.assertRaises(OrchestrationError):
                    self.invoke("invalid-number")
                self.assertEqual(self.calls, [])
                self.assertEqual(self.evidence_count(), 0)

    def test_repeated_malformed_calls_after_success_keep_exact_row_count(self):
        self.invoke(4.0)
        for index in range(20):
            with self.subTest(index=index):
                with self.assertRaises(OrchestrationError):
                    self.invoke(None)
                self.assertEqual(self.calls, [4.0])
                self.assertEqual(self.evidence_count(), 1)

    def test_denial_preserves_exact_existing_evidence_identity(self):
        """Denial must not replace or rewrite a prior successful evidence row."""
        result = self.invoke(7.0)
        with self.state.connect() as db:
            before = tuple(db.execute(
                "SELECT evidence_id, run_id, capability_id, kind, source "
                "FROM evidence ORDER BY evidence_id"
            ).fetchall()[0])
        with self.assertRaises(OrchestrationError):
            self.invoke("7.0")
        with self.state.connect() as db:
            after = tuple(db.execute(
                "SELECT evidence_id, run_id, capability_id, kind, source "
                "FROM evidence ORDER BY evidence_id"
            ).fetchall()[0])
        self.assertEqual(after, before)
        self.assertEqual(result.evidence_id, before[0])
        self.assertEqual(self.calls, [7.0])
        self.assertEqual(self.evidence_count(), 1)

    def test_denials_do_not_change_prior_evidence_payload(self):
        """Evidence bytes must remain stable across denied malformed calls."""
        self.invoke(9.0)
        with self.state.connect() as db:
            before = db.execute(
                "SELECT * FROM evidence ORDER BY evidence_id"
            ).fetchone()
            column_names = [col[1] for col in db.execute("PRAGMA table_info(evidence)")]
            before_values = tuple(before[name] for name in column_names)
        for value in ("9.0", None, False):
            with self.assertRaises(OrchestrationError):
                self.invoke(value)
        with self.state.connect() as db:
            after = db.execute(
                "SELECT * FROM evidence ORDER BY evidence_id"
            ).fetchone()
            after_values = tuple(after[name] for name in column_names)
        self.assertEqual(before_values, after_values)
        self.assertEqual(self.calls, [9.0])
        self.assertEqual(self.evidence_count(), 1)

    def test_denied_arguments_preserve_evidence_after_database_reopen(self):
        """Read through a fresh SQLite connection rather than cached state."""
        result = self.invoke(6.25)
        with self.state.connect() as db:
            before = tuple(db.execute(
                "SELECT * FROM evidence WHERE evidence_id=?", (result.evidence_id,)
            ).fetchone())
        for value in ("6.25", None, False):
            with self.assertRaises(OrchestrationError):
                self.invoke(value)
        with self.state.connect() as db:
            after = tuple(db.execute(
                "SELECT * FROM evidence WHERE evidence_id=?", (result.evidence_id,)
            ).fetchone())
            total = db.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
        self.assertEqual(before, after)
        self.assertEqual(total, 1)
        self.assertEqual(self.calls, [6.25])

    def test_distinct_valid_finite_calls_keep_separate_evidence_records(self):
        """Finite happy-path calls must remain traceable as distinct outputs."""
        first = self.invoke(1.0)
        second = self.invoke(2.0)
        self.assertNotEqual(first.evidence_id, second.evidence_id)
        self.assertEqual(self.calls, [1.0, 2.0])
        self.assertEqual(self.evidence_count(), 2)
        with self.assertRaises(OrchestrationError):
            self.invoke("malformed")
        self.assertEqual(self.evidence_count(), 2)
        self.assertEqual(self.calls, [1.0, 2.0])

    def test_mixed_valid_and_denied_calls_keep_only_valid_evidence(self):
        """Alternating malformed inputs must not contaminate valid evidence."""
        expected = []
        for value in (1.0, "not-numeric", 2.0, None, 3.0, False):
            if isinstance(value, bool) or value is None or isinstance(value, str):
                with self.assertRaises(OrchestrationError):
                    self.invoke(value)
            else:
                expected.append(self.invoke(value).evidence_id)
        self.assertEqual(self.calls, [1.0, 2.0, 3.0])
        self.assertEqual(len(set(expected)), 3)
        with self.state.connect() as db:
            actual = {row[0] for row in db.execute("SELECT evidence_id FROM evidence")}
        self.assertEqual(actual, set(expected))

    def test_rejected_call_does_not_consume_evidence_identity(self):
        """Invalid input between two successes cannot create an action record."""
        first = self.invoke(10.0)
        with self.assertRaises(OrchestrationError):
            self.invoke("invalid")
        second = self.invoke(11.0)
        self.assertNotEqual(first.evidence_id, second.evidence_id)
        self.assertEqual(self.calls, [10.0, 11.0])
        with self.state.connect() as db:
            rows = db.execute(
                "SELECT evidence_id FROM evidence ORDER BY rowid"
            ).fetchall()
        self.assertEqual([row[0] for row in rows],
                         [first.evidence_id, second.evidence_id])

    @unittest.expectedFailure
    def test_duplicate_argument_name_must_not_silently_override(self):
        """ToolCall.arguments_dict currently collapses duplicate tuple keys."""
        with self.assertRaises(OrchestrationError):
            self.executor.execute(
                self.context,
                ToolCall("number-lab-only", "127.0.0.1",
                         (("value", "not-a-number"), ("value", 2.5))),
            )
        self.assertEqual(self.calls, [])
        self.assertEqual(self.evidence_count(), 0)

    @unittest.expectedFailure
    def test_duplicate_argument_name_cannot_replace_good_with_bad(self):
        with self.assertRaises(OrchestrationError):
            self.executor.execute(
                self.context,
                ToolCall("number-lab-only", "127.0.0.1",
                         (("value", 2.5), ("value", 3.5))),
            )
        self.assertEqual(self.calls, [])
        self.assertEqual(self.evidence_count(), 0)

    @unittest.expectedFailure
    def test_duplicate_key_replay_after_valid_call_must_preserve_ledger(self):
        """Ambiguous second invocation must not add evidence to a valid run."""
        self.invoke(1.0)
        before_count = self.evidence_count()
        before_calls = len(self.calls)
        with self.assertRaises(OrchestrationError):
            self.executor.execute(
                self.context,
                ToolCall("number-lab-only", "127.0.0.1",
                         (("value", 1.0), ("value", 2.0))),
            )
        self.assertEqual(self.evidence_count(), before_count)
        self.assertEqual(len(self.calls), before_calls)

    @unittest.expectedFailure
    def test_nonfinite_replay_after_valid_call_must_preserve_ledger(self):
        """A failed numerical input must not mutate prior successful evidence."""
        self.invoke(1.0)
        before_calls = len(self.calls)
        before_evidence = self.evidence_count()
        with self.assertRaises(OrchestrationError):
            self.invoke(float("nan"))
        self.assertEqual(len(self.calls), before_calls)
        self.assertEqual(self.evidence_count(), before_evidence)

    def test_bridge_validator_blocks_duplicate_and_nonfinite_before_real_handler(self):
        """Temporary adapter demonstrates end-to-end wiring without source edits."""
        def bridge(call):
            # Bind validation to the exact registry definition selected by
            # the executor, never to an assumed or caller-named schema.
            definition, _handler = self.registry.get(call.tool_id)
            return validate_unambiguous_arguments(definition, call.arguments)

        with patch.object(ToolCall, "arguments_dict", bridge):
            for value in (float("nan"), float("inf"), float("-inf")):
                with self.subTest(value=str(value)):
                    with self.assertRaises(OrchestrationError):
                        self.invoke(value)
            ambiguous = ToolCall(
                "number-lab-only", "127.0.0.1",
                (("value", 1.0), ("value", 2.0)),
            )
            with self.assertRaises(OrchestrationError):
                self.executor.execute(self.context, ambiguous)
            self.assertEqual(self.calls, [])
            self.assertEqual(self.evidence_count(), 0)
            result = self.invoke(2.5)
            self.assertTrue(result.evidence_id)
            self.assertEqual(self.calls, [2.5])
            self.assertEqual(self.evidence_count(), 1)

    def test_bridge_uses_each_registered_tool_schema(self):
        """A second tool proves the bridge cannot reuse the first tool schema."""
        dispatched = []

        def string_handler(context, arguments):
            dispatched.append(arguments["label"])
            return ToolOutput("secondary local fixture", "fixture", b"secondary")
        self.registry.register(
            ToolDefinition(
                "string-lab-only", "web-baseline", InteractionKind.LAB_ACTIVE,
                RiskLevel.DESTRUCTIVE_LAB_ONLY, "Offline secondary fixture",
                (ToolParameter("label", ParamKind.STRING),),
            ),
            string_handler,
        )

        def bridge(call):
            definition, _handler = self.registry.get(call.tool_id)
            return validate_unambiguous_arguments(definition, call.arguments)

        with patch.object(ToolCall, "arguments_dict", bridge):
            bad_call = ToolCall(
                "string-lab-only", "127.0.0.1", (("value", 2.5),)
            )
            with self.assertRaises(OrchestrationError):
                self.executor.execute(self.context, bad_call)
            self.assertEqual(dispatched, [])
            self.assertEqual(self.evidence_count(), 0)

            valid_call = ToolCall(
                "string-lab-only", "127.0.0.1", (("label", "synthetic"),)
            )
            result = self.executor.execute(self.context, valid_call)
            self.assertTrue(result.evidence_id)
            self.assertEqual(dispatched, ["synthetic"])
            self.assertEqual(self.calls, [])
            self.assertEqual(self.evidence_count(), 1)

    def test_bridge_denial_after_prior_success_preserves_evidence(self):
        """A denied second request must not change committed evidence."""
        def bridge(call):
            definition, _handler = self.registry.get(call.tool_id)
            return validate_unambiguous_arguments(definition, call.arguments)

        with patch.object(ToolCall, "arguments_dict", bridge):
            self.invoke(4.25)
            before_calls = len(self.calls)
            before_evidence = self.evidence_count()
            for invalid in (float("nan"), float("inf"), float("-inf")):
                with self.subTest(invalid=str(invalid)):
                    with self.assertRaises(OrchestrationError):
                        self.invoke(invalid)
                    self.assertEqual(len(self.calls), before_calls)
                    self.assertEqual(self.evidence_count(), before_evidence)
            duplicate_call = ToolCall(
                "number-lab-only", "127.0.0.1",
                (("value", 4.25), ("value", 99.0)),
            )
            with self.assertRaises(OrchestrationError):
                self.executor.execute(self.context, duplicate_call)
            self.assertEqual(len(self.calls), before_calls)
            self.assertEqual(self.evidence_count(), before_evidence)

    def test_bridge_rejects_malformed_registered_required_flag_before_effects(self):
        """A malformed trusted tool schema must fail closed before lab effects."""
        recorded = []

        def malformed_handler(context, arguments):
            recorded.append(arguments)
            return ToolOutput("should never execute", "fixture", b"unexpected")

        self.registry.register(
            ToolDefinition(
                "invalid-schema-lab-only", "web-baseline",
                InteractionKind.LAB_ACTIVE, RiskLevel.DESTRUCTIVE_LAB_ONLY,
                "Offline malformed registry fixture",
                (ToolParameter("value", ParamKind.NUMBER, "yes"),),
            ),
            malformed_handler,
        )

        def bridge(call):
            definition, _handler = self.registry.get(call.tool_id)
            return validate_unambiguous_arguments(definition, call.arguments)

        with patch.object(ToolCall, "arguments_dict", bridge):
            with self.assertRaisesRegex(OrchestrationError, "invalid kind or required"):
                self.executor.execute(
                    self.context,
                    ToolCall(
                        "invalid-schema-lab-only", "127.0.0.1",
                        (("value", 2.5),),
                    ),
                )
        self.assertEqual(recorded, [])
        self.assertEqual(self.calls, [])
        self.assertEqual(self.evidence_count(), 0)

    def test_bridge_rejects_malformed_registered_kind_before_effects(self):
        """Reject a forged registry kind without dispatch or ledger mutation."""
        dispatched = []

        def handler(context, arguments):
            dispatched.append(arguments)
            return ToolOutput("unexpected", "fixture", b"unexpected")

        self.registry.register(
            ToolDefinition(
                "invalid-kind-lab-only", "web-baseline",
                InteractionKind.LAB_ACTIVE, RiskLevel.DESTRUCTIVE_LAB_ONLY,
                "Offline malformed kind fixture",
                (ToolParameter("value", "number"),),
            ),
            handler,
        )

        def bridge(call):
            definition, _handler = self.registry.get(call.tool_id)
            return validate_unambiguous_arguments(definition, call.arguments)

        with patch.object(ToolCall, "arguments_dict", bridge):
            with self.assertRaisesRegex(OrchestrationError, "invalid kind or required"):
                self.executor.execute(
                    self.context,
                    ToolCall("invalid-kind-lab-only", "127.0.0.1", (("value", 2.5),)),
                )
        self.assertEqual(dispatched, [])
        self.assertEqual(self.calls, [])
        self.assertEqual(self.evidence_count(), 0)

    def test_integer_subclass_bridge_denies_before_real_executor_effects(self):
        """Exercise exact INTEGER enforcement at the genuine lab dispatch path."""
        handled = []
        def integer_handler(context, arguments):
            handled.append(arguments["count"])
            return ToolOutput("integer fixture", "fixture", b"integer-evidence")
        self.registry.register(
            ToolDefinition(
                "integer-lab-only", "web-baseline",
                InteractionKind.LAB_ACTIVE, RiskLevel.DESTRUCTIVE_LAB_ONLY,
                "Synthetic integer dispatch",
                (ToolParameter("count", ParamKind.INTEGER),),
            ), integer_handler,
        )
        class SpoofedInt(int):
            def __index__(self):
                raise AssertionError("custom __index__ must never run")
        def bridge(call):
            definition, _handler = self.registry.get(call.tool_id)
            return validate_unambiguous_arguments(definition, call.arguments)
        with patch.object(ToolCall, "arguments_dict", bridge):
            for value in (SpoofedInt(7), True, 2.5):
                with self.subTest(value=value):
                    with self.assertRaises(OrchestrationError):
                        self.executor.execute(
                            self.context,
                            ToolCall("integer-lab-only", "127.0.0.1", (("count", value),)),
                        )
                    self.assertEqual(handled, [])
                    self.assertEqual(self.evidence_count(), 0)
            accepted = self.executor.execute(
                self.context,
                ToolCall("integer-lab-only", "127.0.0.1", (("count", 7),)),
            )
        self.assertTrue(accepted.evidence_id)
        self.assertEqual(handled, [7])
        self.assertEqual(self.evidence_count(), 1)

    @unittest.expectedFailure
    def test_nan_denied_before_handler_and_evidence(self):
        with self.assertRaises(OrchestrationError):
            self.invoke(float("nan"))
        self.assertEqual(self.calls, [])
        self.assertEqual(self.evidence_count(), 0)

    @unittest.expectedFailure
    def test_positive_infinity_denied_before_handler_and_evidence(self):
        with self.assertRaises(OrchestrationError):
            self.invoke(float("inf"))
        self.assertEqual(self.calls, [])
        self.assertEqual(self.evidence_count(), 0)

    @unittest.expectedFailure
    def test_negative_infinity_denied_before_handler_and_evidence(self):
        with self.assertRaises(OrchestrationError):
            self.invoke(float("-inf"))
        self.assertEqual(self.calls, [])
        self.assertEqual(self.evidence_count(), 0)


if __name__ == "__main__":
    unittest.main()
