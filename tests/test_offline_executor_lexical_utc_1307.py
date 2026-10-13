"""W3 strict lexical and UTC guard tests for non-authorizing #1307 preview."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone, tzinfo
from pathlib import Path
import tempfile
import unittest

from lightup.ai.orchestration import (
    ParamKind, RunContext, ToolCall, ToolDefinition,
    ToolExecutor, ToolOutput, ToolParameter, ToolRegistry,
)
from lightup.engagements import AssessmentMode, RiskLevel
from lightup.execution_policy import InteractionKind
from lightup.offline_executor_boundary_preview_optin import (
    OfflineAdmissionDenied, OfflineExecutorBoundaryPreview,
)
from lightup.state import StateStore


class CanaryTZ(tzinfo):
    def utcoffset(self, dt):
        raise AssertionError("attacker-controlled tzinfo executed")

    def dst(self, dt):
        raise AssertionError("attacker-controlled tzinfo executed")


class StrSubclass(str):
    def __len__(self):
        raise AssertionError("attacker-controlled string len executed")

    def __eq__(self, other):
        raise AssertionError("attacker-controlled string eq executed")


class OfflineLexicalBounds1307(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="lightup-1307-w3-")
        self.addCleanup(tmp.cleanup)
        self.state = StateStore(Path(tmp.name) / "synthetic.sqlite")
        self.run_id = self.state.create_run(
            target="synthetic.invalid", activation_mode="plan_only"
        )
        self.called = 0
        self.registry = ToolRegistry()
        for name, parameter in (
            ("number-1307", ToolParameter("number", ParamKind.NUMBER)),
            ("integer-1307", ToolParameter("integer", ParamKind.INTEGER)),
        ):
            self.registry.register(
                ToolDefinition(
                    name, "network-services", InteractionKind.ANALYSIS,
                    RiskLevel.ANALYSIS_ONLY, "inert", (parameter,)
                ), self._handler
            )
        self.preview = OfflineExecutorBoundaryPreview.capture(
            ToolExecutor(self.registry, self.state)
        )
        self.context = RunContext(
            self.run_id, "synthetic", "synthetic-engagement",
            AssessmentMode.ANALYSIS_ONLY, RiskLevel.ANALYSIS_ONLY,
            None, False, datetime.now(timezone.utc),
        )

    def _handler(self, context, args):
        self.called += 1
        return ToolOutput("never invoked", "test", b"never")

    def _call(self, key="number", value=0.5):
        return ToolCall(
            f"{key}-1307", "synthetic.invalid", ((key, value),)
        )

    def _denied(self, context=None, call=None):
        with self.assertRaisesRegex(OfflineAdmissionDenied, "^offline boundary preview refused$"):
            self.preview.preview(
                self.context if context is None else context,
                self._call() if call is None else call,
            )
        self.assertEqual(self.called, 0)
        with self.state.connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM evidence").fetchone()[0], 0)

    def test_exact_utc_timestamp_positive_does_not_execute(self):
        receipt = self.preview.preview(self.context, self._call())
        self.assertFalse(receipt.execution_enabled)
        self.assertFalse(receipt.permit_issued)
        self.assertEqual(self.called, 0)

    def test_custom_timezone_callback_is_never_invoked(self):
        malicious_time = datetime(2026, 10, 13, tzinfo=CanaryTZ())
        self._denied(context=replace(self.context, created_at=malicious_time))

    def test_non_utc_fixed_offset_is_fail_closed(self):
        outside = datetime(2026, 10, 13, tzinfo=timezone.utc)
        self.assertFalse(self.preview.preview(replace(self.context, created_at=outside), self._call()).execution_enabled)
        from datetime import timedelta
        shifted = datetime(2026, 10, 13, tzinfo=timezone(timedelta(hours=1)))
        self._denied(context=replace(self.context, created_at=shifted))

    def test_str_subclass_ids_and_assets_refused_before_user_methods(self):
        self._denied(context=replace(self.context, run_id=StrSubclass(self.run_id)))
        self._denied(call=replace(self._call(), tool_id=StrSubclass("number-1307")))
        self._denied(call=replace(self._call(), asset=StrSubclass("synthetic.invalid")))

    def test_very_long_identity_is_refused_before_regex_scan(self):
        self._denied(context=replace(self.context, client_id="x" * 1_000_000))
        self._denied(call=replace(self._call(), tool_id="x" * 1_000_000))
        self._denied(call=replace(self._call(), asset="x" * 1_000_000))

    def test_numbers_must_be_finite_bounded_and_non_boolean(self):
        for number in (float("nan"), float("inf"), float("-inf"), 10 ** 1000, True):
            with self.subTest(number=str(number)[:20]):
                self._denied(call=self._call(value=number))

    def test_integer_exactness_and_bounds(self):
        self.assertFalse(self.preview.preview(self.context, self._call("integer", 2**63 - 1)).execution_enabled)
        for number in (2**63, -(2**63) - 1, False, 3.14, "2"):
            with self.subTest(value=str(number)[:20]):
                self._denied(call=self._call("integer", number))


if __name__ == "__main__":
    unittest.main()
