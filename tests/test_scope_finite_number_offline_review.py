"""Real pure numeric admission and synthetic ANALYSIS_ONLY executor tests."""
from __future__ import annotations

import json
import math
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from enum import IntEnum
from pathlib import Path

from lightup.ai.orchestration import (
    ParamKind, RunContext, ToolCall, ToolDefinition, ToolExecutor,
    ToolOutput, ToolParameter, ToolRegistry,
)
from lightup.engagements import AssessmentMode, RiskLevel
from lightup.execution_policy import InteractionKind
from lightup.finite_number_offline_review import (
    review_finite_number_arguments, snapshot_finite_number_arguments,
)
from lightup.state import StateStore


class DerivedInt(int):
    pass


class DerivedFloat(float):
    pass


class ANumber(IntEnum):
    ONE = 1


class FiniteNumberOfflineReviewTests(unittest.TestCase):
    def test_exact_builtin_finite_numbers(self):
        values = (0, -1, 42, 10 ** 400, 0.0, -0.0, 0.25, -1e300, 1e-300)
        for value in values:
            with self.subTest(value=str(value)[:20]):
                self.assertEqual(
                    snapshot_finite_number_arguments((("amount", value),)),
                    (("amount", value),),
                )

    def test_huge_integer_budget_and_boundary_signs(self):
        finite_edge = (1 << 4095)
        for value in (finite_edge, -finite_edge, (1 << 4096) - 1, -((1 << 4096) - 1)):
            with self.subTest(size=value.bit_length(), negative=value < 0):
                self.assertEqual(
                    snapshot_finite_number_arguments((("amount", value),)),
                    (("amount", value),),
                )
        for value in (1 << 4096, -(1 << 4096), 10 ** 2000, -(10 ** 2000)):
            with self.subTest(size=value.bit_length(), negative=value < 0):
                with self.assertRaises(ValueError):
                    snapshot_finite_number_arguments((("amount", value),))
                receipt = review_finite_number_arguments((("secret", value),))
                self.assertEqual(receipt["status"], "HOLD")
                self.assertEqual(receipt["checked_count"], 0)
                self.assertNotIn("secret", str(receipt))

    def test_huge_late_integer_failure_is_atomic(self):
        controls = tuple((f"n{i}", i) for i in range(31))
        with self.assertRaises(ValueError):
            snapshot_finite_number_arguments(controls + (("later", 1 << 4096),))
        self.assertEqual(
            snapshot_finite_number_arguments(controls)[0], ("n0", 0)
        )

    def test_nonfinite_and_subtyped_values_fail_closed(self):
        invalid = (
            float("nan"), float("inf"), float("-inf"),
            True, False, None, "1", b"1", complex(1, 0),
            DerivedInt(1), DerivedFloat(1.0), ANumber.ONE, object(),
        )
        for value in invalid:
            with self.subTest(kind=type(value).__name__):
                with self.assertRaisesRegex(ValueError, "noncanonical"):
                    snapshot_finite_number_arguments((("amount", value),))

    def test_invalid_name_and_duplicate_fail_closed(self):
        for name in ("", "A", "_x", "x-y", "a.b", "has space",
                     "\\n", "x" * 65, "x\\x00", "admin.token"):
            with self.subTest(name=repr(name)):
                with self.assertRaises(ValueError):
                    snapshot_finite_number_arguments(((name, 1),))
        for batch in ((("x", 1), ("x", 2)), ((True, 1),),
                      ((DerivedString("x"), 1),)):
            with self.assertRaises(ValueError):
                snapshot_finite_number_arguments(batch)

    def test_noncanonical_containers_and_sizes_fail_closed(self):
        invalid = (None, [], {}, (), [("a", 1)],
                   tuple((f"n{i}", i) for i in range(33)),
                   ((("n", 1, 2)),), (["n", 1],),
                   (("x", 1), ("x", 2)))
        for entries in invalid:
            with self.subTest(kind=repr(type(entries))):
                with self.assertRaises(ValueError):
                    snapshot_finite_number_arguments(entries)

    def test_atomic_late_invalid_and_sorted_snapshot(self):
        self.assertEqual(
            snapshot_finite_number_arguments((("weight", 0.5), ("amount", 100))),
            (("amount", 100), ("weight", 0.5)),
        )
        with self.assertRaises(ValueError):
            snapshot_finite_number_arguments(
                tuple((f"n{i}", i) for i in range(31)) + (("last", math.inf),)
            )

    def test_machine_receipt_never_grants_authority_or_echoes_values(self):
        for batch in ((("risk", 2),), (("secret", float("nan")),),
                      (("real_target", 7), ("late", float("inf")))):
            receipt = review_finite_number_arguments(batch)
            self.assertIn(receipt["status"], {"HOLD", "REVIEW_ONLY"})
            for flag in ("authorization_verified", "permit_issued",
                         "execution_enabled", "merge_approved", "release_approved"):
                self.assertIs(receipt[flag], False)
            self.assertNotIn("secret", str(receipt))
            self.assertNotIn("real_target", str(receipt))


    def test_stdin_cli_privacy_and_fail_closed_invalid_payloads(self):
        cli = Path(__file__).resolve().parents[1] / "scripts" / "review_scope_finite_number_offline.py"
        examples = (
            (b'{"arguments":[["count",2],["weight",0.5]]}', "REVIEW_ONLY", 3),
            (b'{"arguments":[["count",2],["weight",1e999]]}', "HOLD", 2),
            (b'{"arguments":[["huge",' + b'9' * 1300 + b']]}', "HOLD", 2),
            (b'{"arguments":[["huge",-' + b'9' * 1300 + b']]}', "HOLD", 2),
            (b'{"arguments":[["count",NaN]]}', "HOLD", 2),
            (b'{"arguments":[["secret",7],["secret",8]]}', "HOLD", 2),
            (b'{"arguments":[["secret",7]],"arguments":[["secret",8]]}', "HOLD", 2),
            (b'{"arguments":[["bad.name",7]]}', "HOLD", 2),
            (b'{"arguments":[]}', "HOLD", 2),
            (b'{"arguments":[["count",true]]}', "HOLD", 2),
            (b'{"arguments":[["count",2]]}' + b" " * 8193, "HOLD", 2),
            (b'{"arguments":[["private",42]],"target":"example.com"}', "HOLD", 2),
        )
        for payload, expected_status, expected_code in examples:
            with self.subTest(data=payload[:20]):
                run = subprocess.run(
                    [sys.executable, str(cli)],
                    input=payload, capture_output=True, timeout=10,
                    check=False,
                )
                self.assertEqual(run.returncode, expected_code, run.stderr.decode())
                self.assertEqual(run.stderr, b"")
                receipt = json.loads(run.stdout)
                self.assertEqual(receipt["status"], expected_status)
                self.assertEqual(len(run.stdout.splitlines()), 1)
                for field in ("authorization_verified", "permit_issued",
                              "execution_enabled", "merge_approved", "release_approved"):
                    self.assertIs(receipt[field], False)
                for private in ("secret", "private", "example.com", "NaN", "Infinity"):
                    self.assertNotIn(private, run.stdout.decode())

    def test_stdin_cli_rejects_unexpected_arguments_without_stdin(self):
        cli = Path(__file__).resolve().parents[1] / "scripts" / "review_scope_finite_number_offline.py"
        run = subprocess.run(
            [sys.executable, str(cli), "--allow-target"],
            input=b"", capture_output=True, timeout=10, check=False,
        )
        self.assertEqual(run.returncode, 2)
        self.assertEqual(json.loads(run.stdout)["status"], "HOLD")
        self.assertEqual(run.stderr, b"")

    def test_reference_admission_before_real_analysis_executor_and_sqlite(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(Path(tmp) / "audit.sqlite")
            run_id = store.create_run(target="synthetic.invalid")
            context = RunContext(
                run_id=run_id, client_id="synthetic", engagement_id="synthetic",
                mode=AssessmentMode.ANALYSIS_ONLY,
                approved_risk=RiskLevel.ANALYSIS_ONLY,
                authorization=None, is_lab=False,
                created_at=datetime.now(timezone.utc),
            )
            touched = []
            def handler(_ctx, args):
                touched.append(tuple(sorted(args.items())))
                return ToolOutput("ok", "synthetic", b"offline-only")

            registry = ToolRegistry()
            registry.register(
                ToolDefinition("synthetic.analysis", "web-baseline",
                               InteractionKind.ANALYSIS, RiskLevel.ANALYSIS_ONLY,
                               "no target I/O",
                               (ToolParameter("count", ParamKind.NUMBER),
                                ToolParameter("weight", ParamKind.NUMBER))),
                handler,
            )
            executor = ToolExecutor(registry, store)
            batch = snapshot_finite_number_arguments(
                (("weight", 0.125), ("count", 10))
            )
            result = executor.execute(
                context, ToolCall("synthetic.analysis", "synthetic.invalid", batch)
            )
            self.assertEqual(result.run_id, run_id)
            self.assertEqual(touched, [batch])
            with store.connect() as con:
                self.assertEqual(con.execute(
                    "SELECT count(*) FROM evidence WHERE run_id=?", (run_id,)
                ).fetchone()[0], 1)
            for invalid in (math.nan, math.inf, -math.inf, DerivedFloat(1.0)):
                with self.subTest(value=repr(invalid)):
                    with self.assertRaises(ValueError):
                        snapshot_finite_number_arguments(
                            (("count", 10), ("weight", invalid))
                        )
            self.assertEqual(len(touched), 1)
            with store.connect() as con:
                self.assertEqual(con.execute(
                    "SELECT count(*) FROM evidence WHERE run_id=?", (run_id,)
                ).fetchone()[0], 1)


class DerivedString(str):
    pass


if __name__ == "__main__":
    unittest.main()
