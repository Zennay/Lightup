"""W5 real subprocess tests for non-authorizing synthetic plan comparison."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from lightup.offline_executor_batch_cli_optin import _compare


class OfflineSyntheticPlanCompare1307(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="lightup-1307-diff-")
        self.addCleanup(self.tmp.cleanup)
        self.baseline = Path(self.tmp.name) / "baseline.json"
        self.proposed = Path(self.tmp.name) / "proposed.json"

    def _write(self, old, new):
        def as_bytes(value):
            if type(value) is bytes:
                return value
            return json.dumps({"version": 1, "tools": value}).encode("utf-8")
        self.baseline.write_bytes(as_bytes(old))
        self.proposed.write_bytes(as_bytes(new))

    def _run(self):
        return subprocess.run(
            [sys.executable, "-m", "lightup.offline_executor_batch_cli_optin",
             "--compare", str(self.baseline), str(self.proposed)],
            capture_output=True, check=False, timeout=20,
        )

    def _result(self):
        process = self._run()
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(process.stderr, b"")
        receipt = json.loads(process.stdout)
        self.assertEqual(receipt["status"], "reviewed")
        self.assertIs(receipt["permit_issued"], False)
        self.assertIs(receipt["execution_enabled"], False)
        self.assertIs(receipt["authorization_verified"], False)
        self.assertNotIn(b"offline-check-", process.stdout)
        self.assertNotIn(b"synthetic.invalid", process.stdout)
        return receipt

    def _denied(self):
        process = self._run()
        self.assertEqual(process.returncode, 2)
        self.assertEqual(process.stdout, b"")
        self.assertEqual(process.stderr, b"synthetic offline preview denied\n")
        self.assertNotIn(str(self.baseline).encode(), process.stderr)
        self.assertNotIn(str(self.proposed).encode(), process.stderr)

    def test_same_plan_no_expansion(self):
        self._write(["offline-check-001"], ["offline-check-001"])
        self.assertEqual(self._result()["added_tools"], 0)
        self.assertFalse(self._result()["expansion_detected"])

    def test_order_changes_do_not_masquerade_as_expansion(self):
        old = ["offline-check-001", "offline-check-002"]
        self._write(old, list(reversed(old)))
        r = self._result()
        self.assertEqual((r["added_tools"], r["removed_tools"], r["unchanged_tools"]), (0, 0, 2))
        self.assertFalse(r["expansion_detected"])

    def test_one_addition_is_flagged_without_authorizing(self):
        self._write(["offline-check-001"],
                    ["offline-check-001", "offline-check-002"])
        r = self._result()
        self.assertEqual((r["added_tools"], r["removed_tools"], r["unchanged_tools"]), (1, 0, 1))
        self.assertTrue(r["expansion_detected"])
        self.assertIs(r["permit_issued"], False)

    def test_removal_only_does_not_flag_expansion(self):
        self._write(["offline-check-001", "offline-check-002"],
                    ["offline-check-002"])
        r = self._result()
        self.assertEqual((r["added_tools"], r["removed_tools"], r["unchanged_tools"]), (0, 1, 1))
        self.assertFalse(r["expansion_detected"])

    def test_replacement_counts_addition_and_removal(self):
        self._write(["offline-check-001"], ["offline-check-064"])
        r = self._result()
        self.assertEqual((r["added_tools"], r["removed_tools"], r["unchanged_tools"]), (1, 1, 0))
        self.assertTrue(r["expansion_detected"])

    def test_full_sixty_four_to_one_is_bounded_and_narrowing_only(self):
        self._write([f"offline-check-{n:03d}" for n in range(1, 65)],
                    ["offline-check-064"])
        r = self._result()
        self.assertEqual((r["added_tools"], r["removed_tools"], r["unchanged_tools"]), (0, 63, 1))
        self.assertFalse(r["expansion_detected"])

    def test_baseline_invalid_refuses_everything(self):
        self._write(["unknown-target"], ["offline-check-001"])
        self._denied()

    def test_late_invalid_proposed_plan_refuses_without_partial_summary(self):
        self._write(["offline-check-001"],
                    ["offline-check-001", "https://example.com"])
        self._denied()

    def test_late_duplicate_proposal_denied(self):
        self._write(["offline-check-001"], ["offline-check-001", "offline-check-001"])
        self._denied()

    def test_duplicate_baseline_json_keys_denied(self):
        self._write(
            b'{"version":1,"tools":["offline-check-001"],"tools":["offline-check-002"]}',
            ["offline-check-001"],
        )
        self._denied()

    def test_duplicate_proposal_json_keys_denied(self):
        self._write(
            ["offline-check-001"],
            b'{"version":1,"tools":["offline-check-002"],"tools":["offline-check-001"]}',
        )
        self._denied()

    def test_oversized_proposed_input_cannot_emit_partial_result(self):
        self._write(["offline-check-001"], b" " * 4097)
        self._denied()

    def test_missing_input_file_refuses_without_traceback_or_name(self):
        self._write(["offline-check-001"], ["offline-check-002"])
        self.proposed.unlink()
        self._denied()

    def test_in_process_comparison_cannot_invoke_real_executor_or_policy(self):
        from lightup.ai.orchestration import ToolExecutor
        from lightup.execution_policy import ExecutionPolicy
        with patch.object(ToolExecutor, "execute", side_effect=AssertionError("dispatch")):
            with patch.object(ExecutionPolicy, "decide", side_effect=AssertionError("policy")):
                r = _compare(("offline-check-001",), ("offline-check-002",))
        self.assertTrue(r["expansion_detected"])
        self.assertIs(r["permit_issued"], False)
        self.assertIs(r["execution_enabled"], False)
        self.assertIs(r["authorization_verified"], False)


if __name__ == "__main__":
    unittest.main()
