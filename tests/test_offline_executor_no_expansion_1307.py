"""W8: strict non-expansion synthetic-only CLI gate; no real authority.

All tests invoke an ephemeral subprocess or in-process inert synthetic runner.
"""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from lightup.offline_executor_batch_cli_optin import main
from lightup.ai.orchestration import ToolExecutor
from lightup.execution_policy import ExecutionPolicy


class OfflineNoExpansion1307(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="scope-1307-w8-")
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        self.old = base / "baseline.json"
        self.new = base / "proposal.json"

    def _write(self, before, after):
        for path, names in ((self.old, before), (self.new, after)):
            if isinstance(names, bytes):
                path.write_bytes(names)
            else:
                path.write_bytes(json.dumps({"version": 1, "tools": names}).encode("utf-8"))

    def _run(self, flag="--require-no-expansion"):
        return subprocess.run(
            [sys.executable, "-m", "lightup.offline_executor_batch_cli_optin",
             flag, str(self.old), str(self.new)],
            capture_output=True, check=False, timeout=10,
        )

    def _pass(self, added, removed, unchanged):
        p = self._run()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stderr, b"")
        result = json.loads(p.stdout)
        self.assertEqual(result["status"], "reviewed")
        self.assertFalse(result["expansion_detected"])
        self.assertEqual(
            (result["added_tools"], result["removed_tools"], result["unchanged_tools"]),
            (added, removed, unchanged),
        )
        for k in ("permit_issued", "execution_enabled", "authorization_verified"):
            self.assertIs(result[k], False)
        self.assertNotIn(b"offline-check", p.stdout)

    def _deny(self):
        p = self._run()
        self.assertEqual(p.returncode, 2)
        self.assertEqual(p.stdout, b"")
        self.assertEqual(p.stderr, b"synthetic offline preview denied\n")
        self.assertNotIn(str(self.old).encode(), p.stderr)
        self.assertNotIn(str(self.new).encode(), p.stderr)
        self.assertNotIn(b"offline-check", p.stderr)

    def test_same_plan_passes_without_permit(self):
        self._write(["offline-check-001"], ["offline-check-001"])
        self._pass(0, 0, 1)

    def test_reordered_plan_has_no_expansion(self):
        self._write(["offline-check-001", "offline-check-002"],
                    ["offline-check-002", "offline-check-001"])
        self._pass(0, 0, 2)

    def test_removed_tool_passes(self):
        self._write(["offline-check-001", "offline-check-002"],
                    ["offline-check-002"])
        self._pass(0, 1, 1)

    def test_full_64_to_single_plan_passes_without_grant(self):
        all_ids = [f"offline-check-{n:03d}" for n in range(1, 65)]
        self._write(all_ids, ["offline-check-064"])
        self._pass(0, 63, 1)

    def test_added_tool_denied_without_count_or_success_receipt(self):
        self._write(["offline-check-001"],
                    ["offline-check-001", "offline-check-002"])
        self._deny()

    def test_replacement_denied_as_expansion(self):
        self._write(["offline-check-001"], ["offline-check-002"])
        self._deny()

    def test_expansion_from_63_to_64_denied(self):
        self._write([f"offline-check-{n:03d}" for n in range(1, 64)],
                    [f"offline-check-{n:03d}" for n in range(1, 65)])
        self._deny()

    def test_late_invalid_proposal_does_not_emit_partial_receipt(self):
        self._write(["offline-check-001"],
                    ["offline-check-001", "https://example.com"])
        self._deny()

    def test_duplicate_baseline_json_field_fails_closed(self):
        self._write(
            b'{"version":1,"tools":["offline-check-001"],"tools":["offline-check-002"]}',
            ["offline-check-002"],
        )
        self._deny()

    def test_duplicate_proposed_tool_fails_closed(self):
        self._write(["offline-check-001"],
                    ["offline-check-001", "offline-check-001"])
        self._deny()

    def test_missing_baseline_and_proposed_fail_without_path_echo(self):
        self._write(["offline-check-001"], ["offline-check-001"])
        self.old.unlink()
        self._deny()
        self._write(["offline-check-001"], ["offline-check-001"])
        self.new.unlink()
        self._deny()

    def test_bad_cli_flag_does_not_accidentally_become_a_permit(self):
        self._write(["offline-check-001"], ["offline-check-001"])
        p = self._run("--approve")
        self.assertEqual(p.returncode, 2)
        self.assertEqual(p.stdout, b"")
        self.assertEqual(p.stderr, b"synthetic offline preview denied\n")

    def test_non_strict_compare_remains_informational_only(self):
        self._write(["offline-check-001"],
                    ["offline-check-001", "offline-check-002"])
        p = self._run("--compare")
        self.assertEqual(p.returncode, 0, p.stderr)
        receipt = json.loads(p.stdout)
        self.assertTrue(receipt["expansion_detected"])
        self.assertIs(receipt["execution_enabled"], False)
        self.assertIs(receipt["permit_issued"], False)
        self.assertIs(receipt["authorization_verified"], False)

    def test_inprocess_main_never_dispatches_policy_or_executor(self):
        self._write(["offline-check-001"], ["offline-check-001"])
        from io import StringIO
        with patch.object(ToolExecutor, "execute", side_effect=AssertionError("dispatch called")):
            with patch.object(ExecutionPolicy, "decide", side_effect=AssertionError("policy called")):
                with patch("sys.stdout", new_callable=StringIO) as out:
                    code = main(["--require-no-expansion", str(self.old), str(self.new)])
        self.assertEqual(code, 0)
        receipt = json.loads(out.getvalue())
        self.assertFalse(receipt["permit_issued"])
        self.assertFalse(receipt["execution_enabled"])
        self.assertFalse(receipt["authorization_verified"])


if __name__ == "__main__":
    unittest.main()
