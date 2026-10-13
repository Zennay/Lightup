"""W11: hardlink and shared-write admission for synthetic-only JSON plans.

Real tempfile, fstat and CLI subprocesses. No network or actual tool dispatch.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from lightup.offline_executor_batch_cli_optin import _load_plan, InvalidSyntheticPlan


class LocalLinkAndModeAdmission1307(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory(prefix="lightup-w11-link-")
        self.addCleanup(d.cleanup)
        self.root = Path(d.name)
        self.plan = self.root / "plan.json"
        self.plan.write_text(
            '{"version":1,"tools":["offline-check-001"]}', encoding="utf-8"
        )
        self.alias = self.root / "hardlink.json"

    def _run(self, mode="--input", *paths):
        if not paths:
            paths = (self.plan,)
        return subprocess.run(
            [sys.executable, "-m", "lightup.offline_executor_batch_cli_optin",
             mode, *map(str, paths)],
            capture_output=True, check=False, timeout=12,
        )

    def _denied(self, process):
        self.assertEqual(process.returncode, 2)
        self.assertEqual(process.stdout, b"")
        self.assertEqual(process.stderr, b"synthetic offline preview denied\n")
        self.assertNotIn(str(self.plan).encode(), process.stderr)

    def test_standard_single_link_file_stays_offline_non_authorizing(self):
        p = self._run()
        self.assertEqual(p.returncode, 0, p.stderr)
        receipt = json.loads(p.stdout)
        self.assertEqual(receipt["tools_reviewed"], 1)
        for key in ("permit_issued", "execution_enabled", "authorization_verified"):
            self.assertIs(receipt[key], False)

    def test_read_only_single_link_plan_remains_supported(self):
        self.plan.chmod(stat.S_IRUSR)
        self.assertEqual(_load_plan(str(self.plan)), ("offline-check-001",))

    def test_extra_hardlink_to_same_file_is_denied(self):
        os.link(self.plan, self.alias)
        self.assertEqual(os.stat(self.plan).st_nlink, 2)
        self._denied(self._run())
        self._denied(self._run("--input", self.alias))

    def test_hardlink_in_late_proposed_plan_cannot_emit_partial_receipt(self):
        os.link(self.plan, self.alias)
        baseline = self.root / "baseline.json"
        baseline.write_bytes(self.plan.read_bytes())
        self._denied(self._run("--compare", baseline, self.alias))
        self._denied(self._run("--require-no-expansion", baseline, self.alias))

    def test_delete_hardlink_restores_one_link_synthetic_read(self):
        os.link(self.plan, self.alias)
        self._denied(self._run())
        self.alias.unlink()
        p = self._run()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertFalse(json.loads(p.stdout)["execution_enabled"])

    def test_world_writable_file_denied(self):
        self.plan.chmod(0o666)
        self._denied(self._run())

    def test_group_writable_file_denied(self):
        self.plan.chmod(0o664)
        self._denied(self._run())

    def test_owner_only_writable_plan_is_valid(self):
        self.plan.chmod(0o600)
        self.assertEqual(_load_plan(str(self.plan)), ("offline-check-001",))

    def test_hardlink_created_during_read_is_denied_even_if_size_unchanged(self):
        read_fn = os.read
        done = False

        def create_link(fd, count):
            nonlocal done
            chunk = read_fn(fd, count)
            if not done:
                done = True
                os.link(self.plan, self.alias)
            return chunk

        with patch("lightup.offline_executor_batch_cli_optin.os.read", side_effect=create_link):
            with self.assertRaises(InvalidSyntheticPlan):
                _load_plan(str(self.plan))
        self.assertTrue(done)

    def test_mode_turned_group_writable_during_read_is_denied(self):
        read_fn = os.read
        changed = False

        def chmod(fd, count):
            nonlocal changed
            chunk = read_fn(fd, count)
            if not changed:
                changed = True
                self.plan.chmod(0o664)
            return chunk

        with patch("lightup.offline_executor_batch_cli_optin.os.read", side_effect=chmod):
            with self.assertRaises(InvalidSyntheticPlan):
                _load_plan(str(self.plan))
        self.assertTrue(changed)

    def test_simulated_late_nlink_change_is_denied(self):
        original_stat = os.fstat
        seen = 0

        class Metadata:
            def __init__(self, real):
                self.real = real

            def __getattr__(self, name):
                if name == "st_nlink":
                    return self.real.st_nlink + 1
                return getattr(self.real, name)

        def late(fd):
            nonlocal seen
            seen += 1
            val = original_stat(fd)
            return Metadata(val) if seen == 2 else val

        with patch("lightup.offline_executor_batch_cli_optin.os.fstat", side_effect=late):
            with self.assertRaises(InvalidSyntheticPlan):
                _load_plan(str(self.plan))
        self.assertEqual(seen, 2)

    def test_symlinks_are_still_denied_by_path_traversal(self):
        self.alias.symlink_to(self.plan)
        self._denied(self._run("--input", self.alias))


if __name__ == "__main__":
    unittest.main()
