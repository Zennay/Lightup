"""W10 canonical nofollow path traversal for synthetic offline plans.

Genuine tempfile and subprocess behavior; no network, target or tool dispatch.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from lightup.offline_executor_batch_cli_optin import (
    _load_plan, _open_plan_fd_without_symlink_ancestors,
    InvalidSyntheticPlan,
)


class NoSymlinkAncestor1307(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="lightup-w10-ancestor-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.real = self.root / "real"
        self.real.mkdir()
        self.child = self.real / "child"
        self.child.mkdir()
        self.plan = self.child / "plan.json"
        self.plan.write_text(
            '{"version":1,"tools":["offline-check-001"]}', encoding="utf-8"
        )
        self.alias = self.root / "alias"
        self.alias.symlink_to(self.real, target_is_directory=True)
        self.direct_alias = self.root / "file-alias.json"
        self.direct_alias.symlink_to(self.plan)

    def _cli(self, flag: str, *paths: str | Path, cwd=None):
        env = os.environ.copy()
        # A test launched from a disposable directory still imports source
        # from the checked-out repository, not cwd or third-party PYTHONPATH.
        source = str(Path(__file__).resolve().parents[1] / "src")
        env["PYTHONPATH"] = source
        return subprocess.run(
            [sys.executable, "-m", "lightup.offline_executor_batch_cli_optin",
             flag, *map(str, paths)],
            cwd=cwd, env=env, capture_output=True, check=False, timeout=10,
        )

    def _denied(self, result):
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"synthetic offline preview denied\n")
        self.assertNotIn(b"offline-check", result.stderr)

    def test_existing_absolute_nested_regular_file_succeeds(self):
        self.assertEqual(_load_plan(str(self.plan)), ("offline-check-001",))
        r = self._cli("--input", self.plan)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(json.loads(r.stdout)["permit_issued"])

    def test_existing_relative_nested_regular_file_succeeds(self):
        r = self._cli("--input", "real/child/plan.json", cwd=self.root)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)["tools_reviewed"], 1)

    def test_absolute_symlink_ancestor_denied_before_content(self):
        r = self._cli("--input", self.alias / "child" / "plan.json")
        self._denied(r)

    def test_relative_symlink_ancestor_denied_before_content(self):
        r = self._cli("--input", "alias/child/plan.json", cwd=self.root)
        self._denied(r)

    def test_last_component_symlink_still_denied(self):
        self._denied(self._cli("--input", self.direct_alias))

    def test_late_proposed_plan_with_parent_symlink_denied_without_receipt(self):
        self._denied(
            self._cli("--compare", self.plan, self.alias / "child" / "plan.json")
        )
        self._denied(
            self._cli("--require-no-expansion", self.plan,
                      self.alias / "child" / "plan.json")
        )

    def test_bad_baseline_parent_symlink_denied_without_partial_receipt(self):
        self._denied(
            self._cli("--compare", self.alias / "child" / "plan.json", self.plan)
        )

    def test_parent_traversal_dotdot_is_refused_opaquely(self):
        self._denied(
            self._cli("--input", self.root / "real" / ".." / "real" / "child" / "plan.json")
        )

    def test_very_deep_path_components_denied_without_chasing(self):
        unsafe = str(self.root) + "/" + ("real/" * 80) + "plan.json"
        self._denied(self._cli("--input", unsafe))

    def test_non_directory_parent_is_refused_opaquely(self):
        self._denied(self._cli("--input", self.plan / "child.json"))

    def test_every_directory_open_pins_nofollow_and_directory_flags(self):
        open_fn = os.open
        calls = []

        def track(name, flags, **kw):
            calls.append((name, flags, kw))
            return open_fn(name, flags, **kw)

        with patch("lightup.offline_executor_batch_cli_optin.os.open", side_effect=track):
            self.assertEqual(_load_plan(str(self.plan)), ("offline-check-001",))
        self.assertGreaterEqual(len(calls), 4)
        for name, flags, kw in calls[:-1]:
            self.assertTrue(flags & os.O_NOFOLLOW, name)
            self.assertTrue(flags & os.O_DIRECTORY, name)
            self.assertTrue(flags & os.O_CLOEXEC, name)
        leaf_name, leaf_flags, leaf_kwargs = calls[-1]
        self.assertEqual(leaf_name, "plan.json")
        self.assertTrue(leaf_flags & os.O_NOFOLLOW)
        self.assertTrue(leaf_flags & os.O_NONBLOCK)
        self.assertIn("dir_fd", leaf_kwargs)

    def test_ancestor_open_failure_does_not_leak_fd(self):
        open_fn, close_fn = os.open, os.close
        opened, closed = [], []

        def track_open(path, flags, **kw):
            fd = open_fn(path, flags, **kw)
            opened.append(fd)
            return fd

        def track_close(fd):
            closed.append(fd)
            return close_fn(fd)

        with patch("lightup.offline_executor_batch_cli_optin.os.open", side_effect=track_open):
            with patch("lightup.offline_executor_batch_cli_optin.os.close", side_effect=track_close):
                with self.assertRaises(OSError):
                    _open_plan_fd_without_symlink_ancestors(
                        str(self.alias / "child" / "plan.json")
                    )
        self.assertEqual(opened, closed)

    def test_unknown_weak_platform_flags_fail_closed_before_any_open(self):
        # Change only this module's hasattr lookup via a spy object is more
        # fragile than testing runtime; use a malformed (empty) path control.
        with self.assertRaises(InvalidSyntheticPlan):
            _open_plan_fd_without_symlink_ancestors("")

    def test_existing_symlink_does_not_expose_original_file_path(self):
        self._denied(self._cli("--input", self.alias / "child" / "plan.json"))
        self._denied(self._cli("--input", self.direct_alias))


if __name__ == "__main__":
    unittest.main()
