"""W9 - same-length local synthetic plan-file change regressions (#1307).

No production source, grants, targets or sockets. Fixture files are disposable.
"""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lightup.offline_executor_batch_cli_optin import _load_plan, InvalidSyntheticPlan


class _ChangedStat:
    def __init__(self, wrapped, **updates):
        self.wrapped = wrapped
        self.updates = updates

    def __getattr__(self, key):
        return self.updates.get(key, getattr(self.wrapped, key))


class SameLengthMutation1307(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory(prefix="lightup-1307-w9-")
        self.addCleanup(d.cleanup)
        self.path = Path(d.name) / "synthetic.json"
        self.original = b'{"version":1,"tools":["offline-check-001"]}'
        self.rewritten = b'{"version":1,"tools":["offline-check-002"]}'
        self.assertEqual(len(self.original), len(self.rewritten))
        self.path.write_bytes(self.original)

    def _assert_denied(self):
        with self.assertRaisesRegex(
            InvalidSyntheticPlan, "^synthetic offline preview denied$"
        ):
            _load_plan(str(self.path))

    def test_stable_file_still_returns_exact_synthetic_tool(self):
        self.assertEqual(_load_plan(str(self.path)), ("offline-check-001",))

    def test_same_size_rewrite_after_first_read_is_denied(self):
        original_read = os.read
        wrote = False

        def rewrite(fd, count):
            nonlocal wrote
            chunk = original_read(fd, count)
            if not wrote:
                wrote = True
                self.path.write_bytes(self.rewritten)
                st = self.path.stat()
                os.utime(
                    self.path,
                    ns=(st.st_atime_ns, st.st_mtime_ns + 10_000_000_000),
                )
            return chunk

        with patch("lightup.offline_executor_batch_cli_optin.os.read", side_effect=rewrite):
            self._assert_denied()
        self.assertTrue(wrote)

    def test_file_mode_change_after_open_is_denied(self):
        original_read = os.read
        changed = False

        def change_mode(fd, count):
            nonlocal changed
            chunk = original_read(fd, count)
            if not changed:
                changed = True
                self.path.chmod(0o400)
            return chunk

        with patch("lightup.offline_executor_batch_cli_optin.os.read", side_effect=change_mode):
            self._assert_denied()
        self.assertTrue(changed)

    def test_simulated_same_length_mtime_change_is_denied(self):
        stat_fd = os.fstat
        seen = 0

        def changed(fd):
            nonlocal seen
            seen += 1
            real = stat_fd(fd)
            if seen == 2:
                return _ChangedStat(real, st_mtime_ns=real.st_mtime_ns + 1)
            return real

        with patch("lightup.offline_executor_batch_cli_optin.os.fstat", side_effect=changed):
            self._assert_denied()
        self.assertEqual(seen, 2)

    def test_simulated_same_length_ctime_change_is_denied(self):
        original = os.fstat
        count = 0

        def changed(fd):
            nonlocal count
            count += 1
            st = original(fd)
            if count == 2:
                return _ChangedStat(st, st_ctime_ns=st.st_ctime_ns + 1)
            return st

        with patch("lightup.offline_executor_batch_cli_optin.os.fstat", side_effect=changed):
            self._assert_denied()
        self.assertEqual(count, 2)

    def test_simulated_inode_switch_is_denied_even_when_size_is_unchanged(self):
        original = os.fstat
        count = 0

        def changed(fd):
            nonlocal count
            count += 1
            st = original(fd)
            if count == 2:
                return _ChangedStat(st, st_ino=st.st_ino + 1)
            return st

        with patch("lightup.offline_executor_batch_cli_optin.os.fstat", side_effect=changed):
            self._assert_denied()

    def test_simulated_device_switch_is_denied_even_when_size_is_unchanged(self):
        original = os.fstat
        count = 0

        def changed(fd):
            nonlocal count
            count += 1
            st = original(fd)
            if count == 2:
                return _ChangedStat(st, st_dev=st.st_dev + 1)
            return st

        with patch("lightup.offline_executor_batch_cli_optin.os.fstat", side_effect=changed):
            self._assert_denied()


if __name__ == "__main__":
    unittest.main()
