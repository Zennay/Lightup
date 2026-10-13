"""W7 kernel-level bounded read and descriptor lifecycle tests (#1307).

Offline-only local JSON fixtures. This never grants tool authority or performs
target scanning / network activity.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lightup.offline_executor_batch_cli_optin import (
    MAX_BYTES, _load_plan, InvalidSyntheticPlan,
)


class BoundedKernelRead1307(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="lightup-fd-kernel-1307-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.plan = self.root / "synthetic.json"
        self.canonical = b'{"version":1,"tools":["offline-check-001"]}'
        self.plan.write_bytes(self.canonical)

    def test_real_fd_reads_are_all_bounded_by_remaining_budget(self):
        orig_read = os.read
        observed = []

        def bounded(fd, size):
            observed.append(size)
            self.assertLessEqual(size, MAX_BYTES + 1)
            self.assertGreater(size, 0)
            return orig_read(fd, size)

        with patch("lightup.offline_executor_batch_cli_optin.os.read", side_effect=bounded):
            self.assertEqual(_load_plan(str(self.plan)), ("offline-check-001",))
        self.assertGreaterEqual(len(observed), 2)  # payload and EOF
        self.assertEqual(observed[0], MAX_BYTES + 1)
        self.assertEqual(observed[1], MAX_BYTES + 1 - len(self.canonical))

    def test_short_kernel_reads_are_not_treated_as_completed_json(self):
        orig_read = os.read
        requested = []

        def short_reader(fd, size):
            requested.append(size)
            return orig_read(fd, min(size, 3))

        with patch("lightup.offline_executor_batch_cli_optin.os.read", side_effect=short_reader):
            self.assertEqual(_load_plan(str(self.plan)), ("offline-check-001",))
        self.assertGreater(len(requested), 10)
        self.assertTrue(all(1 <= x <= MAX_BYTES + 1 for x in requested))

    def test_valid_json_prefix_followed_by_invalid_trailing_data_is_denied(self):
        self.plan.write_bytes(self.canonical + b'\x00hidden')
        with self.assertRaisesRegex(InvalidSyntheticPlan, "synthetic offline preview denied"):
            _load_plan(str(self.plan))

    def test_payload_growing_mid_stream_is_denied_opaquely(self):
        original = os.read
        changed = False

        def growing(fd, size):
            nonlocal changed
            data = original(fd, min(size, 3))
            if not changed:
                changed = True
                with self.plan.open("ab") as handle:
                    handle.write(b" ")
            return data

        with patch("lightup.offline_executor_batch_cli_optin.os.read", side_effect=growing):
            with self.assertRaisesRegex(InvalidSyntheticPlan, "synthetic offline preview denied"):
                _load_plan(str(self.plan))
        self.assertTrue(changed)

    def test_simulated_read_error_always_closes_original_fd(self):
        original_close = os.close
        opened = []
        closed = []
        original_open = os.open

        def tracked_open(*args, **kwargs):
            fd = original_open(*args, **kwargs)
            opened.append(fd)
            return fd

        def tracked_close(fd):
            closed.append(fd)
            return original_close(fd)

        with patch("lightup.offline_executor_batch_cli_optin.os.open", side_effect=tracked_open):
            with patch("lightup.offline_executor_batch_cli_optin.os.close", side_effect=tracked_close):
                with patch("lightup.offline_executor_batch_cli_optin.os.read", side_effect=OSError("hostile read failure")):
                    with self.assertRaises(OSError):
                        _load_plan(str(self.plan))
        self.assertEqual(opened, closed)

    def test_size_check_runs_before_any_kernel_read(self):
        original_stat = os.fstat
        original_read = os.read

        def huge_size(fd):
            st = original_stat(fd)
            return os.stat_result((
                st.st_mode, st.st_ino, st.st_dev, st.st_nlink, st.st_uid, st.st_gid,
                MAX_BYTES + 1, st.st_atime, st.st_mtime, st.st_ctime,
            ))

        with patch("lightup.offline_executor_batch_cli_optin.os.fstat", side_effect=huge_size):
            with patch("lightup.offline_executor_batch_cli_optin.os.read", wraps=original_read) as spy:
                with self.assertRaises(InvalidSyntheticPlan):
                    _load_plan(str(self.plan))
                spy.assert_not_called()

    def test_exact_maximum_file_bytes_are_allowed(self):
        self.plan.write_bytes(self.canonical + b" " * (MAX_BYTES - len(self.canonical)))
        self.assertEqual(_load_plan(str(self.plan)), ("offline-check-001",))

    def test_overlimit_growth_after_metadata_sample_is_denied(self):
        original_read = os.read
        modified = False

        def change(fd, size):
            nonlocal modified
            if not modified:
                modified = True
                with self.plan.open("ab") as h:
                    h.write(b" " * (MAX_BYTES + 50))
            return original_read(fd, size)

        with patch("lightup.offline_executor_batch_cli_optin.os.read", side_effect=change):
            with self.assertRaises(InvalidSyntheticPlan):
                _load_plan(str(self.plan))

    def test_kernel_read_does_not_call_buffered_path_open(self):
        with patch.object(Path, "open", side_effect=AssertionError("buffered Path.open not allowed")):
            self.assertEqual(_load_plan(str(self.plan)), ("offline-check-001",))


if __name__ == "__main__":
    unittest.main()
