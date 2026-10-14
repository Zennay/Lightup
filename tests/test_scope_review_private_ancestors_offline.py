"""Offline private-file parent-path symlink and traversal regression cases."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import check_scope_review_packet_offline as packet
import check_scope_review_batch_offline as batch


@unittest.skipUnless(hasattr(os, "symlink") and hasattr(os, "geteuid"), "POSIX filesystem only")
class PrivateAncestorTests(unittest.TestCase):
    def readers(self):
        return ((packet.read_packet, packet.PacketHold, b"{}",
                 "check_scope_review_packet_offline.py"),
                (batch.read_batch_file, batch.BatchHold, b"[]",
                 "check_scope_review_batch_offline.py"))

    def prepare(self, folder, raw):
        root = Path(folder) / "direct"
        root.mkdir(mode=0o700)
        child = root / "nested"
        child.mkdir(mode=0o700)
        source = child / "review.json"
        source.write_bytes(raw)
        source.chmod(0o600)
        return root, child, source

    def test_normal_nested_path_accepted_with_private_flag(self):
        for reader, _, raw, _ in self.readers():
            with self.subTest(reader=reader.__name__), tempfile.TemporaryDirectory() as d:
                _, _, source = self.prepare(d, raw)
                self.assertEqual(raw, reader(str(source), require_private_file=True))

    def test_parent_symlink_rejected_even_when_target_file_private(self):
        for reader, error, raw, _ in self.readers():
            with self.subTest(reader=reader.__name__), tempfile.TemporaryDirectory() as d:
                root, _, source = self.prepare(d, raw)
                link = Path(d) / "shortcut"
                link.symlink_to(root, target_is_directory=True)
                through_link = link / "nested" / "review.json"
                with mock.patch.object(os, "open", side_effect=AssertionError("must not open through symlink")):
                    with self.assertRaises(error) as e:
                        reader(str(through_link), require_private_file=True)
                self.assertEqual("PRIVATE_PARENT_SYMLINK", e.exception.code)

    def test_nested_directory_symlink_rejected(self):
        for reader, error, raw, _ in self.readers():
            with self.subTest(reader=reader.__name__), tempfile.TemporaryDirectory() as d:
                root, child, source = self.prepare(d, raw)
                link = root / "alias"
                link.symlink_to(child, target_is_directory=True)
                with self.assertRaises(error) as e:
                    reader(str(link / "review.json"), require_private_file=True)
                self.assertEqual("PRIVATE_PARENT_SYMLINK", e.exception.code)

    def test_dotdot_lexical_traversal_rejected(self):
        for reader, error, raw, _ in self.readers():
            with self.subTest(reader=reader.__name__), tempfile.TemporaryDirectory() as d:
                root, child, source = self.prepare(d, raw)
                with self.assertRaises(error) as e:
                    reader(str(child / ".." / "nested" / "review.json"),
                           require_private_file=True)
                self.assertEqual("PRIVATE_PATH_TRAVERSAL", e.exception.code)

    def test_private_flag_false_preserves_synthetic_symlink_directory_compat(self):
        for reader, _, raw, _ in self.readers():
            with self.subTest(reader=reader.__name__), tempfile.TemporaryDirectory() as d:
                root, child, source = self.prepare(d, raw)
                link = Path(d) / "shortcut"
                link.symlink_to(root, target_is_directory=True)
                self.assertEqual(raw, reader(str(link / "nested" / "review.json")))

    def test_original_file_symlink_still_rejected_without_private_flag(self):
        for reader, error, raw, _ in self.readers():
            with self.subTest(reader=reader.__name__), tempfile.TemporaryDirectory() as d:
                _, child, source = self.prepare(d, raw)
                direct_link = child / "direct_link.json"
                direct_link.symlink_to(source)
                with self.assertRaises(error) as e:
                    reader(str(direct_link))
                self.assertEqual("INPUT_UNAVAILABLE", e.exception.code)

    def test_private_cli_parent_symlink_opaque_hold(self):
        for _, _, raw, script in self.readers():
            with self.subTest(script=script), tempfile.TemporaryDirectory() as d:
                root, child, source = self.prepare(d, raw)
                link = Path(d) / "SECRET-parent"
                link.symlink_to(root, target_is_directory=True)
                result = subprocess.run(
                    [sys.executable, str(SCRIPTS / script), "--require-private-file",
                     str(link / "nested" / "review.json")],
                    capture_output=True, text=True, timeout=5,
                )
                self.assertEqual(2, result.returncode)
                response = json.loads(result.stdout)
                self.assertEqual("PRIVATE_PARENT_SYMLINK", response["reason"])
                self.assertEqual("HOLD", response["state"])
                self.assertNotIn("SECRET-parent", result.stdout + result.stderr)
                for key in packet.AUTHORITY_FLAGS:
                    self.assertIs(response[key], False)

    def test_nonexistent_parent_is_opaque_hold_before_read(self):
        for reader, error, raw, _ in self.readers():
            with self.subTest(reader=reader.__name__), tempfile.TemporaryDirectory() as d:
                missing = Path(d) / "SECRET-missing-dir" / "review.json"
                with self.assertRaises(error) as outcome:
                    reader(str(missing), require_private_file=True)
                self.assertEqual("INPUT_UNAVAILABLE", outcome.exception.code)

    def test_nonexistent_parent_cli_does_not_echo_customer_path(self):
        for _, _, raw, script in self.readers():
            with self.subTest(script=script), tempfile.TemporaryDirectory() as d:
                missing = Path(d) / "SECRET-missing-dir" / "review.json"
                result = subprocess.run(
                    [sys.executable, str(SCRIPTS / script), "--require-private-file",
                     str(missing)],
                    capture_output=True, text=True, timeout=5,
                )
                self.assertEqual(2, result.returncode)
                response = json.loads(result.stdout)
                self.assertEqual(("HOLD", "INPUT_UNAVAILABLE"),
                                 (response["state"], response["reason"]))
                self.assertNotIn("SECRET-missing-dir", result.stdout + result.stderr)
                self.assertFalse(result.stderr)
                self.assertTrue(all(response[k] is False for k in packet.AUTHORITY_FLAGS))

    def test_snapshot_cli_inherits_parent_symlink_policy(self):
        with tempfile.TemporaryDirectory() as d:
            root, child, file1 = self.prepare(d, b"[]")
            file2 = child / "review2.json"
            file2.write_bytes(b"[]")
            file2.chmod(0o600)
            link = Path(d) / "alias"
            link.symlink_to(root, target_is_directory=True)
            cmd = [sys.executable, str(SCRIPTS / "check_scope_review_snapshots_offline.py"),
                   "--require-private-file", "--summary",
                   str(file1), str(link / "nested" / "review2.json")]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            self.assertEqual(2, result.returncode)
            payload = json.loads(result.stdout)
            self.assertEqual("PRIVATE_PARENT_SYMLINK", payload["reason"])
            self.assertEqual(0, payload["files_checked"])
            self.assertEqual(0, payload["packets_checked"])
            self.assertEqual(0, sum(payload["risk_counts"].values()))
            self.assertTrue(all(payload[key] is False for key in packet.AUTHORITY_FLAGS))


if __name__ == "__main__":
    unittest.main()
