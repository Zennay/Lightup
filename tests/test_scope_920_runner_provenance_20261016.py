"""Pure, non-authorizing regression tests for the #920 targeted CLI guard.

No customer input, sockets, git subprocesses, active scan or runtime patch.
"""
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / (
    "check_scope_920_current_main_acceptance_20261016.py"
)
SPEC = importlib.util.spec_from_file_location("scope_920_acceptance_cli", SCRIPT)
acceptance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(acceptance)


class Scope920RunnerProvenanceTest(unittest.TestCase):
    def test_git_blob_encoding_uses_real_nul_framing(self):
        self.assertEqual(
            acceptance.git_blob_id(b"hello"),
            "b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0",
        )
        self.assertEqual(
            acceptance.git_blob_id(b"hello\n"),
            "ce013625030ba8dba906f756967f9e9ca394464a",
        )

    def test_current_main_source_matches_immutable_pinned_blob(self):
        self.assertEqual(
            acceptance.PINNED_SOURCE_BLOB,
            "ca657372e43a15f212b3b7c92605f9f29e055531",
        )
        self.assertTrue(acceptance.source_is_pinned())

    def test_wrong_source_bytes_fail_closed_without_network_or_git(self):
        with tempfile.TemporaryDirectory(prefix="scope-920-only-") as temp:
            candidate = Path(temp) / "src" / "lightup" / "webapp"
            candidate.mkdir(parents=True)
            (candidate / "security.py").write_bytes(b"not the installed source")
            with patch.object(acceptance, "ROOT", Path(temp)):
                self.assertFalse(acceptance.source_is_pinned())

    def test_missing_source_file_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix="scope-920-only-") as temp:
            with patch.object(acceptance, "ROOT", Path(temp)):
                self.assertFalse(acceptance.source_is_pinned())

    def test_source_drift_does_not_run_tests_or_grant_any_authority(self):
        output = io.StringIO()
        with patch.object(acceptance, "source_is_pinned", return_value=False):
            with patch.object(acceptance.unittest, "TestLoader") as loader:
                with patch("sys.stdout", output):
                    self.assertEqual(acceptance.main(), 2)
                loader.assert_not_called()
        receipt = json.loads(output.getvalue())
        self.assertEqual(receipt["status"], "HOLD")
        self.assertEqual(receipt["tests_run"], 0)
        for field in (
            "source_fixed", "release_authorized", "merge_authorized",
            "scan_authorized", "dispatch_authorized", "registered_vps_verified",
            "full_suite_verified", "client_operator_consent_verified",
        ):
            with self.subTest(field=field):
                self.assertIs(receipt[field], False)


if __name__ == "__main__":
    unittest.main()
