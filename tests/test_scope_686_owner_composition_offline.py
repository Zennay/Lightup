"""Failure-mode unit tests of the non-authorizing #686 composition tool."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from scripts import scope_686_owner_composition_offline as compose


class CompositionSafetyTests(unittest.TestCase):
    def test_full_sha_only_and_no_ref_names(self):
        for value in ("main", "HEAD", "abc", "A" * 40, "0" * 39,
                      "0" * 41, "0" * 40 + ":evil", "0" * 40 + "\n"):
            with self.subTest(value=value):
                with self.assertRaises(compose.CompositionHold):
                    compose._sha(value)
        self.assertEqual(compose._sha("a" * 40), "a" * 40)

    def test_unknown_mode_fails_before_any_git_or_network(self):
        with patch.object(compose, "_git") as git:
            with self.assertRaises(compose.CompositionHold):
                compose.verify(Path.cwd(), "a" * 40, "release")
            git.assert_not_called()

    def test_noncanonical_owner_path_rejected(self):
        for path in ("../escape", "tests/../escape", "/tmp/escape", "a\\b"):
            with self.subTest(path=path):
                with patch.object(compose, "_git") as git:
                    with self.assertRaises(compose.CompositionHold):
                        compose._owner_blob(Path.cwd(), path, "a" * 40, "b" * 40)
                    git.assert_not_called()

    def test_pin_tree_entry_mismatch_denied(self):
        with patch.object(compose, "_git", return_value=b"100644 blob fake\tfile\n"):
            with self.assertRaisesRegex(compose.CompositionHold, "owner tree"):
                compose._owner_blob(Path.cwd(), "file", "a" * 40, "b" * 40)

    def test_pin_blob_bytes_mismatch_denied(self):
        path = "a/file.py"
        pinned = "a" * 40
        tree = f"100644 blob {pinned}\t{path}\n".encode()
        with patch.object(compose, "_git", side_effect=[tree, b"wrong bytes"]):
            with self.assertRaisesRegex(compose.CompositionHold, "content mismatch"):
                compose._owner_blob(Path.cwd(), path, "b" * 40, pinned)

    def test_pin_valid_blob_exact_and_binary_safe(self):
        blob = b"\0binary\xff\n"
        pin = compose._blob_oid(blob)
        tree = f"100644 blob {pin}\ta/file.py\n".encode()
        with patch.object(compose, "_git", side_effect=[tree, blob]):
            self.assertEqual(compose._owner_blob(
                Path.cwd(), "a/file.py", "b" * 40, pin), blob)

    def test_failed_git_omits_internal_stderr(self):
        failure = subprocess.CompletedProcess(
            args=["git"], returncode=128, stdout=b"",
            stderr=b"private-token-must-not-leak")
        with patch.object(compose.subprocess, "run", return_value=failure):
            with self.assertRaises(compose.CompositionHold) as error:
                compose._git(Path.cwd(), "show", "a" * 40)
            self.assertNotIn("private-token", str(error.exception))

    def test_git_uses_no_replace_refs_and_no_prompt(self):
        completed = subprocess.CompletedProcess(
            args=["git"], returncode=0, stdout=b"safe", stderr=b"")
        with patch.object(compose.subprocess, "run", return_value=completed) as run:
            self.assertEqual(compose._git(Path.cwd(), "rev-parse", "HEAD"), b"safe")
            env = run.call_args.kwargs["env"]
            self.assertEqual(env["GIT_NO_REPLACE_OBJECTS"], "1")
            self.assertEqual(env["GIT_TERMINAL_PROMPT"], "0")
            self.assertEqual(env["GIT_OPTIONAL_LOCKS"], "0")

    def test_test_runner_failed_exit_holds_even_with_ok_message(self):
        failed = subprocess.CompletedProcess(
            args=[], returncode=3, stdout=b"Ran 3 tests in 0.01s\nOK\n", stderr=b"")
        with patch.object(compose.subprocess, "run", return_value=failed):
            with self.assertRaisesRegex(compose.CompositionHold, "offline tests failed"):
                compose._run_tests(Path.cwd(), "synthetic", ["-s", "tests", "-q"])

    def test_test_runner_missing_summary_holds(self):
        quiet = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=b"OK\n", stderr=b"")
        with patch.object(compose.subprocess, "run", return_value=quiet):
            with self.assertRaises(compose.CompositionHold):
                compose._run_tests(Path.cwd(), "synthetic", ["-s", "tests"])

    def test_test_runner_records_known_red_debt(self):
        good = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout=b"\nRan 13 tests in 0.01s\n\nOK (expected failures=4)\n", stderr=b"")
        with patch.object(compose.subprocess, "run", return_value=good):
            r = compose._run_tests(Path.cwd(), "synthetic", ["-s", "tests"])
            self.assertEqual((r["methods"], r["expected_source_failures"]), (13, 4))

    @staticmethod
    def good_guard_receipt():
        return {
            "status": "HOLD", "release_authorized": False,
            "candidate_compatibility": "PASS", "duplicates_denied_prebody": 9,
            "public_login_denied_prebody": True,
            "single_session_controls_passed": 3,
            "session_lookup_or_write_before_denial": False,
            "real_target_io_performed": False,
        }

    def test_guard_probe_good_receipt_stays_non_authorizing(self):
        good = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps(self.good_guard_receipt()).encode(),
            stderr=b"")
        with patch.object(compose.subprocess, "run", return_value=good):
            self.assertIs(compose._probe_guard(Path.cwd())["release_authorized"], False)

    def test_guard_probe_rejects_unsafe_or_partial_claims(self):
        mutations = (
            {"status": "GO"},
            {"release_authorized": True},
            {"candidate_compatibility": "UNKNOWN"},
            {"duplicates_denied_prebody": 8},
            {"public_login_denied_prebody": False},
            {"single_session_controls_passed": 2},
            {"session_lookup_or_write_before_denial": True},
            {"real_target_io_performed": True},
        )
        for change in mutations:
            with self.subTest(changed_field=change):
                forged = self.good_guard_receipt() | change
                completed = subprocess.CompletedProcess(
                    args=[], returncode=0,
                    stdout=json.dumps(forged).encode(), stderr=b"")
                with patch.object(compose.subprocess, "run", return_value=completed):
                    with self.assertRaises(compose.CompositionHold):
                        compose._probe_guard(Path.cwd())

    def test_guard_probe_non_json_and_failure_denied(self):
        for rc, payload in ((1, b"{}"), (0, b"not json")):
            with self.subTest(returncode=rc):
                completed = subprocess.CompletedProcess(
                    args=[], returncode=rc, stdout=payload, stderr=b"")
                with patch.object(compose.subprocess, "run", return_value=completed):
                    with self.assertRaises(compose.CompositionHold):
                        compose._probe_guard(Path.cwd())

    def test_main_bad_sha_emits_json_hold_nonzero(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = compose.main(["--head", "not-a-SHA", "--source", str(Path.cwd())])
        self.assertEqual(code, 2)
        receipt = json.loads(out.getvalue())
        self.assertEqual(receipt["status"], "HOLD")
        self.assertIs(receipt["release_authorized"], False)
        self.assertIs(receipt["real_target_interaction_authorized"], False)
        self.assertEqual(receipt["candidate_compatibility"], "FAIL")

    def test_dirty_checkout_never_cloned(self):
        head = "a" * 40
        repo = Path.cwd().resolve()
        stdout = [str(repo).encode() + b"\n", head.encode() + b"\n", b" M danger.py\n"]
        with (patch.object(compose, "_git", side_effect=stdout) as git,
              patch.object(compose.subprocess, "run") as run):
            with self.assertRaisesRegex(compose.CompositionHold, "not clean"):
                compose.verify(repo, head, "smoke")
            self.assertEqual(git.call_count, 3)
            run.assert_not_called()

    def test_wrong_source_head_never_cloned(self):
        head = "a" * 40
        repo = Path.cwd().resolve()
        stdout = [str(repo).encode() + b"\n", b"b" * 40 + b"\n"]
        with (patch.object(compose, "_git", side_effect=stdout),
              patch.object(compose.subprocess, "run") as run):
            with self.assertRaisesRegex(compose.CompositionHold, "HEAD differs"):
                compose.verify(repo, head, "smoke")
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
