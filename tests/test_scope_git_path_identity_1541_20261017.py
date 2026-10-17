"""Owner-isolated source acceptance for #1541 / draft #1538 Git path identity.

All repositories and Git objects are fictional, made locally under TemporaryDirectory.
The three expected failures are *known original-source defects*, not green
production evidence. No network, handlers, target, consent or release operation.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lightup.git_changes import GitChangeError, collect_git_range


class GitChangePathIdentityAcceptance(unittest.TestCase):
    def setUp(self):
        self.sandbox = tempfile.TemporaryDirectory(prefix="scope1541-git-")
        self.addCleanup(self.sandbox.cleanup)
        self.repo = Path(self.sandbox.name) / "fictional"
        self.repo.mkdir()
        self.hooks = Path(self.sandbox.name) / "no-hooks"
        self.hooks.mkdir()
        self.env = {
            **os.environ,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
        }
        self.git("init", "-q")
        self.git("config", "user.name", "Offline Fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("config", "core.hooksPath", str(self.hooks))
        self.git("config", "core.quotePath", "true")
        self.git("config", "core.fsmonitor", "false")

    def git(self, *args):
        completed = subprocess.run(
            ["git", "-C", str(self.repo), *args],
            env=self.env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        self.assertEqual(
            completed.returncode, 0,
            "local synthetic git fixture failed (stderr suppressed)",
        )
        return completed.stdout.decode("ascii", "strict").strip()

    def write_file(self, name: bytes, content: bytes) -> None:
        with open(os.fsencode(self.repo) + b"/" + name, "wb") as handle:
            handle.write(content)

    def create_change(self, names: tuple[bytes, ...]) -> tuple[str, str]:
        for name in names:
            self.write_file(name, b"safe = 1\n")
        self.git("add", "-A")
        self.git("commit", "-qm", "fixture initial")
        base = self.git("rev-parse", "HEAD")
        for name in names:
            self.write_file(name, b"safe = 2\n")
        self.git("add", "-A")
        self.git("commit", "-qm", "fixture changed")
        return base, self.git("rev-parse", "HEAD")

    def review(self, base: str, head: str):
        with patch.dict(os.environ, self.env, clear=True):
            return collect_git_range(
                self.repo, base, head, repository="offline/fictional",
                merge_base=False,
            )

    def assert_full_single_file(self, name: str) -> None:
        base, head = self.create_change((name.encode("utf-8"),))
        result = self.review(base, head)
        self.assertEqual(len(result.files), 1)
        item = result.files[0]
        self.assertEqual(item["filename"], name)
        self.assertEqual((item["additions"], item["deletions"]), (1, 1))
        self.assertIsInstance(item["patch"], str)
        self.assertIn("+safe = 2", item["patch"])

    def test_ascii_diff_keeps_patch(self):
        self.assert_full_single_file("normal.py")

    def test_two_ascii_paths_remain_distinct(self):
        base, head = self.create_change((b"first.py", b"second.py"))
        result = self.review(base, head)
        self.assertEqual({item["filename"] for item in result.files},
                         {"first.py", "second.py"})
        self.assertTrue(all(item["patch"] and "+safe = 2" in item["patch"]
                            for item in result.files))

    def test_unicode_with_quotepath_disabled_keeps_patch_control(self):
        self.git("config", "core.quotePath", "false")
        self.assert_full_single_file("café.py")

    @unittest.expectedFailure
    def test_red_canonical_unicode_path_must_keep_patch_with_default_git_quoting(self):
        self.assert_full_single_file("café.py")

    @unittest.expectedFailure
    def test_red_tab_in_path_must_not_silently_drop_changed_patch(self):
        self.assert_full_single_file("name\tpart.py")

    @unittest.expectedFailure
    @unittest.skipUnless(os.name == "posix", "byte path fixture requires POSIX")
    def test_red_distinct_undecodable_paths_must_hold_before_any_review(self):
        names = (b"\xfe.py", b"\xff.py")
        base, head = self.create_change(names)
        with self.assertRaises(
            GitChangeError,
            msg="distinct invalid UTF-8 paths must never collapse to replacement alias",
        ):
            self.review(base, head)



class SourceRedIntegrityTests(unittest.TestCase):
    RED_METHODS = (
        "test_red_canonical_unicode_path_must_keep_patch_with_default_git_quoting",
        "test_red_tab_in_path_must_not_silently_drop_changed_patch",
        "test_red_distinct_undecodable_paths_must_hold_before_any_review",
    )

    def test_original_defects_are_three_real_assertion_failures_not_masked_errors(self):
        for name in self.RED_METHODS:
            self.assertTrue(
                getattr(GitChangePathIdentityAcceptance.__dict__[name],
                        "__unittest_expecting_failure__", False),
                name,
            )
        result = unittest.TestResult()
        unittest.TestSuite(
            [GitChangePathIdentityAcceptance(name) for name in self.RED_METHODS]
        ).run(result)
        self.assertEqual(result.testsRun, len(self.RED_METHODS))
        self.assertEqual(len(result.expectedFailures), len(self.RED_METHODS))
        self.assertFalse(result.errors)
        self.assertFalse(result.failures)
        self.assertFalse(result.unexpectedSuccesses)
        for _case, traceback in result.expectedFailures:
            self.assertIn("AssertionError:", traceback)
            self.assertNotIn("TypeError:", traceback)
            self.assertNotIn("OSError:", traceback)
            self.assertNotIn("ImportError:", traceback)

if __name__ == "__main__":
    unittest.main()
