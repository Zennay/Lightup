"""Read-only native Git -z fixture integration for the isolated #1541 CLI.

Creates only temporary, synthetic local Git repositories with disabled hooks,
no remotes, no targets, no credentials and no production integration.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

CLI = Path(__file__).resolve().parents[1] / "scripts/review_scope_git_path_streams_synthetic_1541.py"
SCHEMA = "lightup.scope_git_paths_synthetic.v1"


@unittest.skipUnless(os.name == "posix", "byte-preserving Git path fixtures use POSIX")
class NativeGitPathStreamCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="lightup1541-native-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name, "repo")
        self.repo.mkdir()
        hooks = Path(self.temp.name, "no-hooks")
        hooks.mkdir()
        self.env = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0",
                    "GIT_NO_REPLACE_OBJECTS": "1"}
        self.git("init", "-q")
        self.git("config", "core.hooksPath", str(hooks))
        self.git("config", "user.name", "Synthetic")
        self.git("config", "user.email", "synthetic@example.invalid")
        self.git("config", "core.quotePath", "true")
        self.git("config", "core.fsmonitor", "false")

    def git(self, *args: str) -> bytes:
        result = subprocess.run(
            ["git", "-C", str(self.repo), *args],
            env=self.env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=10, check=False,
        )
        self.assertEqual(result.returncode, 0, "synthetic Git fixture failure")
        return result.stdout

    def write(self, name: bytes, data: bytes) -> None:
        path = os.fsencode(self.repo) + b"/" + name
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as file:
            file.write(data)

    def commit(self, message: str) -> str:
        self.git("add", "-A")
        self.git("commit", "-qm", message)
        return self.git("rev-parse", "HEAD").strip().decode("ascii")

    def review(self, before: str, after: str, expected: int) -> tuple[bytes, bytes]:
        options = ("-z", "-M", "--no-ext-diff", "--no-textconv",
                   "--no-color", before, after)
        status = self.git("diff", "--name-status", *options)
        numstat = self.git("diff", "--numstat", *options)
        payload = {
            "schema": SCHEMA,
            "synthetic_only": True,
            "status_b64": base64.b64encode(status).decode("ascii"),
            "numstat_b64": base64.b64encode(numstat).decode("ascii"),
        }
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-B", str(CLI)],
            input=raw, capture_output=True, check=False, timeout=10,
        )
        self.assertEqual(result.returncode, expected)
        self.assertEqual(result.stderr, b"")
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["status"], "REVIEW_ONLY" if expected == 3 else "HOLD")
        for name in ("authorized", "consent_verified", "permit_issued",
                     "dispatch_allowed", "execution_allowed", "merge_allowed",
                     "release_allowed"):
            self.assertIs(receipt[name], False)
        self.assertNotIn(b"src/secret", result.stdout)
        return status, numstat

    def test_git_utf8_tab_and_ascii_order_retained(self):
        for name in (b"caf\xc3\xa9\tname.py", b"src/second.py", b"docs/third.txt"):
            self.write(name, b"old = 1\n")
        first = self.commit("synthetic initial")
        for name in (b"caf\xc3\xa9\tname.py", b"src/second.py", b"docs/third.txt"):
            self.write(name, b"new = 2\n")
        second = self.commit("synthetic modify")
        status, num = self.review(first, second, 3)
        self.assertIn(b"caf\xc3\xa9\tname.py", status)
        self.assertIn(b"caf\xc3\xa9\tname.py", num)

    def test_git_true_rename_is_still_reviewable(self):
        self.write(b"before.py", b"common = 2\n")
        first = self.commit("synthetic before")
        os.rename(os.fsencode(self.repo) + b"/before.py",
                  os.fsencode(self.repo) + b"/after.py")
        second = self.commit("synthetic after")
        status, _ = self.review(first, second, 3)
        self.assertIn(b"R100\0", status)

    def test_git_file_to_directory_transition_conservatively_holds(self):
        self.write(b"root", b"legacy\n")
        first = self.commit("synthetic file")
        os.unlink(os.fsencode(self.repo) + b"/root")
        self.write(b"root/nested.py", b"new\n")
        second = self.commit("synthetic directory")
        status, num = self.review(first, second, 2)
        self.assertIn(b"root\0", status)
        self.assertIn(b"root/nested.py", num)

    def test_git_invalid_utf8_path_holds_without_echo(self):
        self.write(b"src/secret\xfe.py", b"one\n")
        first = self.commit("synthetic invalid before")
        self.write(b"src/secret\xfe.py", b"two\n")
        second = self.commit("synthetic invalid after")
        self.review(first, second, 2)

    def test_git_trailing_dot_name_holds_without_echo(self):
        self.write(b"src/secret.", b"one\n")
        first = self.commit("synthetic period before")
        self.write(b"src/secret.", b"two\n")
        second = self.commit("synthetic period after")
        self.review(first, second, 2)


if __name__ == "__main__":
    unittest.main()
