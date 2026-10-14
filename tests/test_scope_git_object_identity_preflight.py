"""Disposable local Git acceptance for the negative-only identity preflight."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from check_scope_git_object_identity_preflight import inspect, main


class ScopeGitObjectIdentityPreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="scope-git-identity-")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.git("init", "-q")
        self.git("config", "user.name", "Synthetic")
        self.git("config", "user.email", "synthetic@example.invalid")
        (self.repo / "a.txt").write_text("safe\n")
        self.git("add", "-A")
        self.git("commit", "-qm", "base")
        self.base = self.git("rev-parse", "HEAD").strip()
        (self.repo / "a.txt").write_text("changed\n")
        self.git("add", "-A")
        self.git("commit", "-qm", "head")
        self.head = self.git("rev-parse", "HEAD").strip()

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.repo, check=True,
                              capture_output=True, text=True, timeout=10).stdout

    def test_clean_disposable_git_is_review_only_never_authorizing(self):
        self.assertEqual(inspect(self.repo), "NO_LOCAL_GIT_SUBSTITUTION_OBSERVED")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main(["--repo", str(self.repo)])
        payload = json.loads(out.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(payload["status"], "REVIEW_ONLY")
        for key in ("authorization_verified", "permit_issued",
                    "execution_enabled", "merge_approved", "release_approved"):
            self.assertIs(payload[key], False)

    def test_replace_ref_is_denied_without_mutating_it(self):
        self.git("replace", self.head, self.base)
        self.assertEqual(inspect(self.repo), "LOCAL_REPLACE_REF_PRESENT")
        self.assertEqual(self.git("for-each-ref", "--format=%(refname)",
                                  "refs/replace").strip(), "refs/replace/" + self.head)

    def test_packed_replace_ref_is_denied_after_loose_ref_prune(self):
        self.git("replace", self.head, self.base)
        self.git("pack-refs", "--all", "--prune")
        self.assertEqual(inspect(self.repo), "LOCAL_REPLACE_REF_PRESENT")
        self.assertIn("refs/replace/" + self.head,
                      self.git("for-each-ref", "--format=%(refname)", "refs/replace"))

    def test_dangling_grafts_symlink_is_refused_conservatively(self):
        graft = self.repo / ".git" / "info" / "grafts"
        graft.symlink_to(self.repo / "nonexistent-graft-payload")
        self.assertEqual(inspect(self.repo), "LEGACY_GRAFT_PRESENT")

    def test_grafts_are_denied_even_without_replace_refs(self):
        graft = self.repo / ".git" / "info" / "grafts"
        graft.write_text(self.head + "\n", encoding="ascii")
        self.assertEqual(inspect(self.repo), "LEGACY_GRAFT_PRESENT")
        self.assertTrue(graft.is_file())

    def test_empty_grafts_file_is_conservatively_held(self):
        graft = self.repo / ".git" / "info" / "grafts"
        graft.touch()
        self.assertEqual(inspect(self.repo), "LEGACY_GRAFT_PRESENT")

    def test_nested_repository_directory_is_not_mistaken_for_root(self):
        sub = self.repo / "nested"
        sub.mkdir()
        self.assertEqual(inspect(sub), "INVALID_REPOSITORY_ROOT")

    def test_inherited_git_environment_cannot_redirect_repository(self):
        with mock.patch.dict(os.environ, {"GIT_DIR": "/does/not/exist",
                                           "GIT_WORK_TREE": "/does/not/exist",
                                           "GIT_NO_REPLACE_OBJECTS": "0"}):
            self.assertEqual(inspect(self.repo), "NO_LOCAL_GIT_SUBSTITUTION_OBSERVED")

    def test_missing_git_or_failed_subprocess_returns_hold(self):
        with mock.patch("check_scope_git_object_identity_preflight.subprocess.run",
                        side_effect=FileNotFoundError):
            self.assertEqual(inspect(self.repo), "INVALID_REPOSITORY_ROOT")


if __name__ == "__main__":
    unittest.main()
