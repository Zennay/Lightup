"""Offline Git object-identity regression: replacement refs must not be trusted.

This acceptance oracle is not a LightUp runtime authorizer or approval gate.
It modifies only disposable repositories; never targets, grants, or networks.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class GitReplaceRefBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="lightup-git-replace-")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.git("init", "-q")
        self.git("config", "user.name", "Offline Fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.write("src/lightup/protected.py", "BASE = True\n")
        self.git("add", "-A")
        self.git("commit", "-qm", "base fixture")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.write("src/lightup/protected.py", "BASE = False\n")
        self.unsafe = self.commit("unsafe original")
        self.git("checkout", "-q", "-b", "benign", self.base)
        self.write("tests/test_scope_synthetic.py", "SYNTHETIC = True\n")
        self.benign = self.commit("benign alternative")
        self.git("replace", self.unsafe, self.benign)

    def git(self, *args: str, disable_replace: bool = False) -> str:
        env = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
        if disable_replace:
            env["GIT_NO_REPLACE_OBJECTS"] = "1"
        else:
            env.pop("GIT_NO_REPLACE_OBJECTS", None)
        result = subprocess.run(["git", *args], cwd=self.repo, env=env,
                                capture_output=True, text=True, timeout=10, check=True)
        return result.stdout

    def write(self, name: str, value: str):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8")

    def commit(self, message: str) -> str:
        self.git("add", "-A")
        self.git("commit", "-qm", message)
        return self.git("rev-parse", "HEAD").strip()

    def test_replace_ref_hides_transient_production_edit_in_default_git_diff(self):
        apparent = self.git("diff", "--name-only", self.base, self.unsafe, "--").splitlines()
        actual = self.git("diff", "--name-only", self.base, self.unsafe, "--",
                          disable_replace=True).splitlines()
        self.assertEqual(apparent, ["tests/test_scope_synthetic.py"])
        self.assertEqual(actual, ["src/lightup/protected.py"])

    def test_exact_immutable_commit_sha_does_not_imply_immutable_git_tree_with_replace_ref(self):
        self.assertEqual(self.git("rev-parse", self.unsafe).strip(), self.unsafe)
        apparent = self.git("ls-tree", "-r", "--name-only", self.unsafe).splitlines()
        actual = self.git("ls-tree", "-r", "--name-only", self.unsafe,
                          disable_replace=True).splitlines()
        self.assertIn("tests/test_scope_synthetic.py", apparent)
        self.assertNotIn("tests/test_scope_synthetic.py", actual)
        self.assertIn("src/lightup/protected.py", actual)

    def test_disabling_replace_refs_preserves_real_original_commit_content(self):
        apparent = self.git("show", f"{self.unsafe}:src/lightup/protected.py")
        actual = self.git("show", f"{self.unsafe}:src/lightup/protected.py",
                          disable_replace=True)
        self.assertEqual(apparent, "BASE = True\n")
        self.assertEqual(actual, "BASE = False\n")

    def test_replace_ref_is_repository_local_not_required_to_be_inherited_from_environment(self):
        listing = self.git("for-each-ref", "--format=%(refname)", "refs/replace").splitlines()
        self.assertEqual(listing, [f"refs/replace/{self.unsafe}"])
        self.assertNotIn("GIT_REPLACE_REF_BASE", os.environ)
        self.assertEqual(self.git("diff", "--name-only", self.base, self.unsafe).strip(),
                         "tests/test_scope_synthetic.py")
        self.assertEqual(self.git("diff", "--name-only", self.base, self.unsafe,
                                  disable_replace=True).strip(), "src/lightup/protected.py")

    def test_original_object_still_accessible_without_removing_local_replace_ref(self):
        self.assertEqual(self.git("show", "--format=%s", "-s", self.unsafe,
                                  disable_replace=True).strip(), "unsafe original")
        self.assertEqual(self.git("show", "--format=%s", "-s", self.unsafe).strip(),
                         "benign alternative")
        listing = self.git("for-each-ref", "--format=%(refname)", "refs/replace").strip()
        self.assertTrue(listing.endswith(self.unsafe))


if __name__ == "__main__":
    unittest.main()
