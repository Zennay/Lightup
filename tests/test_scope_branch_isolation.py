"""Isolated disposable Git fixture tests; never import LightUp production code."""
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

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
from check_scope_branch_isolation import inspect, main


class IsolationCheckTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        self.git("init", "-q")
        self.git("config", "user.name", "Synthetic")
        self.git("config", "user.email", "synthetic@example.invalid")
        self.write("src/lightup/scope.py", "ORIGINAL = True\n")
        self.git("add", ".")
        self.git("commit", "-qm", "base")
        self.base = self.sha()

    def git(self, *args):
        return subprocess.run(("git", *args), cwd=self.repo, check=True,
                              capture_output=True).stdout.decode().strip()

    def sha(self):
        return self.git("rev-parse", "HEAD")

    def write(self, path, text):
        dst = self.repo / path
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(text)

    def commit(self):
        self.git("add", "-A")
        self.git("commit", "-qm", "synthetic")
        return self.sha()

    def test_add_only_owned_paths_are_reviewable_but_never_authorize(self):
        files = ("tests/test_scope_synthetic_review.py", "docs/scope-synthetic-review.md")
        for path in files:
            self.write(path, "synthetic content\n")
        head = self.commit()
        self.assertEqual(inspect(self.repo, self.base, head, files), ("ADDITIVE_PATHS_MATCH", 2))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["--repo", str(self.repo), "--base", self.base,
                         "--head", head, "--allow", files[0], "--allow", files[1]])
        receipt = json.loads(output.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(receipt["status"], "REVIEW_ONLY")
        for key in ("authorization_verified", "permit_issued", "execution_enabled",
                    "merge_approved", "release_approved"):
            self.assertIs(receipt[key], False)

    def test_original_source_change_denied(self):
        self.write("src/lightup/scope.py", "ORIGINAL = False\n")
        head = self.commit()
        self.assertEqual(inspect(self.repo, self.base, head,
                         ("tests/test_scope_synthetic_review.py",))[0], "PREEXISTING_PATH_CHANGED")

    def test_unowned_ci_workflow_denied(self):
        self.write(".github/workflows/ci.yml", "name: synthetic\n")
        head = self.commit()
        self.assertEqual(inspect(self.repo, self.base, head,
                         ("tests/test_scope_synthetic_review.py",))[0], "UNOWNED_OR_DUPLICATE_PATH")

    def test_missing_manifest_path_denied(self):
        self.write("tests/test_scope_synthetic_review.py", "x=1\n")
        head = self.commit()
        self.assertEqual(inspect(self.repo, self.base, head,
                         ("docs/scope-synthetic-review.md",))[0], "OWNERSHIP_MANIFEST_MISMATCH")

    def test_extra_manifest_path_denied(self):
        self.write("tests/test_scope_synthetic_review.py", "x=1\n")
        self.write("docs/scope-synthetic-review.md", "ok\n")
        head = self.commit()
        self.assertEqual(inspect(self.repo, self.base, head,
                         ("tests/test_scope_synthetic_review.py",))[0], "OWNERSHIP_MANIFEST_MISMATCH")

    def test_symlink_denied(self):
        link = self.repo / "tests/test_scope_synthetic_review.py"
        link.parent.mkdir(parents=True)
        link.symlink_to("../src/lightup/scope.py")
        head = self.commit()
        self.assertEqual(inspect(self.repo, self.base, head,
                         ("tests/test_scope_synthetic_review.py",))[0], "UNSAFE_TREE_MODE")

    def test_executable_blob_denied(self):
        path = "scripts/check_scope_synthetic_review.py"
        self.write(path, "print('synthetic')\n")
        (self.repo / path).chmod(0o755)
        head = self.commit()
        self.assertEqual(inspect(self.repo, self.base, head, (path,))[0], "UNSAFE_TREE_MODE")

    def test_invalid_sha_and_path_manifests_denied(self):
        self.assertEqual(inspect(self.repo, "main", self.base,
                         ("tests/test_scope_synthetic_review.py",))[0], "INVALID_IMMUTABLE_REFS")
        self.write("tests/test_scope_synthetic_review.py", "test\n")
        head = self.commit()
        for paths in (("../src/lightup/scope.py",), ("src/lightup/scope.py",),
                      ("tests/test_scope_synthetic_review.py",) * 2):
            self.assertEqual(inspect(self.repo, self.base, head, paths)[0],
                             "INVALID_OWNERSHIP_MANIFEST")

    def test_non_ancestor_head_denied(self):
        self.write("tests/test_scope_synthetic_review.py", "test\n")
        head = self.commit()
        self.git("checkout", "-q", self.base)
        self.write("docs/scope-synthetic-review.md", "other\n")
        other = self.commit()
        self.assertEqual(inspect(self.repo, head, other,
                         ("docs/scope-synthetic-review.md",))[0], "NON_DESCENDANT_HEAD")

    def test_whitespace_defect_denied(self):
        self.write("tests/test_scope_synthetic_review.py", "bad trailing space \n")
        head = self.commit()
        self.assertEqual(inspect(self.repo, self.base, head,
                         ("tests/test_scope_synthetic_review.py",))[0], "PATCH_CHECK_FAILED")


    def test_peer_new_file_collision_rejected(self):
        path = "tests/test_scope_synthetic_review.py"
        self.write(path, "owned\n")
        head = self.commit()
        self.git("checkout", "-qb", "peer", self.base)
        self.write(path, "other worker\n")
        peer = self.commit()
        self.assertEqual(inspect(self.repo, self.base, head, (path,), (peer,))[0],
                         "PEER_PATH_COLLISION")

    def test_disjoint_peer_does_not_grant_release(self):
        path = "tests/test_scope_synthetic_review.py"
        self.write(path, "owned\n")
        head = self.commit()
        self.git("checkout", "-qb", "peer", self.base)
        self.write("docs/scope-other-worker.md", "different\n")
        peer = self.commit()
        self.assertEqual(inspect(self.repo, self.base, head, (path,), (peer,)),
                         ("ADDITIVE_PATHS_MATCH", 1))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main(["--repo", str(self.repo), "--base", self.base,
                         "--head", head, "--allow", path, "--peer", peer])
        self.assertEqual(code, 0)
        receipt = json.loads(out.getvalue())
        self.assertEqual(receipt["peer_heads_checked"], 1)
        self.assertIs(receipt["release_approved"], False)

    def test_untrusted_peer_metadata_rejected(self):
        path = "tests/test_scope_synthetic_review.py"
        self.write(path, "owned\n")
        head = self.commit()
        for peer in ("main", self.base, head):
            self.assertEqual(inspect(self.repo, self.base, head, (path,), (peer,))[0],
                             "INVALID_PEER_REFS")


    def test_missing_git_binary_fails_closed(self):
        path = "tests/test_scope_synthetic_review.py"
        self.write(path, "synthetic\n")
        head = self.commit()
        with mock.patch("check_scope_branch_isolation.subprocess.run",
                        side_effect=FileNotFoundError):
            self.assertEqual(inspect(self.repo, self.base, head, (path,))[0],
                             "INVALID_REPOSITORY_ROOT")

    def test_missing_peer_commit_fails_closed(self):
        path = "tests/test_scope_synthetic_review.py"
        self.write(path, "synthetic\n")
        head = self.commit()
        self.assertEqual(inspect(self.repo, self.base, head, (path,), ("f" * 40,))[0],
                         "MISSING_PEER_COMMIT")

    def test_nested_directory_is_not_accepted_as_repository_root(self):
        path = "tests/test_scope_synthetic_review.py"
        self.write(path, "safe\\n")
        head = self.commit()
        nested = self.repo / "nested"
        nested.mkdir()
        self.assertEqual(inspect(nested, self.base, head, (path,))[0],
                         "INVALID_REPOSITORY_ROOT")

    def test_inherited_git_redirects_are_ignored(self):
        path = "tests/test_scope_synthetic_review.py"
        self.write(path, "safe\\n")
        head = self.commit()
        with mock.patch.dict(os.environ, {
            "GIT_DIR": str(self.repo / "nonexistent-attacker-gitdir"),
            "GIT_WORK_TREE": "/does-not-exist",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.whitespace",
            "GIT_CONFIG_VALUE_0": "-trailing-space",
        }):
            self.assertEqual(inspect(self.repo, self.base, head, (path,)),
                             ("ADDITIVE_PATHS_MATCH", 1))

    def test_local_whitespace_policy_cannot_disable_trailing_check(self):
        self.git("config", "core.whitespace", "-trailing-space")
        path = "tests/test_scope_synthetic_review.py"
        self.write(path, "bad trailing space \\n")
        head = self.commit()
        self.assertEqual(inspect(self.repo, self.base, head, (path,))[0],
                         "PATCH_CHECK_FAILED")

    def test_denied_receipt_does_not_claim_peers_checked(self):
        path = "tests/test_scope_synthetic_review.py"
        self.write(path, "safe\\n")
        head = self.commit()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exit_code = main(["--repo", str(self.repo), "--base", self.base,
                              "--head", head, "--allow", path, "--peer", "f" * 40])
        receipt = json.loads(output.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertEqual(receipt["status"], "HOLD")
        self.assertEqual(receipt["peer_heads_submitted"], 1)
        self.assertEqual(receipt["peer_heads_checked"], 0)
        for key in ("authorization_verified", "permit_issued", "execution_enabled",
                    "merge_approved", "release_approved"):
            self.assertIs(receipt[key], False)

    def test_git_timeout_fails_closed(self):
        path = "tests/test_scope_synthetic_review.py"
        self.write(path, "safe\\n")
        head = self.commit()
        with mock.patch("check_scope_branch_isolation.subprocess.run",
                        side_effect=subprocess.TimeoutExpired(["git"], 20)):
            self.assertEqual(inspect(self.repo, self.base, head, (path,))[0],
                             "INVALID_REPOSITORY_ROOT")


if __name__ == "__main__":
    unittest.main()
