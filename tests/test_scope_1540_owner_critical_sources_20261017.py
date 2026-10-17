"""#1540 fail-closed critical source paths independent of caller-owned allowlists."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "review_scope_worker_ownership_offline_1540.py"
SPEC = importlib.util.spec_from_file_location("scope1540_critical_paths", SCRIPT)
owner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(owner)

FIXTURE = ROOT / "examples" / "scope1540-owner-review-only.json"


def canonical(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


class CriticalSourceProtectionTests(unittest.TestCase):
    def setUp(self):
        self.doc = json.loads(FIXTURE.read_text())

    def test_benign_synthetic_fixture_still_review_only(self):
        self.assertEqual(owner.check(canonical(self.doc)), "REVIEW_ONLY")

    def test_core_application_tree_is_always_held(self):
        for changed in ("src/lightup/new_scope.py", "src/lightup", "SRC/LIGHTUP/domain.py",
                        "src/lightup/security/permissions.py", "src/LIGHTUP/scopes.py"):
            with self.subTest(changed=changed):
                d = json.loads(json.dumps(self.doc))
                d["reviews"][1]["compare"]["files"][0]["filename"] = changed
                d["ownership"][1]["paths"][0] = changed
                # Caller deliberately omits core source from its protected inventory.
                d["protected_paths"] = ["noncritical/placeholder.txt"]
                self.assertEqual(owner.check(canonical(d)), "HOLD")

    def test_github_actions_and_workflows_are_always_held(self):
        for changed in (".github/workflows/scope.yml", ".github/actions/deploy/action.yml",
                        ".github/CODEOWNERS", ".GITHUB/workflows/ci.yml",
                        ".github", ".github/ISSUE_TEMPLATE/new.md"):
            with self.subTest(changed=changed):
                d = json.loads(json.dumps(self.doc))
                d["reviews"][1]["compare"]["files"][0]["filename"] = changed
                d["ownership"][1]["paths"][0] = changed
                d["protected_paths"] = ["unrelated/path.md"]
                self.assertEqual(owner.check(canonical(d)), "HOLD")

    def test_build_and_release_metadata_is_always_held(self):
        for changed in ("pyproject.toml", "setup.py", "setup.cfg", "tox.ini",
                        "uv.lock", "poetry.lock", "requirements.txt",
                        "Dockerfile", "Makefile", ".pre-commit-config.yaml",
                        "PYPROJECT.TOML"):
            with self.subTest(changed=changed):
                d = json.loads(json.dumps(self.doc))
                d["reviews"][1]["compare"]["files"][0]["filename"] = changed
                d["ownership"][1]["paths"][0] = changed
                d["protected_paths"] = ["not/really/security.txt"]
                self.assertEqual(owner.check(canonical(d)), "HOLD")

    def test_sibling_paths_not_false_positive(self):
        for changed in ("src/lightup_fake/my_review.py", ".github2/example.txt",
                        "pyproject.toml.backup", "tests/test_restricted.py"):
            with self.subTest(changed=changed):
                d = json.loads(json.dumps(self.doc))
                d["reviews"][1]["compare"]["files"][0]["filename"] = changed
                d["ownership"][1]["paths"][0] = changed
                d["protected_paths"] = ["other/safe_file.py"]
                self.assertEqual(owner.check(canonical(d)), "REVIEW_ONLY")

    def test_caller_cannot_override_critical_source_for_rename_from_path(self):
        d = json.loads(json.dumps(self.doc))
        d["reviews"][0]["compare"]["files"][0]["previous_filename"] = ".github/workflows/release.yml"
        d["ownership"][0]["paths"][1] = ".github/workflows/release.yml"
        d["protected_paths"] = ["some/other/path.md"]
        self.assertEqual(owner.check(canonical(d)), "HOLD")

    def test_executable_holds_silent_critical_workflow_even_with_matching_owner(self):
        d = json.loads(json.dumps(self.doc))
        d["reviews"][1]["compare"]["files"][0]["filename"] = ".github/workflows/deploy.yml"
        d["ownership"][1]["paths"][0] = ".github/workflows/deploy.yml"
        d["protected_paths"] = ["unrelated/foo.md"]
        p = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT)],
                           input=canonical(d), capture_output=True, timeout=8)
        self.assertEqual(p.returncode, 2, p.stderr)
        self.assertEqual(p.stderr, b"")
        receipt = json.loads(p.stdout)
        self.assertEqual(receipt["status"], "HOLD")
        self.assertEqual(set(receipt), {"status", *owner.review.FLAGS})
        self.assertTrue(all(receipt[k] is False for k in owner.review.FLAGS))
        self.assertNotIn(b"deploy.yml", p.stdout)

    def test_caller_cannot_change_builtin_policy_by_mutating_proposals(self):
        d = json.loads(json.dumps(self.doc))
        d["protected_paths"] = ["another/doc.md"]
        d["ownership"][1]["paths"][0] = "SRC/LIGHTUP/critical.py"
        d["reviews"][1]["compare"]["files"][0]["filename"] = "SRC/LIGHTUP/critical.py"
        with (mock.patch("socket.socket", side_effect=AssertionError("network")),
              mock.patch("subprocess.run", side_effect=AssertionError("process"))):
            self.assertEqual(owner.check(canonical(d)), "HOLD")


if __name__ == "__main__":
    unittest.main()
