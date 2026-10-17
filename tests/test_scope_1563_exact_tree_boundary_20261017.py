"""Synthetic offline tests for the #1563 immutable ownership gate.

Creates only disposable local Git repositories; no remote or real asset access.
"""
from __future__ import annotations

import importlib.util
import pathlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

MODULE = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "scope_1563_exact_tree_boundary_20261017.py"
spec = importlib.util.spec_from_file_location("scope_1563_exact_tree_gate", MODULE)
assert spec is not None and spec.loader is not None
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class ParseScopeOwnerRecordsTests(unittest.TestCase):
    def test_exact_new_paths(self):
        records = b"".join(
            b"A\0" + path.encode("ascii") + b"\0"
            for path in sorted(gate.ALLOWED_ADDED)
        )
        self.assertEqual(gate.parse_changes(records), gate.ALLOWED_ADDED)

    def test_every_owner_path_is_mandatory(self):
        records = b"".join(
            b"A\0" + path.encode("ascii") + b"\0"
            for path in sorted(gate.ALLOWED_ADDED)[:-1]
        )
        with self.assertRaises(gate.Hold):
            gate.parse_changes(records)

    def test_reject_existing_file_change_and_rename(self):
        for status in (b"M", b"D", b"R100", b"C100", b"X"):
            with self.subTest(status=status), self.assertRaises(gate.Hold):
                gate.parse_changes(status + b"\0" + next(iter(gate.ALLOWED_ADDED)).encode() + b"\0")

    def test_reject_duplicate_or_unowned_path(self):
        p = next(iter(gate.ALLOWED_ADDED)).encode("ascii")
        for data in (
            b"A\0" + p + b"\0A\0" + p + b"\0",
            b"A\0src/lightup/scope.py\0",
            b"A\0.github/workflows/other-worker.yml\0",
        ):
            with self.subTest(data=data), self.assertRaises(gate.Hold):
                gate.parse_changes(data)

    def test_reject_broken_utf8_alias_or_partial_records(self):
        for data in (
            b"",
            b"A\0a",
            b"A\0",
            b"A\0tests/\xc3\xa9vil.py\0",
            b"A\0../../src/lightup/scope.py\0",
        ):
            with self.subTest(data=data), self.assertRaises(gate.Hold):
                gate.parse_changes(data)


class TemporaryOwnerTreeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="scope-1563-tree-fixture-")
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self._git("init", "-q")
        self._write("README.md", "base")
        self._git("add", "README.md")
        self._git("-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-q", "-m", "base")
        self.base = self._git("rev-parse", "HEAD")
        self.original = gate.ORIGINAL_BASE
        gate.ORIGINAL_BASE = self.base
        self.addCleanup(setattr, gate, "ORIGINAL_BASE", self.original)

    def _git(self, *args):
        result = subprocess.run(
            ("git", *args), cwd=self.root, check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
        )
        return result.stdout.decode("ascii").strip()

    def _write(self, name, content):
        p = self.root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")

    def _commit(self):
        self._git("add", "-A")
        self._git("-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-q", "-m", "proposed")
        return self._git("rev-parse", "HEAD")

    def _build_owned(self):
        for name in gate.ALLOWED_ADDED:
            self._write(name, "synthetic fixture")
        return self._commit()

    def test_exact_additive_tree_is_review_only(self):
        head = self._build_owned()
        result = gate.inspect_exact_head(self.root, head)
        self.assertEqual(result["decision"], "REVIEW_ONLY")
        self.assertEqual(result["added_paths"], len(gate.ALLOWED_ADDED))
        self.assertIs(result["authorization_granted"], False)
        self.assertIs(result["release_approved"], False)

    def test_reject_source_change_even_with_all_expected_new_paths(self):
        self._write("README.md", "modified original file")
        head = self._build_owned()
        with self.assertRaises(gate.Hold):
            gate.inspect_exact_head(self.root, head)

    def test_reject_missing_file_or_wrong_exact_head(self):
        names = sorted(gate.ALLOWED_ADDED)
        for name in names[:-1]:
            self._write(name, "synthetic fixture")
        head = self._commit()
        with self.assertRaises(gate.Hold):
            gate.inspect_exact_head(self.root, head)
        with self.assertRaises(gate.Hold):
            gate.inspect_exact_head(self.root, self.base)

    def test_reject_symlink_in_owned_path(self):
        names = sorted(gate.ALLOWED_ADDED)
        for name in names[:-1]:
            self._write(name, "synthetic fixture")
        target = self.root / names[-1]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.symlink_to(self.root / "README.md")
        head = self._commit()
        with self.assertRaises(gate.Hold):
            gate.inspect_exact_head(self.root, head)


    def test_source_only_second_commit_still_holds(self):
        valid_head = self._build_owned()
        self.assertEqual(gate.inspect_exact_head(self.root, valid_head)["decision"], "REVIEW_ONLY")
        self._write("README.md", "malicious source-only follow-up")
        forbidden_head = self._commit()
        with self.assertRaises(gate.Hold):
            gate.inspect_exact_head(self.root, forbidden_head)

    def test_executable_mode_on_new_owned_file_holds(self):
        valid_head = self._build_owned()
        self.assertEqual(gate.inspect_exact_head(self.root, valid_head)["decision"], "REVIEW_ONLY")
        path = self.root / sorted(gate.ALLOWED_ADDED)[0]
        path.chmod(0o755)
        forbidden_head = self._commit()
        with self.assertRaises(gate.Hold):
            gate.inspect_exact_head(self.root, forbidden_head)

    def test_ambient_git_repository_redirect_does_not_override_root(self):
        valid_head = self._build_owned()
        with patch.dict("os.environ", {
            "GIT_DIR": str(self.root / "does-not-exist"),
            "GIT_WORK_TREE": str(self.root / "also-not-real"),
            "GIT_NO_REPLACE_OBJECTS": "0",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.fsmonitor",
            "GIT_CONFIG_VALUE_0": "dangerous-override",
        }):
            result = gate.inspect_exact_head(self.root, valid_head)
        self.assertEqual(result["head"], valid_head)
        self.assertEqual(result["decision"], "REVIEW_ONLY")


    def test_transient_original_source_change_then_revert_still_holds(self):
        original_head = self._build_owned()
        self.assertEqual(gate.inspect_exact_head(self.root, original_head)["decision"], "REVIEW_ONLY")
        self._write("README.md", "synthetic unowned intermediate change")
        self._commit()
        self._write("README.md", "base")
        final_head = self._commit()
        self.assertEqual(self._git("diff", "--name-only", original_head, final_head), "")
        with self.assertRaisesRegex(gate.Hold, "forbidden transient"):
            gate.inspect_exact_head(self.root, final_head)

    def test_temporary_unowned_added_file_then_delete_still_holds(self):
        original_head = self._build_owned()
        self._write("src/lightup/foreign-worker.py", "synthetic unowned file")
        self._commit()
        (self.root / "src/lightup/foreign-worker.py").unlink()
        final_head = self._commit()
        self.assertEqual(self._git("diff", "--name-only", original_head, final_head), "")
        with self.assertRaises(gate.Hold):
            gate.inspect_exact_head(self.root, final_head)

    def test_owned_file_delete_and_readd_still_holds(self):
        original_head = self._build_owned()
        path = self.root / sorted(gate.ALLOWED_ADDED)[0]
        original = path.read_bytes()
        path.unlink()
        self._commit()
        path.write_bytes(original)
        final_head = self._commit()
        self.assertEqual(self._git("diff", "--name-only", original_head, final_head), "")
        with self.assertRaises(gate.Hold):
            gate.inspect_exact_head(self.root, final_head)

    def test_temporary_symlink_then_original_regular_file_still_holds(self):
        original_head = self._build_owned()
        path = self.root / sorted(gate.ALLOWED_ADDED)[0]
        original = path.read_bytes()
        path.unlink()
        path.symlink_to(self.root / "README.md")
        self._commit()
        path.unlink()
        path.write_bytes(original)
        final_head = self._commit()
        self.assertEqual(self._git("diff", "--name-only", original_head, final_head), "")
        with self.assertRaises(gate.Hold):
            gate.inspect_exact_head(self.root, final_head)

    def test_commit_history_count_and_no_release_authority(self):
        original_head = self._build_owned()
        decision = gate.inspect_exact_head(self.root, original_head)
        self.assertEqual(decision["checked_commits"], 1)
        self.assertIs(decision["release_approved"], False)
        self.assertIs(decision["authorization_granted"], False)


    def test_temporary_executable_mode_then_restore_still_holds(self):
        original_head = self._build_owned()
        file = self.root / sorted(gate.ALLOWED_ADDED)[0]
        file.chmod(0o755)
        self._commit()
        file.chmod(0o644)
        final_head = self._commit()
        self.assertEqual(self._git("diff", "--name-only", original_head, final_head), "")
        with self.assertRaises(gate.Hold):
            gate.inspect_exact_head(self.root, final_head)

    def test_merge_commit_with_apparently_valid_final_tree_still_holds(self):
        original_head = self._build_owned()
        files = sorted(gate.ALLOWED_ADDED)
        self._git("switch", "-q", "-c", "synthetic-branch-A")
        self._write(files[0], "branch A owns own path")
        self._commit()
        self._git("switch", "-q", "-c", "synthetic-branch-B", original_head)
        self._write(files[1], "branch B owns another owned path")
        self._commit()
        self._git("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                  "merge", "--no-ff", "-q", "synthetic-branch-A", "-m", "synthetic merge")
        merged_head = self._git("rev-parse", "HEAD")
        with self.assertRaisesRegex(gate.Hold, "nonlinear"):
            gate.inspect_exact_head(self.root, merged_head)


    def test_index_only_mutation_is_invisible_to_unstaged_diff(self):
        owned_head = self._build_owned()
        path = sorted(gate.ALLOWED_ADDED)[0]
        self._write(path, "synthetic staged-only changed bytes")
        self._git("add", path)
        self.assertEqual(self._git("diff", "--name-only"), "")
        self.assertEqual(self._git("diff", "--cached", "--name-only"), path)
        # Immutable committed tree review still applies to HEAD; CI must check
        # the index as an additional and independent trust boundary.
        self.assertEqual(gate.inspect_exact_head(self.root, owned_head)["decision"], "REVIEW_ONLY")



class HostedTriggerContractTests(unittest.TestCase):
    def test_any_head_change_triggers_tree_review(self):
        workflow = (pathlib.Path(__file__).resolve().parents[1] /
                    ".github/workflows/scope-1563-membership-offline.yml").read_text()
        trigger = workflow.split("\non:\n", 1)[1].split("\npermissions:\n", 1)[0]
        self.assertIn("pull_request:", trigger)
        self.assertIn("synchronize", trigger)
        self.assertNotIn("paths:", trigger)
        self.assertIn("github.head_ref == 'chatgpt/scope-1563-membership-metamorphic-20261017'", workflow)

    def test_non_authorizing_exit_three_required_in_workflow(self):
        workflow = (pathlib.Path(__file__).resolve().parents[1] /
                    ".github/workflows/scope-1563-membership-offline.yml").read_text()
        self.assertIn("python scripts/scope_1563_exact_tree_boundary_20261017.py", workflow)
        self.assertIn('test "$result" -eq 3', workflow)
        self.assertIn("fetch-depth: 0", workflow)
        self.assertIn("persist-credentials: false", workflow)


    def test_owner_composition_gate_precedes_foreign_overlay(self):
        path = (pathlib.Path(__file__).resolve().parents[1] /
                ".github/workflows/scope-1563-owner301-compat-offline.yml")
        workflow = path.read_text(encoding="utf-8")
        self.assertIn("fetch-depth: 0", workflow)
        gate_call = 'python3 scripts/scope_1563_exact_tree_boundary_20261017.py --expected-head "$EXACT_HEAD"'
        foreign_overlay = 'git show "$EXACT_OWNER_SHA:$OWNER_TEST_PATH"'
        self.assertIn(gate_call, workflow)
        self.assertIn('test "$scope_gate" -eq 3', workflow)
        self.assertLess(workflow.index(gate_call), workflow.index(foreign_overlay))
        self.assertLess(workflow.index("- name: Python runtime"), workflow.index("- name: Pin branch"))
        self.assertIn("persist-credentials: false", workflow)



    def test_both_own_ci_workflows_require_index_and_untracked_cleanliness(self):
        root = pathlib.Path(__file__).resolve().parents[1] / ".github/workflows"
        for name in (
            "scope-1563-membership-offline.yml",
            "scope-1563-owner301-compat-offline.yml",
        ):
            with self.subTest(workflow=name):
                data = (root / name).read_text(encoding="utf-8")
                self.assertIn("git diff --cached --exit-code", data)
                self.assertIn('test -z "$(git ls-files --others --exclude-standard)"', data)



class MutationWitnessQualityTests(unittest.TestCase):
    """An unrelated exception must never be mistaken for an auth rejection."""

    @classmethod
    def setUpClass(cls):
        path = (pathlib.Path(__file__).resolve().parents[1] /
                "scripts/scope_1563_membership_mutation_proof_20261017.py")
        spec = importlib.util.spec_from_file_location("scope_1563_mutation_quality", path)
        if spec is None or spec.loader is None:
            raise AssertionError("mutation proof source unavailable")
        cls.proof = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.proof)

    @staticmethod
    def result(*, assertion=True, error=False, expected=False, wrong=False):
        class Case:
            def __str__(self):
                return ("test_other_case" if wrong else
                        "test_invalid_target_cannot_be_rescued_by_grant_or_auth_flag")

        result = unittest.TestResult()
        result.testsRun = 7
        case = Case()
        if assertion:
            result.failures.append((case, "Traceback: AssertionError: denied correctly"))
        if error:
            result.errors.append((case, "Traceback: RuntimeError: import crashed"))
        if expected:
            result.expectedFailures.append((case, "expected underlying source RED"))
        return result

    def test_real_assertion_and_matching_test_is_required(self):
        self.assertTrue(self.proof.mutation_detected(
            self.result(), "test_invalid_target"
        ))

    def test_exception_cannot_be_relabelled_mutation_detection(self):
        self.assertFalse(self.proof.mutation_detected(
            self.result(assertion=False, error=True), "test_invalid_target"
        ))
        self.assertFalse(self.proof.mutation_detected(
            self.result(assertion=True, error=True), "test_invalid_target"
        ))

    def test_only_matching_security_case_counts(self):
        self.assertFalse(self.proof.mutation_detected(
            self.result(wrong=True), "test_invalid_target"
        ))
        self.assertFalse(self.proof.mutation_detected(
            self.result(assertion=False), "test_invalid_target"
        ))

    def test_expected_red_or_exception_text_is_not_acceptance(self):
        result = self.result(expected=True)
        self.assertFalse(self.proof.mutation_detected(result, "test_invalid_target"))
        result = self.result()
        result.failures[0] = (result.failures[0][0], "Traceback: TypeError: broken")
        self.assertFalse(self.proof.mutation_detected(result, "test_invalid_target"))


if __name__ == "__main__":
    unittest.main()
