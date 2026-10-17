"""Synthetic offline tests for the #1563 immutable ownership gate.

Creates only disposable local Git repositories; no remote or real asset access.
"""
from __future__ import annotations

import importlib.util
import io
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



    def test_preflight_precedes_all_project_test_execution(self):
        root = pathlib.Path(__file__).resolve().parents[1] / ".github/workflows"
        focused = (root / "scope-1563-membership-offline.yml").read_text(encoding="utf-8")
        composed = (root / "scope-1563-owner301-compat-offline.yml").read_text(encoding="utf-8")
        gate_call = "python3 scripts/scope_1563_exact_tree_boundary_20261017.py --expected-head"
        self.assertIn(gate_call, focused)
        self.assertIn(gate_call, composed)
        self.assertLess(focused.index(gate_call), focused.index("- name: Python runtime"))
        self.assertLess(focused.index(gate_call), focused.index("python -m unittest discover"))
        self.assertLess(composed.index(gate_call), composed.index("git show \"$EXACT_OWNER_SHA"))
        self.assertLess(composed.index(gate_call), composed.index("python -m unittest discover"))

    def test_both_workflows_guard_all_branch_changes_without_path_bypass(self):
        root = pathlib.Path(__file__).resolve().parents[1] / ".github/workflows"
        for name in ("scope-1563-membership-offline.yml", "scope-1563-owner301-compat-offline.yml"):
            with self.subTest(workflow=name):
                workflow = (root / name).read_text(encoding="utf-8")
                trigger = workflow.split("\non:\n", 1)[1].split("\npermissions:\n", 1)[0]
                self.assertIn("pull_request:", trigger)
                self.assertIn("synchronize", trigger)
                self.assertNotIn("paths:", trigger)
                self.assertIn("github.head_ref == 'chatgpt/scope-1563-membership-metamorphic-20261017'", workflow)
                self.assertIn("git diff --cached --exit-code", workflow)
                self.assertIn('test -z "$(git ls-files --others --exclude-standard)"', workflow)

    def test_preflight_rejects_dirty_index_before_any_fixture_overlay(self):
        root = pathlib.Path(__file__).resolve().parents[1] / ".github/workflows"
        for name in ("scope-1563-membership-offline.yml", "scope-1563-owner301-compat-offline.yml"):
            with self.subTest(workflow=name):
                workflow = (root / name).read_text(encoding="utf-8")
                gate = workflow.index("python3 scripts/scope_1563_exact_tree_boundary_20261017.py --expected-head")
                clean_index = workflow.index("git diff --cached --exit-code")
                clean_untracked = workflow.index('test -z "$(git ls-files --others --exclude-standard)"')
                self.assertLess(clean_index, gate)
                self.assertLess(clean_untracked, gate)


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

        result = MutationWitnessQualityTests.proof.CoverageResult(io.StringIO(), True, 0)
        result.testsRun = 16
        result.subtest_attempts.update(MutationWitnessQualityTests.proof.EXPECTED_CASE_COUNTS)
        result.subtest_passes.update(MutationWitnessQualityTests.proof.EXPECTED_CASE_COUNTS)
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



    def test_exact_membership_contract_manifest_is_complete(self):
        self.assertEqual(len(self.proof.REQUIRED_TEST_METHODS), 16)
        self.assertTrue(self.proof.suite_manifest_valid())

    def test_security_case_replacement_with_unrelated_stub_is_rejected(self):
        # Preserve total of 16 tests while replacing one meaningful case.
        # A mere testsRun == 16 gate would produce an unsafe false green.
        cls = self.proof.suite_module.ScopeMembershipMetamorphicTests
        missing = "test_ipv6_right_neighbor_of_declared_prefix_remains_unlisted"
        replacement = "test_noop_unrelated_stub"
        with patch.object(cls, missing, None):
            with patch.object(cls, replacement, lambda self: None, create=True):
                suite = unittest.defaultTestLoader.loadTestsFromModule(self.proof.suite_module)
                self.assertEqual(suite.countTestCases(), 16)
                self.assertFalse(self.proof.suite_manifest_valid())
        self.assertTrue(self.proof.suite_manifest_valid())



    def test_original_baseline_refuses_expected_failure_or_skip(self):
        result = self.proof.CoverageResult(io.StringIO(), True, 0)
        result.testsRun = len(self.proof.REQUIRED_TEST_METHODS)
        result.subtest_attempts.update(self.proof.EXPECTED_CASE_COUNTS)
        result.subtest_passes.update(self.proof.EXPECTED_CASE_COUNTS)
        self.assertTrue(self.proof.baseline_is_strictly_green(result))
        result.expectedFailures.append((self, "synthetic unresolved safety RED"))
        self.assertTrue(result.wasSuccessful())  # unittest's misleading default
        self.assertFalse(self.proof.baseline_is_strictly_green(result))
        result.expectedFailures.clear()
        result.skipped.append((self, "synthetic safety bypass"))
        self.assertTrue(result.wasSuccessful())
        self.assertFalse(self.proof.baseline_is_strictly_green(result))
        result.skipped.clear()
        result.testsRun -= 1
        self.assertFalse(self.proof.baseline_is_strictly_green(result))

    def test_actual_expected_failure_decorator_cannot_greenwash_named_contract(self):
        cls = self.proof.suite_module.ScopeMembershipMetamorphicTests
        name = "test_ipv6_right_neighbor_of_declared_prefix_remains_unlisted"
        with patch.object(cls, name, unittest.expectedFailure(lambda self: self.fail("SYNTHETIC RED"))):
            self.assertTrue(self.proof.suite_manifest_valid())
            result = self.proof.run_suite()
            self.assertEqual(result.testsRun, len(self.proof.REQUIRED_TEST_METHODS))
            self.assertTrue(result.wasSuccessful())
            self.assertEqual(len(result.expectedFailures), 1)
            self.assertFalse(self.proof.baseline_is_strictly_green(result))
        self.assertTrue(self.proof.suite_manifest_valid())

    def test_actual_skip_decorator_cannot_suppress_named_contract(self):
        cls = self.proof.suite_module.ScopeMembershipMetamorphicTests
        name = "test_ipv4_right_neighbor_of_declared_cidr_remains_unlisted"
        skipped = unittest.skip("SYNTHETIC HOLD")(lambda self: None)
        with patch.object(cls, name, skipped):
            self.assertTrue(self.proof.suite_manifest_valid())
            result = self.proof.run_suite()
            self.assertEqual(result.testsRun, len(self.proof.REQUIRED_TEST_METHODS))
            self.assertTrue(result.wasSuccessful())
            self.assertEqual(len(result.skipped), 1)
            self.assertFalse(self.proof.baseline_is_strictly_green(result))
        self.assertTrue(self.proof.suite_manifest_valid())


    def test_all_730_negative_subcases_are_required_by_method(self):
        self.assertEqual(set(self.proof.EXPECTED_CASE_COUNTS), self.proof.REQUIRED_TEST_METHODS)
        self.assertEqual(sum(self.proof.EXPECTED_CASE_COUNTS.values()), 730)
        original = self.proof.run_suite()
        self.assertIs(type(original), self.proof.CoverageResult)
        self.assertTrue(self.proof.baseline_is_strictly_green(original))
        self.assertEqual(dict(original.subtest_passes), self.proof.EXPECTED_CASE_COUNTS)

    def test_count_preserving_subcase_shift_must_fail_closed(self):
        result = self.proof.CoverageResult(io.StringIO(), True, 0)
        result.testsRun = len(self.proof.REQUIRED_TEST_METHODS)
        result.subtest_attempts.update(self.proof.EXPECTED_CASE_COUNTS)
        result.subtest_passes.update(self.proof.EXPECTED_CASE_COUNTS)
        self.assertTrue(self.proof.baseline_is_strictly_green(result))
        from_name = "test_generated_global_ipv4_nonmembers_do_not_gain_scope"
        to_name = "test_ipv4_right_neighbor_of_declared_cidr_remains_unlisted"
        for counts in (result.subtest_attempts, result.subtest_passes):
            counts[from_name] -= 1
            counts[to_name] += 1
        self.assertEqual(sum(result.subtest_passes.values()), 730)
        self.assertFalse(self.proof.all_subcases_covered(result))
        self.assertFalse(self.proof.baseline_is_strictly_green(result))

    def test_named_test_with_single_subtest_cannot_replace_full_ipv4_matrix(self):
        cls = self.proof.suite_module.ScopeMembershipMetamorphicTests
        method = "test_generated_global_ipv4_nonmembers_do_not_gain_scope"

        def superficial_success(self):
            with self.subTest(ip="one-synthetic-case"):
                self.assertTrue(True)

        with patch.object(cls, method, superficial_success):
            self.assertTrue(self.proof.suite_manifest_valid())
            result = self.proof.run_suite()
            self.assertTrue(result.wasSuccessful())
            self.assertEqual(result.testsRun, 16)
            self.assertEqual(result.subtest_attempts[method], 1)
            self.assertEqual(sum(result.subtest_passes.values()), 475)
            self.assertFalse(self.proof.baseline_is_strictly_green(result))
        self.assertTrue(self.proof.baseline_is_strictly_green(self.proof.run_suite()))

    def test_missing_result_instrumentation_is_hold_even_with_synthetic_pass(self):
        result = unittest.TestResult()
        result.testsRun = 16
        self.assertTrue(result.wasSuccessful())
        self.assertFalse(self.proof.all_subcases_covered(result))
        self.assertFalse(self.proof.baseline_is_strictly_green(result))

    def test_downstream_mutation_manifest_is_separate_and_exact(self):
        self.assertEqual(
            {entry[0] for entry in self.proof.DOWNSTREAM_MUTATIONS},
            {
                "planner_denied_capabilities",
                "planner_early_discovery",
                "planner_execution_enabled",
                "permit_gate_missing_membership",
                "permit_token_before_membership",
            },
        )
        for name, owner, method, mutation, contract in self.proof.DOWNSTREAM_MUTATIONS:
            with self.subTest(mutation=name):
                self.assertIn(owner.__name__, ("Planner", "ActivationGate"))
                self.assertIn(method, ("build", "issue"))
                self.assertTrue(callable(mutation))
                self.assertTrue(any(name.startswith(contract) for name in self.proof.REQUIRED_TEST_METHODS))

    def test_downstream_mutation_restoration_targets_canonical_source(self):
        self.assertIs(self.proof.Planner.build, self.proof.REAL_PLAN)
        self.assertIs(self.proof.ActivationGate.issue, self.proof.REAL_ISSUE)
        self.assertEqual(len(self.proof.REQUIRED_TEST_METHODS), 16)

    def test_all_nine_mutation_canaries_have_distinct_expected_contracts(self):
        self.assertEqual(len(self.proof.MUTATIONS), 9)
        expected = {
            "grant_mints_membership",
            "invalid_identity_rescued",
            "grant_checked_before_scope",
            "spoofed_label_authorizes",
            "cidr_right_neighbor_authorizes",
            "hostname_wildcard_authorizes",
            "denied_identity_rewritten",
            "reason_string_type_confusion",
            "decision_proxy_type_confusion",
        }
        self.assertEqual({entry[0] for entry in self.proof.MUTATIONS}, expected)
        for name, broken, method in self.proof.MUTATIONS:
            with self.subTest(mutation=name):
                self.assertTrue(callable(broken))
                self.assertTrue(method.startswith("test_"))

    def test_mutation_harness_refuses_old_partial_test_count(self):
        result = self.result()
        result.testsRun = 7
        self.assertFalse(self.proof.mutation_detected(result, "test_invalid_target"))
        result.testsRun = 16
        self.assertTrue(self.proof.mutation_detected(result, "test_invalid_target"))


    def test_mutation_skip_or_missing_subcase_is_not_security_proof(self):
        result = self.result()
        self.assertTrue(self.proof.mutation_detected(result, "test_invalid_target"))
        result.skipped.append((self, "synthetic skipped branch"))
        self.assertFalse(self.proof.mutation_detected(result, "test_invalid_target"))
        result.skipped.clear()
        method = "test_generated_global_ipv4_nonmembers_do_not_gain_scope"
        result.subtest_attempts[method] -= 1
        self.assertFalse(self.proof.mutation_detected(result, "test_invalid_target"))
        result.subtest_attempts[method] += 1
        self.assertTrue(self.proof.mutation_detected(result, "test_invalid_target"))

    def test_early_security_assertion_may_stop_only_its_own_nested_subcases(self):
        with patch.object(self.proof.ScopePolicy, "decide",
                          self.proof.illegally_accept_invalid_target):
            result = self.proof.run_suite()
        affected = "test_invalid_identity_stops_planner_and_permit_before_side_effects"
        self.assertEqual(result.subtest_attempts[affected], 16)
        self.assertEqual(self.proof.EXPECTED_CASE_COUNTS[affected], 64)
        self.assertEqual(result.testsRun, 16)
        self.assertFalse(result.errors)
        self.assertTrue(self.proof.mutation_subcases_valid(result))
        self.assertTrue(self.proof.mutation_detected(result, "test_invalid_target"))
        self.assertIs(self.proof.ScopePolicy.decide, self.proof.REAL_DECIDE)

    def test_missing_subcase_in_unaffected_test_is_not_mutation_proof(self):
        result = self.result()
        self.assertTrue(self.proof.mutation_detected(result, "test_invalid_target"))
        name = "test_generated_global_ipv4_nonmembers_do_not_gain_scope"
        result.subtest_attempts[name] -= 1
        self.assertFalse(self.proof.mutation_subcases_valid(result))
        self.assertFalse(self.proof.mutation_detected(result, "test_invalid_target"))
        result.subtest_attempts[name] += 1
        self.assertTrue(self.proof.mutation_detected(result, "test_invalid_target"))

    def test_real_mutation_runs_exercise_full_subcase_attempt_counts(self):
        cls = self.proof.suite_module.ScopeMembershipMetamorphicTests
        with patch.object(self.proof.ScopePolicy, "decide", self.proof.illegally_promote_cidr_right_neighbor):
            result = self.proof.run_suite()
        self.assertIs(type(result), self.proof.CoverageResult)
        self.assertEqual(dict(result.subtest_attempts), self.proof.EXPECTED_CASE_COUNTS)
        self.assertTrue(self.proof.mutation_detected(result, "test_ipv4_right_neighbor"))
        self.assertIs(self.proof.ScopePolicy.decide, self.proof.REAL_DECIDE)

    def test_expected_red_or_exception_text_is_not_acceptance(self):
        result = self.result(expected=True)
        self.assertFalse(self.proof.mutation_detected(result, "test_invalid_target"))
        result = self.result()
        result.failures[0] = (result.failures[0][0], "Traceback: TypeError: broken")
        self.assertFalse(self.proof.mutation_detected(result, "test_invalid_target"))


if __name__ == "__main__":
    unittest.main()
