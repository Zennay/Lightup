"""Negative proofs for the isolated hosted test-manifest gate itself.

Never runs production code, a scanner, external targets or real permissions.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_scope_literal_suite_20261016.py"
spec = importlib.util.spec_from_file_location("scope_manifest_proof", SCRIPT)
assert spec and spec.loader
manifest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manifest)


PINNED_GATES = frozenset({
    "test_scope_literal_ownership_20261016.AdditiveOwnershipTests.test_real_branch_checker_rejects_dirty_checkout",
    "test_scope_literal_ownership_20261016.AdditiveOwnershipTests.test_workflow_checks_clean_checkout_after_tests",
    "test_scope_literal_runtime_isolation_20261016.RuntimeIsolationStaticTests.test_all_production_modules_stay_unwired",
    "test_scope_literal_runtime_isolation_20261016.RuntimeIsolationStaticTests.test_deployment_entrypoints_cannot_import_reviewer",
    "test_scope_literal_runtime_isolation_20261016.RuntimeIsolationStaticTests.test_lab_fixture_entrypoints_cannot_import_reviewer",
    "test_scope_literal_suite_integrity_20261016.ManifestEvidenceTests.test_replayed_known_red_cannot_hide_duplicate_expected_failures",
    "test_scope_literal_suite_integrity_20261016.ManifestEvidenceTests.test_named_safety_sentinel_cannot_be_replaced_by_dummy",
})


class ManifestEvidenceTests(unittest.TestCase):
    def example(self):
        source_reds = tuple(sorted(manifest.KNOWN_SOURCE_REDS))
        other_modules = manifest.REQUIRED_MODULES - {
            "test_scope_literal_controls_20261016",
        }
        pinned = tuple(
            f"{module}.Sample.test_coverage" for module in sorted(other_modules)
        )
        ids = source_reds + pinned + tuple(sorted(PINNED_GATES)) + tuple(
            f"test_scope_literal_fixture_20261016.Sample.test_case_{i:03d}"
            for i in range(manifest.MIN_TESTS - len(source_reds) - len(pinned) - len(PINNED_GATES))
        )
        result = unittest.TestResult()
        result.testsRun = len(ids)
        result.expectedFailures = [
            (SimpleNamespace(id=lambda item=item: item), "fictional")
            for item in sorted(manifest.KNOWN_SOURCE_REDS)
        ]
        modules = {item.split(".", 1)[0] for item in ids}
        return ids, result, modules

    def test_correct_manifest_is_valid_synthetic_proof(self):
        ids, result, modules = self.example()
        self.assertTrue(manifest.check_evidence(ids, result, modules))

    def test_missing_or_duplicate_tests_fail(self):
        ids, result, modules = self.example()
        self.assertFalse(manifest.check_evidence(ids[:-1], result, modules))
        self.assertFalse(manifest.check_evidence(ids[:-1] + (ids[0],), result, modules))
        self.assertFalse(manifest.check_evidence(ids, result, modules | {"test_scope_literal_missing"}))

    def test_missing_whole_owned_module_cannot_hide_behind_test_count(self):
        ids, result, modules = self.example()
        # A whole module must be provably present, even if the total number
        # of tests remains above the minimum by retaining all other tests.
        for missing in (
            "test_scope_literal_adapter_errors_20261016",
            "test_scope_literal_git_modes_20261016",
        ):
            with self.subTest(missing=missing):
                changed = tuple(
                    ident.replace(missing + ".", "test_scope_literal_other_20261016.")
                    if ident.startswith(missing + ".") else ident
                    for ident in ids
                )
                observed = {ident.split(".", 1)[0] for ident in changed}
                self.assertEqual(len(changed), len(ids))
                self.assertFalse(manifest.check_evidence(changed, result, observed))

    def test_named_safety_sentinel_cannot_be_replaced_by_dummy(self):
        ids, result, modules = self.example()
        self.assertTrue(manifest.check_evidence(ids, result, modules))
        for pinned in sorted(PINNED_GATES):
            with self.subTest(pinned=pinned):
                replacement = pinned.split(".")[0] + ".Other.test_replacement_dummy"
                changed = tuple(replacement if x == pinned else x for x in ids)
                self.assertEqual(len(changed), len(ids))
                self.assertEqual({x.split(".", 1)[0] for x in changed}, modules)
                self.assertFalse(manifest.check_evidence(changed, result, modules))

    def test_skips_fail_closed_even_if_test_runner_says_success(self):
        ids, result, modules = self.example()
        result.skipped.append((SimpleNamespace(id=lambda: ids[0]), "fictional skip"))
        self.assertFalse(manifest.check_evidence(ids, result, modules))

    def test_new_unapproved_expected_failure_fails_closed(self):
        ids, result, modules = self.example()
        result.expectedFailures.append(
            (SimpleNamespace(id=lambda: "test_scope_literal_fixture.New.test_red"), "fictional")
        )
        self.assertFalse(manifest.check_evidence(ids, result, modules))

    def test_replayed_known_red_cannot_hide_duplicate_expected_failures(self):
        ids, result, modules = self.example()
        # The same original-source RED must not be counted twice as proof.
        result.expectedFailures.append(result.expectedFailures[0])
        self.assertFalse(manifest.check_evidence(ids, result, modules))

    def test_missing_original_red_contract_fails_closed(self):
        ids, result, modules = self.example()
        result.expectedFailures.pop()
        self.assertFalse(manifest.check_evidence(ids, result, modules))

    def test_other_failure_statuses_cannot_pass(self):
        for attr in ("failures", "errors", "unexpectedSuccesses"):
            with self.subTest(attr=attr):
                ids, result, modules = self.example()
                getattr(result, attr).append(("fictional", "synthetic"))
                self.assertFalse(manifest.check_evidence(ids, result, modules))


if __name__ == "__main__":
    unittest.main()
