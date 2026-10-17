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


class ManifestEvidenceTests(unittest.TestCase):
    def example(self):
        ids = tuple(sorted(manifest.KNOWN_SOURCE_REDS)) + tuple(
            f"test_scope_literal_fixture_20261016.Sample.test_case_{i:03d}"
            for i in range(manifest.MIN_TESTS - len(manifest.KNOWN_SOURCE_REDS))
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
