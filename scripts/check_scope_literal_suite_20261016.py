#!/usr/bin/env python3
"""Strictly offline test-discovery health check; never authorizes or deploys.

The original four source RED witnesses remain expected failures, not fixes.
Run only the separately-owned scope-literal test family.
"""
from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"
sys.path.insert(0, str(ROOT / "src"))

KNOWN_SOURCE_REDS = frozenset({
    "test_scope_literal_controls_20261016.InstalledSourceRedWitness.test_original_scope_must_not_convert_newline_to_loopback",
    "test_scope_literal_controls_20261016.InstalledSourceRedWitness.test_original_scope_must_not_convert_tab_to_loopback",
    "test_scope_literal_controls_20261016.InstalledSourceRedWitness.test_original_lab_activation_must_deny_control_char_authority",
    "test_scope_literal_controls_20261016.InstalledSourceRedWitness.test_original_scope_must_not_convert_newline_in_url",
})
MIN_TESTS = 121
REQUIRED_CASES = frozenset({
    "test_scope_literal_ownership_20261016.AdditiveOwnershipTests.test_real_branch_checker_rejects_dirty_checkout",
    "test_scope_literal_ownership_20261016.AdditiveOwnershipTests.test_workflow_checks_clean_checkout_after_tests",
    "test_scope_literal_runtime_isolation_20261016.RuntimeIsolationStaticTests.test_all_production_modules_stay_unwired",
    "test_scope_literal_runtime_isolation_20261016.RuntimeIsolationStaticTests.test_deployment_entrypoints_cannot_import_reviewer",
    "test_scope_literal_runtime_isolation_20261016.RuntimeIsolationStaticTests.test_lab_fixture_entrypoints_cannot_import_reviewer",
    "test_scope_literal_suite_integrity_20261016.ManifestEvidenceTests.test_replayed_known_red_cannot_hide_duplicate_expected_failures",
    "test_scope_literal_suite_integrity_20261016.ManifestEvidenceTests.test_named_safety_sentinel_cannot_be_replaced_by_dummy",
})
REQUIRED_MODULES = frozenset({
    "test_scope_literal_adapter_errors_20261016",
    "test_scope_literal_aliases_20261016",
    "test_scope_literal_canonical_equivalence_20261016",
    "test_scope_literal_cli_flags_20261016",
    "test_scope_literal_controls_20261016",
    "test_scope_literal_encoded_review_20261016",
    "test_scope_literal_git_modes_20261016",
    "test_scope_literal_json_boundary_20261016",
    "test_scope_literal_metamorphic_20261016",
    "test_scope_literal_output_errors_20261016",
    "test_scope_literal_ownership_20261016",
    "test_scope_literal_query_fragments_20261016",
    "test_scope_literal_runtime_isolation_20261016",
    "test_scope_literal_short_reads_20261016",
    "test_scope_literal_stream_errors_20261016",
    "test_scope_literal_suite_integrity_20261016",
})



def _cases(suite: unittest.TestSuite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from _cases(item)
        else:
            yield item


def check_evidence(ids: tuple[str, ...], result: unittest.TestResult, expected_modules: set[str]) -> bool:
    """Refuse green from skipped/missing tests, new REDs or missing modules."""
    red_ids = {case.id() for case, _text in result.expectedFailures}
    return (
        len(ids) >= MIN_TESTS
        and len(ids) == len(set(ids))
        and {item.split(".", 1)[0] for item in ids} == expected_modules
        and REQUIRED_MODULES <= expected_modules
        and REQUIRED_CASES <= set(ids)
        and KNOWN_SOURCE_REDS <= set(ids)
        and red_ids == KNOWN_SOURCE_REDS
        and len(result.expectedFailures) == len(KNOWN_SOURCE_REDS)
        and not (result.failures or result.errors or result.skipped or result.unexpectedSuccesses)
        and result.testsRun == len(ids)
        and result.wasSuccessful()
    )


def main() -> int:
    suite = unittest.defaultTestLoader.discover(
        start_dir=str(TESTS), pattern="test_scope_literal_*20261016.py",
        top_level_dir=str(TESTS),
    )
    # TestCase instances can be mutated/cleared while a suite runs.
    # Snapshot source names before execution and validate result afterwards.
    cases = tuple(_cases(suite))
    ids = [case.id() for case in cases]
    modules = {p.stem for p in TESTS.glob("test_scope_literal_*20261016.py")}
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    good = check_evidence(tuple(ids), result, modules)
    print(
        "scope_review_isolated_proof="
        + ("PASS" if good else "HOLD")
        + f" tests={result.testsRun} ordinary_pass="
        + str(result.testsRun - len(result.expectedFailures))
        + f" expected_source_reds={len(result.expectedFailures)}"
    )
    return 0 if good else 1


if __name__ == "__main__":
    raise SystemExit(main())
