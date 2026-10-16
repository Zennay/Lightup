"""Strict *offline* source acceptance for #1482; never a release gate.

Source bytes and exact unit IDs are checked BEFORE executing source imports.
Even a successful run exits 0 as REVIEW_ONLY, never grants execution.
"""
from __future__ import annotations

import hashlib
import io
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEST_NAME = "test_scope_decision_shape_activation_1482_20261016.py"
PINNED_BLOBS = {
    "src/lightup/activation.py": "156e94c18d5221b3d55e2c9fff4e393369e0f38e",
    "src/lightup/scope.py": "23909917822b5630c76be0cb47c99e1549b30cf8",
    "src/lightup/models.py": "74b96d45a5308d39e2c4c930728e10a2ccc18d2a",
    "src/lightup/activation_decision_shape_review_1482.py": "8f746b7b04f9bb576f799dcae6f25fd42388e635",
    "tests/test_scope_decision_shape_activation_1482_20261016.py": "a2e0354d3f8a2449b1ab638a6cd0e14e144289c9",
}
ORDINARY_IDS = frozenset({
    "test_scope_decision_shape_activation_1482_20261016.OriginalSourceAcceptance.test_normal_lab_loopback_still_issues",
    "test_scope_decision_shape_activation_1482_20261016.OriginalSourceAcceptance.test_public_explicit_host_still_denied_in_lab_mode",
    "test_scope_decision_shape_activation_1482_20261016.OriginalSourceAcceptance.test_plan_only_still_denies",
    "test_scope_decision_shape_activation_1482_20261016.ShapeReviewerTests.test_real_normal_lab_decision_is_review_only",
    "test_scope_decision_shape_activation_1482_20261016.ShapeReviewerTests.test_real_out_of_scope_denial_is_review_only_not_authorization",
    "test_scope_decision_shape_activation_1482_20261016.ShapeReviewerTests.test_noncanonical_policy_is_hold_without_running_decide",
    "test_scope_decision_shape_activation_1482_20261016.ShapeReviewerTests.test_truthy_string_allowed_is_hold",
    "test_scope_decision_shape_activation_1482_20261016.ShapeReviewerTests.test_wrong_host_is_hold",
    "test_scope_decision_shape_activation_1482_20261016.ShapeReviewerTests.test_public_loopback_claim_is_hold",
    "test_scope_decision_shape_activation_1482_20261016.ShapeReviewerTests.test_false_allowed_and_loopback_reason_is_hold",
    "test_scope_decision_shape_activation_1482_20261016.ShapeReviewerTests.test_bogus_decision_object_is_hold",
    "test_scope_decision_shape_activation_1482_20261016.ShapeReviewerTests.test_oversized_input_is_hold_without_parser",
    "test_scope_decision_shape_activation_1482_20261016.ShapeReviewerTests.test_fake_target_subclass_is_hold",
    "test_scope_decision_shape_activation_1482_20261016.ShapeReviewerTests.test_verdict_is_not_modifiable_to_grant",
    "test_scope_decision_shape_activation_1482_20261016.ShapeReviewerTests.test_exact_review_is_network_free",
})
EXPECTED_SOURCE_REDS = frozenset({
    "test_scope_decision_shape_activation_1482_20261016.OriginalSourceAcceptance.test_source_red_rejects_noncanonical_constructor_policy",
    "test_scope_decision_shape_activation_1482_20261016.OriginalSourceAcceptance.test_source_red_rejects_truthy_nonboolean_allowed",
    "test_scope_decision_shape_activation_1482_20261016.OriginalSourceAcceptance.test_source_red_rejects_target_to_decision_host_substitution",
})
ALL_IDS = ORDINARY_IDS | EXPECTED_SOURCE_REDS


def git_blob_hash(payload: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(payload)).encode("ascii") + b"\\0" + payload).hexdigest()


def source_tree_ok(root: Path = ROOT, pins: dict[str, str] = PINNED_BLOBS) -> bool:
    """Reject missing/symlinked/oversized/changed bytes before any imports."""
    try:
        for relative, digest in pins.items():
            path = root / relative
            if path.is_symlink() or not path.is_file():
                return False
            with path.open("rb") as file:
                data = file.read(131073)
            if len(data) > 131072 or git_blob_hash(data) != digest:
                return False
    except (OSError, ValueError):
        return False
    return True


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def manifest_ok(suite) -> bool:
    ids = [case.id() for case in flatten(suite)]
    return (
        len(ids) == len(ALL_IDS)
        and len(ids) == len(set(ids))
        and set(ids) == ALL_IDS
    )


def result_ok(result: unittest.TestResult) -> bool:
    observed_reds = {case.id() for case, _ in result.expectedFailures}
    red_proofs = all(
        "AssertionError: " in traceback and "not raised" in traceback
        for _, traceback in result.expectedFailures
    )
    return (
        result.testsRun == len(ALL_IDS)
        and not result.errors and not result.failures
        and not result.skipped and not result.unexpectedSuccesses
        and observed_reds == EXPECTED_SOURCE_REDS
        and red_proofs
    )


def run(root: Path = ROOT) -> int:
    if sys.version_info < (3, 11) or not source_tree_ok(root):
        print("HOLD: source_integrity")
        return 2
    try:
        suite = unittest.defaultTestLoader.discover(
            str(root / "tests"), pattern=TEST_NAME
        )
        if not manifest_ok(suite):
            print("HOLD: test_manifest")
            return 2
        output = io.StringIO()
        result = unittest.TextTestRunner(stream=output, verbosity=0).run(suite)
        if not result_ok(result):
            print("HOLD: source_acceptance")
            return 2
    except (Exception, SystemExit):
        print("HOLD: source_acceptance")
        return 2
    print("REVIEW_ONLY: exact source shape acceptance; 15 ordinary PASS, 3 source RED still OPEN")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
