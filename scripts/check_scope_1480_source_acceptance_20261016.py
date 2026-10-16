#!/usr/bin/env python3
"""Strict *non-authorizing* opt-in harness for #1480 original-source RED.

Run only in an isolated review branch. Exit 0 attests 43 ordinary controls +
1 original-source expected RED, never a fixed source or release.
No network, subprocess, active adapters, real grant issuance, or target IO.
"""

from __future__ import annotations

import hashlib
import io
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OWN_TEST_FILES = (
    "test_scope_1480_activation_issuance_instant_20261016.py",
    "test_scope_1480_issuance_window_review_20261016.py",
    "test_scope_1480_issuance_transition_20261016.py",
    "test_scope_1480_local_source_reference_20261016.py",
)
ACTIVATION = ROOT / "src" / "lightup" / "activation.py"
ORIGINAL_SOURCE_BLOB = "156e94c18d5221b3d55e2c9fff4e393369e0f38e"
# Original runtime depends on these two source modules for authorization
# semantics. Pin their bytes too, not only ActivationGate and our own tests.
# We NEVER change them or treat a matching blob as real permission.
ORIGINAL_DEPENDENCY_BLOBS = {
    "src/lightup/models.py": "74b96d45a5308d39e2c4c930728e10a2ccc18d2a",
    "src/lightup/scope.py": "23909917822b5630c76be0cb47c99e1549b30cf8",
}
EXPECTED_RED = ("test_scope_1480_activation_issuance_instant_20261016."
                "ActivationIssuanceInstant1480Tests."
                "test_expected_red_authorized_permit_cannot_be_stamped_after_expiry")
EXPECTED_METHODS = 44

# Byte-identical reviewed proof material. Git object IDs prevent accidental
# test/helper drift; they are NOT a signature or an authorization token.
PINNED_REVIEW_BLOBS = {
    "tests/test_scope_1480_activation_issuance_instant_20261016.py": "a559811861a2b3d932ec10fbc5f058ca16e394bf",
    "tests/test_scope_1480_issuance_window_review_20261016.py": "a7aa1dce66098a6a2587c7744d955481993a2f73",
    "tests/test_scope_1480_issuance_transition_20261016.py": "5cc15798ff5a46fd65d06a4e9cd426824d1c9d67",
    "tests/test_scope_1480_local_source_reference_20261016.py": "a030a4f7179e47ee147ad1e989ce0debd4952e9a",
    "src/lightup/activation_issuance_window_review_1480.py": "3340190bbe981a30a2fef030f4090051d1f0c7a0",
}


EXPECTED_TEST_IDS = frozenset({
    "test_scope_1480_activation_issuance_instant_20261016.ActivationIssuanceInstant1480Tests.test_fixture_has_distinct_utc_instants",
    "test_scope_1480_activation_issuance_instant_20261016.ActivationIssuanceInstant1480Tests.test_authorized_exact_public_asset_inside_entire_window",
    "test_scope_1480_activation_issuance_instant_20261016.ActivationIssuanceInstant1480Tests.test_exact_expiry_inclusive_control",
    "test_scope_1480_activation_issuance_instant_20261016.ActivationIssuanceInstant1480Tests.test_expired_at_scope_check_denies",
    "test_scope_1480_activation_issuance_instant_20261016.ActivationIssuanceInstant1480Tests.test_plan_only_denies_without_issuing",
    "test_scope_1480_activation_issuance_instant_20261016.ActivationIssuanceInstant1480Tests.test_lab_only_rejects_fictional_public_host",
    "test_scope_1480_activation_issuance_instant_20261016.ActivationIssuanceInstant1480Tests.test_denied_unlisted_asset_even_with_valid_authorization",
    "test_scope_1480_activation_issuance_instant_20261016.ActivationIssuanceInstant1480Tests.test_expected_red_authorized_permit_cannot_be_stamped_after_expiry",
    "test_scope_1480_issuance_window_review_20261016.IssuanceWindowReview1480Tests.test_inside_window_remains_review_only",
    "test_scope_1480_issuance_window_review_20261016.IssuanceWindowReview1480Tests.test_both_inclusive_boundaries_are_only_review",
    "test_scope_1480_issuance_window_review_20261016.IssuanceWindowReview1480Tests.test_expired_issuance_is_hold",
    "test_scope_1480_issuance_window_review_20261016.IssuanceWindowReview1480Tests.test_not_yet_valid_issuance_is_hold",
    "test_scope_1480_issuance_window_review_20261016.IssuanceWindowReview1480Tests.test_missing_or_naive_bounds_hold",
    "test_scope_1480_issuance_window_review_20261016.IssuanceWindowReview1480Tests.test_inverted_window_is_rejected",
    "test_scope_1480_issuance_window_review_20261016.IssuanceWindowReview1480Tests.test_polymorphic_time_never_inherits_authority",
    "test_scope_1480_issuance_window_review_20261016.IssuanceWindowReview1480Tests.test_authorization_subclass_refused",
    "test_scope_1480_issuance_window_review_20261016.IssuanceWindowReview1480Tests.test_result_is_slotless_and_even_object_setattr_cannot_forge_release",
    "test_scope_1480_issuance_window_review_20261016.IssuanceWindowReview1480Tests.test_closed_interval_boundary_matrix_never_widens",
    "test_scope_1480_issuance_window_review_20261016.IssuanceWindowReview1480Tests.test_incomplete_forged_dataclass_is_hold_not_attribute_error",
    "test_scope_1480_issuance_window_review_20261016.IssuanceWindowReview1480Tests.test_erased_bound_on_frozen_authorization_holds",
    "test_scope_1480_issuance_window_review_20261016.IssuanceWindowReview1480Tests.test_review_uses_one_field_snapshot_not_live_bound_getattr",
    "test_scope_1480_issuance_window_review_20261016.IssuanceWindowReview1480Tests.test_review_requires_no_network",
    "test_scope_1480_issuance_transition_20261016.Transition1480Tests.test_increasing_inside_window_is_structural_review_only",
    "test_scope_1480_issuance_transition_20261016.Transition1480Tests.test_same_instant_is_structural_review_only",
    "test_scope_1480_issuance_transition_20261016.Transition1480Tests.test_check_outside_validity_does_not_inherit_later_valid_stamp",
    "test_scope_1480_issuance_transition_20261016.Transition1480Tests.test_expiry_between_check_and_stamp_is_hold",
    "test_scope_1480_issuance_transition_20261016.Transition1480Tests.test_backwards_clock_even_within_window_is_hold",
    "test_scope_1480_issuance_transition_20261016.Transition1480Tests.test_expired_check_holds_even_when_stamp_is_past",
    "test_scope_1480_issuance_transition_20261016.Transition1480Tests.test_polymorphic_checked_clock_holds",
    "test_scope_1480_issuance_transition_20261016.Transition1480Tests.test_polymorphic_issuance_clock_holds",
    "test_scope_1480_issuance_transition_20261016.Transition1480Tests.test_missing_authorization_is_hold_not_crash",
    "test_scope_1480_issuance_transition_20261016.Transition1480Tests.test_live_input_widening_between_two_reviews_cannot_change_original_snapshot",
    "test_scope_1480_issuance_transition_20261016.Transition1480Tests.test_incomplete_exact_authorization_holds_without_crashing",
    "test_scope_1480_issuance_transition_20261016.Transition1480Tests.test_object_new_without_constructor_holds",
    "test_scope_1480_issuance_transition_20261016.Transition1480Tests.test_live_time_bound_getters_are_not_read_between_reviews",
    "test_scope_1480_issuance_transition_20261016.Transition1480Tests.test_seeded_clock_matrix_preserves_coherent_interval",
    "test_scope_1480_issuance_transition_20261016.Transition1480Tests.test_non_utc_clock_offsets_never_create_review_authority",
    "test_scope_1480_issuance_transition_20261016.Transition1480Tests.test_no_caller_values_mutated",
    "test_scope_1480_local_source_reference_20261016.IssuanceReference1480Tests.test_unpatched_source_still_produces_expired_synthetic_permit",
    "test_scope_1480_local_source_reference_20261016.IssuanceReference1480Tests.test_reference_wrapper_turns_original_red_body_into_plain_pass",
    "test_scope_1480_local_source_reference_20261016.IssuanceReference1480Tests.test_reference_preserves_legitimate_in_window_exact_host",
    "test_scope_1480_local_source_reference_20261016.IssuanceReference1480Tests.test_real_gate_source_retains_permit_after_second_check_grant_shrink",
    "test_scope_1480_local_source_reference_20261016.IssuanceReference1480Tests.test_test_only_wrapper_denies_post_check_grant_shrink",
    "test_scope_1480_local_source_reference_20261016.IssuanceReference1480Tests.test_reference_preserves_expired_scope_and_plan_only_denials",
})


def _original_source_is_pinned() -> bool:
    try:
        if ACTIVATION.is_symlink() or not ACTIVATION.is_file():
            return False
        if ACTIVATION.stat().st_size > 100_000:
            return False
        contents = ACTIVATION.read_bytes()
        framed = b"blob " + str(len(contents)).encode("ascii") + b"\0" + contents
        return hashlib.sha1(framed).hexdigest() == ORIGINAL_SOURCE_BLOB
    except (OSError, ValueError):
        return False


def _original_dependency_sources_are_pinned() -> bool:
    """No source acceptance if installed grant/scope semantics have drifted."""
    return _review_blobs_match(ORIGINAL_DEPENDENCY_BLOBS)


def _review_material_is_pinned() -> bool:
    """No execution if any expected test/helper source blob has drifted."""
    return _review_blobs_match(PINNED_REVIEW_BLOBS)


def _review_blobs_match(expected_blobs: dict[str, str]) -> bool:
    """Inspect original Git blob framing with bounded, no-symlink file reads."""
    for relative_name, expected_sha in expected_blobs.items():
        path = ROOT / relative_name
        try:
            if path.is_symlink() or not path.is_file():
                return False
            if path.stat().st_size > 100_000:
                return False
            source = path.read_bytes()
            framed = b"blob " + str(len(source)).encode("ascii") + b"\0" + source
            if hashlib.sha1(framed).hexdigest() != expected_sha:
                return False
        except (OSError, ValueError):
            return False
    return True


def _expected_case_manifest_sha256() -> str:
    """Stable self-reported method-manifest digest (not signed CI evidence)."""
    records = "\n".join(sorted(EXPECTED_TEST_IDS)).encode("utf-8")
    return hashlib.sha256(records).hexdigest()


def _verdict(status: str, reason: str, tests: int = 0, expected_source_reds: int = 0) -> dict:
    return {
        "issue": 1480,
        "evidence_manifest_version": 1,
        "evidence_self_reported": True,
        "independent_ci_attestation": False,
        "original_activation_git_blob": ORIGINAL_SOURCE_BLOB,
        "original_dependency_git_blobs": dict(sorted(ORIGINAL_DEPENDENCY_BLOBS.items())),
        "reviewed_local_git_blobs": dict(sorted(PINNED_REVIEW_BLOBS.items())),
        "expected_case_manifest_sha256": _expected_case_manifest_sha256(),
        "expected_case_count": EXPECTED_METHODS,
        "status": status,
        "reason": reason,
        "tests_run": tests,
        "expected_source_reds": expected_source_reds,
        "source_fixed": False,
        "full_suite_green": False,
        "permanent_vps_proven": False,
        "consent_verified": False,
        "revocation_verified": False,
        "may_issue_grants": False,
        "may_dispatch_tools": False,
        "may_scan_targets": False,
        "may_merge": False,
        "may_deploy": False,
        "release_authorized": False,
    }



def _loaded_test_ids(suite: unittest.TestSuite) -> tuple[str, ...]:
    """Enumerate every loaded case, including failure placeholders."""
    names: list[str] = []

    def visit(node: unittest.TestSuite | unittest.TestCase) -> None:
        if isinstance(node, unittest.TestSuite):
            for child in node:
                visit(child)
        else:
            names.append(node.id())

    visit(suite)
    return tuple(names)


def _has_exact_test_inventory(ids: tuple[str, ...]) -> bool:
    """Fail CLOSED on substitutions even when the total test count matches."""
    return (
        len(ids) == EXPECTED_METHODS
        and len(set(ids)) == EXPECTED_METHODS
        and set(ids) == EXPECTED_TEST_IDS
    )


def main() -> int:
    # The only accepted source is the exact installed main source inspected
    # when filing #1480. Do not silently promote a repaired or drifted source.
    if not _original_source_is_pinned():
        print(json.dumps(_verdict("HOLD", "original_activation_source_blob_mismatch"), sort_keys=True))
        return 1
    if not _original_dependency_sources_are_pinned():
        print(json.dumps(_verdict("HOLD", "original_authorization_dependency_blob_mismatch"), sort_keys=True))
        return 1
    if not _review_material_is_pinned():
        print(json.dumps(_verdict("HOLD", "review_material_blob_mismatch"), sort_keys=True))
        return 1

    for filename in OWN_TEST_FILES:
        test_path = ROOT / "tests" / filename
        if test_path.is_symlink() or not test_path.is_file():
            print(json.dumps(_verdict("HOLD", "test_module_missing_or_symlinked"), sort_keys=True))
            return 1

    sys.path.insert(0, str(ROOT / "src"))
    suite = unittest.TestSuite()
    for filename in OWN_TEST_FILES:
        suite.addTests(unittest.defaultTestLoader.discover(
            start_dir=str(ROOT / "tests"), pattern=filename,
        ))
    if not _has_exact_test_inventory(_loaded_test_ids(suite)):
        print(json.dumps(_verdict("HOLD", "test_inventory_mismatch"), sort_keys=True))
        return 1

    capture = io.StringIO()
    result = unittest.TextTestRunner(stream=capture, verbosity=2).run(suite)
    red_is_exact = (
        len(result.expectedFailures) == 1
        and EXPECTED_RED == result.expectedFailures[0][0].id()
        and "AssertionError: PermissionError not raised" in result.expectedFailures[0][1]
    )
    okay = (
        result.testsRun == EXPECTED_METHODS
        and red_is_exact
        and not result.failures
        and not result.errors
        and not result.skipped
        and not result.unexpectedSuccesses
    )
    print(
        json.dumps(
            _verdict(
                "REVIEW_ONLY" if okay else "HOLD",
                "original_source_gap_reproduced" if okay else "test_contract_mismatch",
                result.testsRun,
                len(result.expectedFailures),
            ),
            sort_keys=True,
        )
    )
    if not okay:
        print(capture.getvalue(), file=sys.stderr)
    return 0 if okay else 1


if __name__ == "__main__":
    raise SystemExit(main())
