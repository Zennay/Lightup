"""Strict offline exact-head acceptance for own #1482 scope-authorization tests.

Never a release approval, permit or customer consent. Fail closed if any
original source or own tested file changes, including a genuine source fix.
No active adapters, real targets, DNS, scan or handler are executed here.
"""
from __future__ import annotations

import hashlib
import io
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
PINNED_GIT_BLOBS = {
    "src/lightup/activation.py": "156e94c18d5221b3d55e2c9fff4e393369e0f38e",
    "src/lightup/scope.py": "23909917822b5630c76be0cb47c99e1549b30cf8",
    "src/lightup/models.py": "74b96d45a5308d39e2c4c930728e10a2ccc18d2a",
    "src/lightup/activation_decision_shape_review_1482.py": "8f746b7b04f9bb576f799dcae6f25fd42388e635",
    "src/lightup/activation_decision_cohort_review_1482.py": "b41dd8f4181ca505a90cc8b39575f3ecaa1af273",
    "src/lightup/activation_fictional_source_differential_1482.py": "6eb0df8b8180dfeb703b9474c7f2e796f791bee8",
    "src/lightup/activation_lab_binding_reference_1482.py": "d26bf6938acaedc7b26ce02c86380d05e5aef4fb",
    "tests/test_scope_decision_shape_activation_1482_20261016.py": "a2e0354d3f8a2449b1ab638a6cd0e14e144289c9",
    "tests/test_scope_decision_source_verifier_1482_20261016.py": "bf5cb58591325294a292e9a298551229c7d620f2",
    "tests/test_scope_decision_legacy_constructor_witness_1482_20261016.py": "367f522db76286a369d1091e7ce5951a349dcf85",
    "tests/test_scope_decision_cohort_review_1482_20261016.py": "e01e8b0e72d6ed1fefa11e462a4a4b1820b5cd33",
    "tests/test_scope_decision_policy_metadata_1482_20261016.py": "8abdcc0513b1cd9d8671967c46ebf6d9b6e5a6e8",
    "tests/test_scope_decision_hostile_matrix_1482_20261016.py": "65d282b13e0271602ba91a51de7de5b1063995af",
    "tests/test_scope_fictional_source_differential_1482_20261016.py": "b04727724d1c6bf6e2af7ad79a85b4169240a098",
    "tests/test_scope_lab_binding_reference_1482_20261016.py": "2378e417db5a47dcd8806993481a6f1f86d9d91b",
}
TEST_PATTERNS = (
    "test_scope_decision_shape_activation_1482_20261016.py",
    "test_scope_decision_source_verifier_1482_20261016.py",
    "test_scope_decision_legacy_constructor_witness_1482_20261016.py",
    "test_scope_decision_cohort_review_1482_20261016.py",
    "test_scope_decision_policy_metadata_1482_20261016.py",
    "test_scope_decision_hostile_matrix_1482_20261016.py",
    "test_scope_fictional_source_differential_1482_20261016.py",
    "test_scope_lab_binding_reference_1482_20261016.py",
)
EXPECTED_TEST_IDS = frozenset({
    "test_scope_decision_shape_activation_1482_20261016.OriginalSourceAcceptance.test_normal_lab_loopback_still_issues",
    "test_scope_decision_shape_activation_1482_20261016.OriginalSourceAcceptance.test_public_explicit_host_still_denied_in_lab_mode",
    "test_scope_decision_shape_activation_1482_20261016.OriginalSourceAcceptance.test_plan_only_still_denies",
    "test_scope_decision_shape_activation_1482_20261016.OriginalSourceAcceptance.test_source_red_rejects_noncanonical_constructor_policy",
    "test_scope_decision_shape_activation_1482_20261016.OriginalSourceAcceptance.test_source_red_rejects_truthy_nonboolean_allowed",
    "test_scope_decision_shape_activation_1482_20261016.OriginalSourceAcceptance.test_source_red_rejects_target_to_decision_host_substitution",
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
    "test_scope_decision_source_verifier_1482_20261016.StrictOfflineSourceAcceptanceTests.test_canonical_empty_git_blob_hash",
    "test_scope_decision_source_verifier_1482_20261016.StrictOfflineSourceAcceptanceTests.test_current_exact_reviewed_bytes_match",
    "test_scope_decision_source_verifier_1482_20261016.StrictOfflineSourceAcceptanceTests.test_mismatched_digest_fails_closed",
    "test_scope_decision_source_verifier_1482_20261016.StrictOfflineSourceAcceptanceTests.test_missing_reviewed_files_fail_closed",
    "test_scope_decision_source_verifier_1482_20261016.StrictOfflineSourceAcceptanceTests.test_exact_manifest_has_18_unique_methods",
    "test_scope_decision_source_verifier_1482_20261016.StrictOfflineSourceAcceptanceTests.test_manifest_detects_removed_case",
    "test_scope_decision_source_verifier_1482_20261016.StrictOfflineSourceAcceptanceTests.test_source_drift_never_executes_a_test",
    "test_scope_decision_source_verifier_1482_20261016.StrictOfflineSourceAcceptanceTests.test_fabricated_result_cannot_claim_success",
    "test_scope_decision_source_verifier_1482_20261016.StrictOfflineSourceAcceptanceTests.test_real_isolated_18_method_source_acceptance",
    "test_scope_decision_legacy_constructor_witness_1482_20261016.ConstructedScopeProvenanceWitness.test_current_legacy_canary_synthetic_policy_can_stamp_lab_record",
    "test_scope_decision_legacy_constructor_witness_1482_20261016.ConstructedScopeProvenanceWitness.test_same_fictional_public_target_denied_by_actual_scope_policy",
    "test_scope_decision_legacy_constructor_witness_1482_20261016.ConstructedScopeProvenanceWitness.test_offline_reviewer_refuses_forged_decider_without_invocation",
    "test_scope_decision_legacy_constructor_witness_1482_20261016.ConstructedScopeProvenanceWitness.test_even_forged_scope_cannot_override_plan_only_mode",
    "test_scope_decision_legacy_constructor_witness_1482_20261016.ConstructedScopeProvenanceWitness.test_valid_actual_loopback_remains_provenance_distinct",
    "test_scope_decision_cohort_review_1482_20261016.CohortShapeReviewTests.test_multiple_real_loopback_decisions_are_review_only",
    "test_scope_decision_cohort_review_1482_20261016.CohortShapeReviewTests.test_real_denied_public_domain_is_not_promoted",
    "test_scope_decision_cohort_review_1482_20261016.CohortShapeReviewTests.test_invalid_generator_refused_before_iteration",
    "test_scope_decision_cohort_review_1482_20261016.CohortShapeReviewTests.test_tuple_subclass_refused",
    "test_scope_decision_cohort_review_1482_20261016.CohortShapeReviewTests.test_empty_and_overlimit_refused",
    "test_scope_decision_cohort_review_1482_20261016.CohortShapeReviewTests.test_list_row_refused",
    "test_scope_decision_cohort_review_1482_20261016.CohortShapeReviewTests.test_tuple_subclass_row_refused",
    "test_scope_decision_cohort_review_1482_20261016.CohortShapeReviewTests.test_malformed_length_refused",
    "test_scope_decision_cohort_review_1482_20261016.CohortShapeReviewTests.test_invalid_decision_object_refused",
    "test_scope_decision_cohort_review_1482_20261016.CohortShapeReviewTests.test_forged_public_loopback_flag_fail_closed_atomically",
    "test_scope_decision_cohort_review_1482_20261016.CohortShapeReviewTests.test_duplicate_target_rejected_even_if_different_notation",
    "test_scope_decision_cohort_review_1482_20261016.CohortShapeReviewTests.test_conflicted_allow_boolean_is_hold",
    "test_scope_decision_cohort_review_1482_20261016.CohortShapeReviewTests.test_never_calls_policy_decide",
    "test_scope_decision_cohort_review_1482_20261016.CohortShapeReviewTests.test_unexpected_helper_exception_is_hold_not_crash",
    "test_scope_decision_cohort_review_1482_20261016.CohortShapeReviewTests.test_no_network_or_subprocess",
    "test_scope_decision_cohort_review_1482_20261016.CohortShapeReviewTests.test_non_authorizing_verdict_is_immutable",
    "test_scope_decision_cohort_review_1482_20261016.CohortShapeReviewTests.test_min_and_max_accepted_batch_size",
    "test_scope_decision_policy_metadata_1482_20261016.PolicyMetadataSnapshotTests.test_canonical_frozen_policy_metadata_remains_review_only",
    "test_scope_decision_policy_metadata_1482_20261016.PolicyMetadataSnapshotTests.test_mutable_host_set_is_hold",
    "test_scope_decision_policy_metadata_1482_20261016.PolicyMetadataSnapshotTests.test_mutable_network_list_is_hold",
    "test_scope_decision_policy_metadata_1482_20261016.PolicyMetadataSnapshotTests.test_int_like_private_lab_bool_is_hold",
    "test_scope_decision_policy_metadata_1482_20261016.PolicyMetadataSnapshotTests.test_int_like_authorization_requirement_is_hold",
    "test_scope_decision_policy_metadata_1482_20261016.PolicyMetadataSnapshotTests.test_host_string_subclass_is_hold",
    "test_scope_decision_policy_metadata_1482_20261016.PolicyMetadataSnapshotTests.test_network_string_subclass_is_hold",
    "test_scope_decision_policy_metadata_1482_20261016.PolicyMetadataSnapshotTests.test_excess_hosts_are_hold_before_iteration",
    "test_scope_decision_policy_metadata_1482_20261016.PolicyMetadataSnapshotTests.test_excess_network_entries_are_hold",
    "test_scope_decision_policy_metadata_1482_20261016.PolicyMetadataSnapshotTests.test_oversized_host_entry_is_hold",
    "test_scope_decision_policy_metadata_1482_20261016.PolicyMetadataSnapshotTests.test_erased_original_field_does_not_fall_back_to_default",
    "test_scope_decision_policy_metadata_1482_20261016.PolicyMetadataSnapshotTests.test_injected_unrecognized_policy_field_is_hold",
    "test_scope_decision_policy_metadata_1482_20261016.PolicyMetadataSnapshotTests.test_snapshot_copied_not_fetched_fieldwise",
    "test_scope_decision_policy_metadata_1482_20261016.PolicyMetadataSnapshotTests.test_public_domain_cannot_claim_private_lab_reason",
    "test_scope_decision_policy_metadata_1482_20261016.PolicyMetadataSnapshotTests.test_public_global_ip_cannot_claim_private_lab_reason",
    "test_scope_decision_policy_metadata_1482_20261016.PolicyMetadataSnapshotTests.test_dns_name_cannot_claim_explicit_network",
    "test_scope_decision_policy_metadata_1482_20261016.PolicyMetadataSnapshotTests.test_ip_literal_cannot_claim_explicit_host",
    "test_scope_decision_policy_metadata_1482_20261016.PolicyMetadataSnapshotTests.test_real_private_lab_ipv4_still_has_shape_review",
    "test_scope_decision_policy_metadata_1482_20261016.PolicyMetadataSnapshotTests.test_real_public_explicit_cidr_remains_non_authorizing",
    "test_scope_decision_hostile_matrix_1482_20261016.OfflineCohortHostileMatrixTests.test_exhaustive_host_reason_allow_type_cross_product",
    "test_scope_decision_hostile_matrix_1482_20261016.OfflineCohortHostileMatrixTests.test_seeded_2048_mixed_fields_never_authorize",
    "test_scope_decision_hostile_matrix_1482_20261016.OfflineCohortHostileMatrixTests.test_typed_hostile_policy_values_denied_without_stringifying",
    "test_scope_decision_hostile_matrix_1482_20261016.OfflineCohortHostileMatrixTests.test_tuple_subclass_iterator_side_effect_blocked",
    "test_scope_decision_hostile_matrix_1482_20261016.OfflineCohortHostileMatrixTests.test_private_identifiers_are_never_reflected",
    "test_scope_decision_hostile_matrix_1482_20261016.OfflineCohortHostileMatrixTests.test_no_dns_socket_or_process_during_seeded_mixed_review",
    "test_scope_decision_hostile_matrix_1482_20261016.OfflineCohortHostileMatrixTests.test_64_row_batch_never_leaks_partial_approval",
    "test_scope_fictional_source_differential_1482_20261016.FictionalSourceDifferentialTests.test_actual_loopback_source_matches_original_claim",
    "test_scope_fictional_source_differential_1482_20261016.FictionalSourceDifferentialTests.test_actual_ipv4_loopback_source_matches",
    "test_scope_fictional_source_differential_1482_20261016.FictionalSourceDifferentialTests.test_original_fictional_public_name_denial_matches",
    "test_scope_fictional_source_differential_1482_20261016.FictionalSourceDifferentialTests.test_explicit_fictional_name_without_auth_is_still_denied",
    "test_scope_fictional_source_differential_1482_20261016.FictionalSourceDifferentialTests.test_forged_public_allow_does_not_match_source",
    "test_scope_fictional_source_differential_1482_20261016.FictionalSourceDifferentialTests.test_forged_normalized_host_does_not_match_source",
    "test_scope_fictional_source_differential_1482_20261016.FictionalSourceDifferentialTests.test_raw_string_reason_is_hold",
    "test_scope_fictional_source_differential_1482_20261016.FictionalSourceDifferentialTests.test_embedded_credentials_rejected_before_original_decide",
    "test_scope_fictional_source_differential_1482_20261016.FictionalSourceDifferentialTests.test_malformed_double_dot_rejected_before_original_decide",
    "test_scope_fictional_source_differential_1482_20261016.FictionalSourceDifferentialTests.test_uppercase_domain_rejected_before_source",
    "test_scope_fictional_source_differential_1482_20261016.FictionalSourceDifferentialTests.test_target_with_authorization_is_rejected_without_checking_grants",
    "test_scope_fictional_source_differential_1482_20261016.FictionalSourceDifferentialTests.test_target_with_polymorphic_labels_rejected_without_equality",
    "test_scope_fictional_source_differential_1482_20261016.FictionalSourceDifferentialTests.test_default_lab_enabled_policy_rejected_before_original_decide",
    "test_scope_fictional_source_differential_1482_20261016.FictionalSourceDifferentialTests.test_nonempty_explicit_networks_rejected_without_decide",
    "test_scope_fictional_source_differential_1482_20261016.FictionalSourceDifferentialTests.test_unknown_allowlist_name_rejected",
    "test_scope_fictional_source_differential_1482_20261016.FictionalSourceDifferentialTests.test_disabled_public_authorization_requirement_rejected",
    "test_scope_fictional_source_differential_1482_20261016.FictionalSourceDifferentialTests.test_policy_subclass_rejected",
    "test_scope_fictional_source_differential_1482_20261016.FictionalSourceDifferentialTests.test_mocked_source_exception_is_generic_hold",
    "test_scope_fictional_source_differential_1482_20261016.FictionalSourceDifferentialTests.test_actual_original_source_probe_has_no_network_or_process",
    "test_scope_fictional_source_differential_1482_20261016.FictionalSourceDifferentialTests.test_result_cannot_be_mutated_to_authorize",
    "test_scope_lab_binding_reference_1482_20261016.LabBindingReferenceTests.test_localhost_matches_trusted_reference",
    "test_scope_lab_binding_reference_1482_20261016.LabBindingReferenceTests.test_loopback_ipv4_matches_trusted_reference",
    "test_scope_lab_binding_reference_1482_20261016.LabBindingReferenceTests.test_fictional_public_out_of_scope_matches_deny",
    "test_scope_lab_binding_reference_1482_20261016.LabBindingReferenceTests.test_fictional_explicit_host_without_grant_matches_missing",
    "test_scope_lab_binding_reference_1482_20261016.LabBindingReferenceTests.test_forged_public_loopback_decision_denied",
    "test_scope_lab_binding_reference_1482_20261016.LabBindingReferenceTests.test_forged_false_public_claim_wrong_reason_denied",
    "test_scope_lab_binding_reference_1482_20261016.LabBindingReferenceTests.test_forged_allow_truthy_string_denied",
    "test_scope_lab_binding_reference_1482_20261016.LabBindingReferenceTests.test_forged_bool_integer_denied",
    "test_scope_lab_binding_reference_1482_20261016.LabBindingReferenceTests.test_forged_reason_string_denied",
    "test_scope_lab_binding_reference_1482_20261016.LabBindingReferenceTests.test_forged_normalized_host_denied",
    "test_scope_lab_binding_reference_1482_20261016.LabBindingReferenceTests.test_forged_host_subclass_denied",
    "test_scope_lab_binding_reference_1482_20261016.LabBindingReferenceTests.test_duplicate_dot_fictional_host_denied",
    "test_scope_lab_binding_reference_1482_20261016.LabBindingReferenceTests.test_url_with_userinfo_not_considered_fictional_host",
    "test_scope_lab_binding_reference_1482_20261016.LabBindingReferenceTests.test_ipv6_and_private_lab_ineligible_for_reference",
    "test_scope_lab_binding_reference_1482_20261016.LabBindingReferenceTests.test_real_auth_metadata_denied_without_evaluation",
    "test_scope_lab_binding_reference_1482_20261016.LabBindingReferenceTests.test_nonempty_labels_denied",
    "test_scope_lab_binding_reference_1482_20261016.LabBindingReferenceTests.test_labels_wrong_type_cannot_trigger_untrusted_eq",
    "test_scope_lab_binding_reference_1482_20261016.LabBindingReferenceTests.test_default_private_lab_policy_denied",
    "test_scope_lab_binding_reference_1482_20261016.LabBindingReferenceTests.test_public_auth_disabled_denied",
    "test_scope_lab_binding_reference_1482_20261016.LabBindingReferenceTests.test_real_explicit_network_denied",
    "test_scope_lab_binding_reference_1482_20261016.LabBindingReferenceTests.test_nonfictional_explicit_host_denied",
    "test_scope_lab_binding_reference_1482_20261016.LabBindingReferenceTests.test_plan_only_activation_is_not_lab_reference",
    "test_scope_lab_binding_reference_1482_20261016.LabBindingReferenceTests.test_authorized_activation_is_not_lab_reference",
    "test_scope_lab_binding_reference_1482_20261016.LabBindingReferenceTests.test_non_enum_activation_mode_denied",
    "test_scope_lab_binding_reference_1482_20261016.LabBindingReferenceTests.test_lab_requires_bounded_reference",
    "test_scope_lab_binding_reference_1482_20261016.LabBindingReferenceTests.test_modified_activation_policy_envelope_denied",
    "test_scope_lab_binding_reference_1482_20261016.LabBindingReferenceTests.test_missing_activation_policy_envelope_field_denied",
    "test_scope_lab_binding_reference_1482_20261016.LabBindingReferenceTests.test_noncanonical_policy_class_denied",
    "test_scope_lab_binding_reference_1482_20261016.LabBindingReferenceTests.test_no_policy_decide_invocation",
    "test_scope_lab_binding_reference_1482_20261016.LabBindingReferenceTests.test_no_network_process_or_sqlite",
    "test_scope_lab_binding_reference_1482_20261016.LabBindingReferenceTests.test_review_result_cannot_be_mutated_to_grant",
})
EXPECTED_OPEN_REDS = frozenset({
    "test_scope_decision_shape_activation_1482_20261016.OriginalSourceAcceptance.test_source_red_rejects_noncanonical_constructor_policy",
    "test_scope_decision_shape_activation_1482_20261016.OriginalSourceAcceptance.test_source_red_rejects_truthy_nonboolean_allowed",
    "test_scope_decision_shape_activation_1482_20261016.OriginalSourceAcceptance.test_source_red_rejects_target_to_decision_host_substitution",
})
MAX_BYTES = 131072


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def pinned_tree_valid(root: Path = ROOT) -> bool:
    """Reject indirection at EVERY owned path component before imports.

    This is a local review-only guard, not a signed-source or race-safe
    provenance attestation. Never resolve a symlink into a different tree.
    """
    try:
        if type(root) is not Path or root.is_symlink() or not root.is_dir():
            return False
        if len(PINNED_GIT_BLOBS) != 15:
            return False
        for relpath, expected_sha in PINNED_GIT_BLOBS.items():
            if (
                type(relpath) is not str or type(expected_sha) is not str
                or len(expected_sha) != 40
            ):
                return False
            components = Path(relpath).parts
            if (
                not components or any(c in (".", "..") for c in components)
                or Path(relpath).is_absolute()
            ):
                return False
            parent = root
            for component in components[:-1]:
                parent = parent / component
                if parent.is_symlink() or not parent.is_dir():
                    return False
            path = parent / components[-1]
            if path.is_symlink() or not path.is_file():
                return False
            with path.open("rb") as stream:
                data = stream.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES or git_blob_sha(data) != expected_sha:
                return False
    except (OSError, ValueError, TypeError):
        return False
    return True


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def test_manifest_valid(suite) -> bool:
    ids = [test.id() for test in flatten(suite)]
    return (
        len(ids) == len(EXPECTED_TEST_IDS)
        and len(ids) == len(set(ids))
        and set(ids) == EXPECTED_TEST_IDS
    )


def test_result_valid(result: unittest.TestResult) -> bool:
    red = {test.id() for test, _ in result.expectedFailures}
    # Distinguish an intended original 'with assertRaises' failing from any
    # arbitrary exception hidden behind an expectedFailure decorator.
    red_is_assertion = all(
        "AssertionError:" in traceback and "not raised" in traceback
        for test, traceback in result.expectedFailures
    )
    return (
        result.testsRun == len(EXPECTED_TEST_IDS)
        and not result.failures
        and not result.errors
        and not result.skipped
        and not result.unexpectedSuccesses
        and len(result.expectedFailures) == len(EXPECTED_OPEN_REDS)
        and red == EXPECTED_OPEN_REDS
        and red_is_assertion
    )


def run(root: Path = ROOT) -> int:
    if sys.version_info < (3, 11) or not pinned_tree_valid(root):
        print("HOLD: source_bytes")
        return 2
    try:
        sys.path.insert(0, str(root / "src"))
        suite = unittest.TestSuite()
        for pattern in TEST_PATTERNS:
            suite.addTests(unittest.defaultTestLoader.discover(
                str(root / "tests"), pattern=pattern
            ))
        if not test_manifest_valid(suite):
            print("HOLD: test_manifest")
            return 2
        result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(suite)
        if not test_result_valid(result):
            print("HOLD: test_outcomes")
            return 2
    except (Exception, SystemExit):
        print("HOLD: test_runtime")
        return 2
    print("REVIEW_ONLY: 123 ordinary synthetic PASS; 3 ORIGINAL SOURCE REDs remain OPEN; NO RELEASE")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
