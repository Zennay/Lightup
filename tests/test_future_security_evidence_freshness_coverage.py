from __future__ import annotations

import dataclasses
import json
import unittest

import test_future_security_evidence_freshness as freshness_tests
import test_future_security_evidence_freshness_admission as admission_tests
from lightup.future_security_evidence_freshness_coverage import (
    COVERAGE_SCHEMA_VERSION,
    build_future_security_evidence_freshness_coverage,
    validate_future_security_evidence_freshness_coverage,
)


class FutureSecurityEvidenceFreshnessCoverageTest(unittest.TestCase):
    def setUp(self):
        self.freshness = freshness_tests.FutureSecurityEvidenceFreshnessConstraintsTest(
            "test_live_gap_binds_prior_evidence_and_run_as_forbidden"
        )
        self.freshness.setUp()
        self.addCleanup(self.freshness.tearDown)
        self.state = self.freshness.state

    def _base(self, *, suffix):
        return self.freshness._constraints(suffix=suffix)

    def _admission_base(self, *, suffix):
        helper = admission_tests.FutureSecurityEvidenceFreshnessAdmissionTest(
            "test_fresh_new_run_evidence_passes_without_security_classification"
        )
        helper.base = self.freshness
        helper.state = self.state
        return helper._admission(suffix=suffix)

    def test_no_admissions_reports_gap_missing_without_closure_semantics(self):
        (
            current,
            proposal,
            source_context,
            resolution,
            preview,
            report,
            plan,
            request,
            constraints,
        ) = self._base(suffix="coverage-empty")
        current_before = dataclasses.asdict(current)
        constraints_before = dataclasses.asdict(constraints)

        coverage = build_future_security_evidence_freshness_coverage(
            constraints,
            (),
            (),
            request=request,
            plan=plan,
            report=report,
            preview=preview,
            proposal=proposal,
            resolutions=(resolution,),
            source_contexts=(source_context,),
            state=self.state,
        )

        self.assertEqual(coverage.schema_version, COVERAGE_SCHEMA_VERSION)
        self.assertEqual(coverage.total_gap_count, 1)
        self.assertEqual(coverage.covered_gap_count, 0)
        self.assertEqual(coverage.missing_gap_count, 1)
        self.assertFalse(coverage.all_gaps_have_fresh_candidates)
        self.assertFalse(coverage.evidence_sufficiency_evaluated)
        self.assertFalse(coverage.gap_closed)
        self.assertFalse(coverage.classification_selected)
        self.assertFalse(coverage.transition_resolution_created)
        self.assertFalse(coverage.execution_allowed)
        self.assertFalse(coverage.target_interaction_allowed)

        item = coverage.items[0]
        self.assertFalse(item.fresh_candidate_present)
        self.assertIsNone(item.admission_sha256)
        self.assertIsNone(item.candidate_run_id)
        self.assertEqual(item.candidate_evidence_ids, ())
        self.assertEqual(dataclasses.asdict(current), current_before)
        self.assertEqual(dataclasses.asdict(constraints), constraints_before)

    def test_exact_live_admission_marks_only_its_gap_covered(self):
        (
            _,
            proposal,
            source_context,
            resolution,
            preview,
            report,
            plan,
            request,
            constraints,
            candidate_context,
            evidence_id,
            admission,
        ) = self._admission_base(suffix="coverage-live")

        coverage = build_future_security_evidence_freshness_coverage(
            constraints,
            (admission,),
            (candidate_context,),
            request=request,
            plan=plan,
            report=report,
            preview=preview,
            proposal=proposal,
            resolutions=(resolution,),
            source_contexts=(source_context,),
            state=self.state,
        )

        self.assertEqual(coverage.total_gap_count, 1)
        self.assertEqual(coverage.covered_gap_count, 1)
        self.assertEqual(coverage.missing_gap_count, 0)
        self.assertTrue(coverage.all_gaps_have_fresh_candidates)
        self.assertFalse(coverage.evidence_sufficiency_evaluated)
        self.assertFalse(coverage.gap_closed)
        item = coverage.items[0]
        self.assertTrue(item.fresh_candidate_present)
        self.assertEqual(item.admission_sha256, admission.admission_sha256)
        self.assertEqual(item.candidate_run_id, candidate_context.run_id)
        self.assertEqual(item.candidate_evidence_ids, (evidence_id,))

    def test_duplicate_foreign_and_missing_context_admissions_fail_closed(self):
        (
            _,
            proposal,
            source_context,
            resolution,
            preview,
            report,
            plan,
            request,
            constraints,
            candidate_context,
            _,
            admission,
        ) = self._admission_base(suffix="coverage-invalid")

        with self.assertRaisesRegex(ValueError, "duplicate source admissions"):
            build_future_security_evidence_freshness_coverage(
                constraints,
                (admission, admission),
                (candidate_context,),
                request=request,
                plan=plan,
                report=report,
                preview=preview,
                proposal=proposal,
                resolutions=(resolution,),
                source_contexts=(source_context,),
                state=self.state,
            )

        foreign = dataclasses.replace(admission, source_resolution_id="foreign")
        with self.assertRaisesRegex(ValueError, "foreign source admission"):
            build_future_security_evidence_freshness_coverage(
                constraints,
                (foreign,),
                (candidate_context,),
                request=request,
                plan=plan,
                report=report,
                preview=preview,
                proposal=proposal,
                resolutions=(resolution,),
                source_contexts=(source_context,),
                state=self.state,
            )

        with self.assertRaisesRegex(ValueError, "candidate RunContext is missing"):
            build_future_security_evidence_freshness_coverage(
                constraints,
                (admission,),
                (),
                request=request,
                plan=plan,
                report=report,
                preview=preview,
                proposal=proposal,
                resolutions=(resolution,),
                source_contexts=(source_context,),
                state=self.state,
            )

    def test_unreferenced_context_and_tampered_admission_fail_closed(self):
        (
            _,
            proposal,
            source_context,
            resolution,
            preview,
            report,
            plan,
            request,
            constraints,
            candidate_context,
            _,
            admission,
        ) = self._admission_base(suffix="coverage-tampered")

        with self.assertRaisesRegex(ValueError, "unreferenced candidate RunContexts"):
            build_future_security_evidence_freshness_coverage(
                constraints,
                (),
                (candidate_context,),
                request=request,
                plan=plan,
                report=report,
                preview=preview,
                proposal=proposal,
                resolutions=(resolution,),
                source_contexts=(source_context,),
                state=self.state,
            )

        tampered = dataclasses.replace(admission, admission_sha256="0" * 64)
        with self.assertRaisesRegex(ValueError, "live validated evidence"):
            build_future_security_evidence_freshness_coverage(
                constraints,
                (tampered,),
                (candidate_context,),
                request=request,
                plan=plan,
                report=report,
                preview=preview,
                proposal=proposal,
                resolutions=(resolution,),
                source_contexts=(source_context,),
                state=self.state,
            )

    def test_coverage_is_deterministic_bounded_and_live_revalidated(self):
        (
            _,
            proposal,
            source_context,
            resolution,
            preview,
            report,
            plan,
            request,
            constraints,
            candidate_context,
            evidence_id,
            admission,
        ) = self._admission_base(suffix="coverage-deterministic")

        first = build_future_security_evidence_freshness_coverage(
            constraints,
            (admission,),
            (candidate_context,),
            request=request,
            plan=plan,
            report=report,
            preview=preview,
            proposal=proposal,
            resolutions=(resolution,),
            source_contexts=(source_context,),
            state=self.state,
        )
        second = build_future_security_evidence_freshness_coverage(
            constraints,
            (admission,),
            (candidate_context,),
            request=request,
            plan=plan,
            report=report,
            preview=preview,
            proposal=proposal,
            resolutions=(resolution,),
            source_contexts=(source_context,),
            state=self.state,
        )
        self.assertEqual(first, second)
        self.assertEqual(len(first.coverage_sha256), 64)
        int(first.coverage_sha256, 16)

        exported = json.loads(first.to_json())
        self.assertEqual(exported["coverage_sha256"], first.coverage_sha256)
        self.assertEqual(exported["items"][0]["candidate_evidence_ids"], [evidence_id])
        serialized = first.to_json()
        for forbidden in (
            "evidence_payload",
            "metadata",
            "source",
            "target",
            "arguments",
            "credentials",
        ):
            self.assertNotIn(f'"{forbidden}"', serialized)

        validated = validate_future_security_evidence_freshness_coverage(
            first,
            constraints,
            (admission,),
            (candidate_context,),
            request=request,
            plan=plan,
            report=report,
            preview=preview,
            proposal=proposal,
            resolutions=(resolution,),
            source_contexts=(source_context,),
            state=self.state,
        )
        self.assertEqual(validated, first)

        tampered = dataclasses.replace(first, coverage_sha256="0" * 64)
        with self.assertRaisesRegex(ValueError, "live validated state"):
            validate_future_security_evidence_freshness_coverage(
                tampered,
                constraints,
                (admission,),
                (candidate_context,),
                request=request,
                plan=plan,
                report=report,
                preview=preview,
                proposal=proposal,
                resolutions=(resolution,),
                source_contexts=(source_context,),
                state=self.state,
            )


if __name__ == "__main__":
    unittest.main()
