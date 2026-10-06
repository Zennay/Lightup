from __future__ import annotations

import copy
import json
import unittest

import test_future_security_evidence_freshness_coverage as coverage_tests
from lightup.future_security_evidence_freshness_coverage import (
    build_future_security_evidence_freshness_coverage,
    future_security_evidence_freshness_coverage_from_dict,
)


class FutureSecurityEvidenceFreshnessCoverageHandoffTest(unittest.TestCase):
    def setUp(self):
        self.base = coverage_tests.FutureSecurityEvidenceFreshnessCoverageTest(
            "test_no_admissions_reports_gap_missing_without_closure_semantics"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _uncovered_payload(self):
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
        ) = self.base._base(suffix="coverage-handoff-empty")
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
            state=self.base.state,
        )
        return coverage, json.loads(coverage.to_json())

    def _covered_payload(self):
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
        ) = self.base._admission_base(suffix="coverage-handoff-covered")
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
            state=self.base.state,
        )
        return coverage, json.loads(coverage.to_json())

    def test_exact_round_trip_restores_covered_and_uncovered_reports(self):
        for factory in (self._uncovered_payload, self._covered_payload):
            with self.subTest(factory=factory.__name__):
                coverage, payload = factory()
                restored = future_security_evidence_freshness_coverage_from_dict(
                    payload
                )
                self.assertEqual(restored, coverage)

    def test_extra_missing_and_bad_primitive_fields_fail_closed(self):
        _, payload = self._covered_payload()

        extra = copy.deepcopy(payload)
        extra["unexpected"] = "field"
        with self.assertRaisesRegex(ValueError, "payload schema mismatch"):
            future_security_evidence_freshness_coverage_from_dict(extra)

        missing = copy.deepcopy(payload)
        del missing["constraints_sha256"]
        with self.assertRaisesRegex(ValueError, "payload schema mismatch"):
            future_security_evidence_freshness_coverage_from_dict(missing)

        item_extra = copy.deepcopy(payload)
        item_extra["items"][0]["security_verdict"] = "pass"
        with self.assertRaisesRegex(ValueError, "item schema mismatch"):
            future_security_evidence_freshness_coverage_from_dict(item_extra)

        bool_count = copy.deepcopy(payload)
        bool_count["total_gap_count"] = True
        with self.assertRaisesRegex(ValueError, "non-negative integer"):
            future_security_evidence_freshness_coverage_from_dict(bool_count)

    def test_forged_counts_and_all_covered_flag_fail_closed(self):
        _, uncovered = self._uncovered_payload()

        forged_count = copy.deepcopy(uncovered)
        forged_count["covered_gap_count"] = 1
        forged_count["missing_gap_count"] = 0
        with self.assertRaisesRegex(ValueError, "covered gap count mismatch"):
            future_security_evidence_freshness_coverage_from_dict(forged_count)

        forged_all = copy.deepcopy(uncovered)
        forged_all["all_gaps_have_fresh_candidates"] = True
        with self.assertRaisesRegex(ValueError, "all-gaps flag mismatch"):
            future_security_evidence_freshness_coverage_from_dict(forged_all)

    def test_covered_and_uncovered_identity_fields_are_strict(self):
        _, covered = self._covered_payload()

        missing_digest = copy.deepcopy(covered)
        missing_digest["items"][0]["admission_sha256"] = None
        with self.assertRaisesRegex(ValueError, "canonical lowercase SHA-256"):
            future_security_evidence_freshness_coverage_from_dict(missing_digest)

        empty_evidence = copy.deepcopy(covered)
        empty_evidence["items"][0]["candidate_evidence_ids"] = []
        with self.assertRaisesRegex(ValueError, "non-empty string list"):
            future_security_evidence_freshness_coverage_from_dict(empty_evidence)

        _, uncovered = self._uncovered_payload()
        stray_run = copy.deepcopy(uncovered)
        stray_run["items"][0]["candidate_run_id"] = "run-stray"
        with self.assertRaisesRegex(ValueError, "cannot carry a candidate run"):
            future_security_evidence_freshness_coverage_from_dict(stray_run)

        stray_evidence = copy.deepcopy(uncovered)
        stray_evidence["items"][0]["candidate_evidence_ids"] = ["evidence-stray"]
        with self.assertRaisesRegex(ValueError, "cannot carry candidate evidence"):
            future_security_evidence_freshness_coverage_from_dict(stray_evidence)

    def test_duplicate_or_noncanonical_items_and_evidence_ids_fail_closed(self):
        _, covered = self._covered_payload()

        duplicate_evidence = copy.deepcopy(covered)
        evidence_id = duplicate_evidence["items"][0]["candidate_evidence_ids"][0]
        duplicate_evidence["items"][0]["candidate_evidence_ids"].append(evidence_id)
        with self.assertRaisesRegex(ValueError, "sorted and unique"):
            future_security_evidence_freshness_coverage_from_dict(
                duplicate_evidence
            )

        duplicate_item = copy.deepcopy(covered)
        duplicate_item["items"].append(copy.deepcopy(duplicate_item["items"][0]))
        duplicate_item["total_gap_count"] = 2
        duplicate_item["covered_gap_count"] = 2
        with self.assertRaisesRegex(ValueError, "identities must be unique"):
            future_security_evidence_freshness_coverage_from_dict(duplicate_item)

    def test_safety_flags_and_digest_fail_closed(self):
        _, covered = self._covered_payload()

        closed = copy.deepcopy(covered)
        closed["gap_closed"] = True
        with self.assertRaisesRegex(ValueError, "gap_closed must remain false"):
            future_security_evidence_freshness_coverage_from_dict(closed)

        sufficient = copy.deepcopy(covered)
        sufficient["evidence_sufficiency_evaluated"] = True
        with self.assertRaisesRegex(
            ValueError,
            "evidence_sufficiency_evaluated must remain false",
        ):
            future_security_evidence_freshness_coverage_from_dict(sufficient)

        digest = copy.deepcopy(covered)
        digest["coverage_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            future_security_evidence_freshness_coverage_from_dict(digest)


if __name__ == "__main__":
    unittest.main()
