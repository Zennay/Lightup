from __future__ import annotations

import json
import unittest

import test_future_security_evidence_freshness_coverage as coverage_tests
from lightup.future_security_evidence_freshness_coverage import (
    build_future_security_evidence_freshness_coverage,
)
from lightup.future_security_evidence_freshness_coverage_consumer import (
    load_and_validate_future_security_evidence_freshness_coverage,
)


class FutureSecurityEvidenceFreshnessCoverageConsumerTest(unittest.TestCase):
    def setUp(self):
        self.base = coverage_tests.FutureSecurityEvidenceFreshnessCoverageTest(
            "test_exact_live_admission_marks_only_its_gap_covered"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.state = self.base.state

    def _producer(self, *, suffix: str):
        produced = self.base._admission_base(suffix=suffix)
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
        ) = produced
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
        return produced + (coverage,)

    def _consume(self, persisted: object, produced: tuple):
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
            _,
        ) = produced
        return load_and_validate_future_security_evidence_freshness_coverage(
            persisted,
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

    def test_real_producer_json_is_strictly_parsed_and_live_validated(self):
        produced = self._producer(suffix="coverage-consumer-roundtrip")
        coverage = produced[-1]

        consumed = self._consume(coverage.to_json(), produced)

        self.assertEqual(consumed, coverage)
        self.assertTrue(consumed.all_gaps_have_fresh_candidates)
        self.assertFalse(consumed.evidence_sufficiency_evaluated)
        self.assertFalse(consumed.gap_closed)
        self.assertFalse(consumed.classification_selected)
        self.assertFalse(consumed.transition_resolution_created)
        self.assertFalse(consumed.collection_authorized)
        self.assertFalse(consumed.execution_allowed)
        self.assertFalse(consumed.target_interaction_allowed)
        self.assertFalse(consumed.remediation_authoring_allowed)
        self.assertFalse(consumed.future_state_retest_allowed)
        self.assertFalse(consumed.deployment_authorized)
        self.assertFalse(consumed.attack_path_mutation_allowed)
        self.assertEqual(consumed.future_semantics, "unresolved")
        self.assertEqual(consumed.security_verdict, "not_evaluated")

    def test_invalid_duplicate_and_non_object_persisted_json_fail_closed(self):
        produced = self._producer(suffix="coverage-consumer-json")

        with self.assertRaisesRegex(ValueError, "persisted JSON is invalid"):
            self._consume("{", produced)

        with self.assertRaisesRegex(ValueError, "duplicate object keys"):
            self._consume(
                '{"schema_version":"a","schema_version":"b"}',
                produced,
            )

        with self.assertRaisesRegex(ValueError, "persisted payload must be an object"):
            self._consume("[]", produced)

        with self.assertRaisesRegex(ValueError, "JSON text or object"):
            self._consume(123, produced)

    def test_strict_serialization_tampering_fails_before_live_acceptance(self):
        produced = self._producer(suffix="coverage-consumer-tamper")
        coverage = produced[-1]
        payload = json.loads(coverage.to_json())
        payload["coverage_sha256"] = "0" * 64

        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            self._consume(payload, produced)

    def test_live_evidence_drift_fails_after_strict_parse(self):
        produced = self._producer(suffix="coverage-consumer-live-drift")
        evidence_id = produced[10]
        coverage = produced[-1]

        with self.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                ("0" * 64, evidence_id),
            )

        with self.assertRaises(ValueError):
            self._consume(coverage.to_json(), produced)


if __name__ == "__main__":
    unittest.main()
