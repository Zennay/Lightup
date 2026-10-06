from __future__ import annotations

import json
import unittest

import test_future_security_evidence_freshness_admission as admission_tests
from lightup.future_security_evidence_freshness_admission_consumer import (
    load_and_validate_future_security_evidence_freshness_admission,
)


class FutureSecurityEvidenceFreshnessAdmissionConsumerTest(unittest.TestCase):
    def setUp(self):
        self.base = admission_tests.FutureSecurityEvidenceFreshnessAdmissionTest(
            "test_fresh_new_run_evidence_passes_without_security_classification"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.state = self.base.state

    def _producer(self, *, suffix: str):
        return self.base._admission(suffix=suffix)

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
            _,
        ) = produced
        return load_and_validate_future_security_evidence_freshness_admission(
            persisted,
            constraints,
            candidate_context=candidate_context,
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
        produced = self._producer(suffix="admission-consumer-roundtrip")
        admission = produced[-1]

        consumed = self._consume(admission.to_json(), produced)

        self.assertEqual(consumed, admission)
        self.assertTrue(consumed.freshness_check_passed)
        self.assertFalse(consumed.evidence_suitability_evaluated)
        self.assertFalse(consumed.classification_selected)
        self.assertFalse(consumed.transition_resolution_created)
        self.assertFalse(consumed.collection_authorized)
        self.assertFalse(consumed.tool_call_created)
        self.assertFalse(consumed.execution_allowed)
        self.assertFalse(consumed.target_interaction_allowed)
        self.assertFalse(consumed.remediation_authoring_allowed)
        self.assertFalse(consumed.future_state_retest_allowed)
        self.assertFalse(consumed.deployment_authorized)
        self.assertFalse(consumed.attack_path_mutation_allowed)
        self.assertEqual(consumed.future_semantics, "unresolved")
        self.assertEqual(consumed.security_verdict, "not_evaluated")

    def test_invalid_duplicate_and_non_object_persisted_json_fail_closed(self):
        produced = self._producer(suffix="admission-consumer-json")
        admission = produced[-1]

        with self.assertRaisesRegex(ValueError, "persisted JSON is invalid"):
            self._consume("{", produced)

        with self.assertRaisesRegex(ValueError, "duplicate object keys"):
            self._consume(
                '{"schema_version":"a","schema_version":"b"}',
                produced,
            )

        duplicate_nested = admission.to_json().replace(
            '"capability_id":',
            '"capability_id":"duplicate","capability_id":',
            1,
        )
        with self.assertRaisesRegex(ValueError, "duplicate object keys"):
            self._consume(duplicate_nested, produced)

        with self.assertRaisesRegex(ValueError, "persisted payload must be an object"):
            self._consume("[]", produced)

        with self.assertRaisesRegex(ValueError, "JSON text or object"):
            self._consume(123, produced)

    def test_strict_digest_tampering_fails_before_live_acceptance(self):
        produced = self._producer(suffix="admission-consumer-tamper")
        admission = produced[-1]
        payload = json.loads(admission.to_json())
        payload["admission_sha256"] = "0" * 64

        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            self._consume(payload, produced)

    def test_live_candidate_evidence_drift_fails_after_strict_parse(self):
        produced = self._producer(suffix="admission-consumer-live-drift")
        evidence_id = produced[10]
        admission = produced[-1]

        with self.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                ("0" * 64, evidence_id),
            )

        with self.assertRaisesRegex(ValueError, "live validated evidence"):
            self._consume(admission.to_json(), produced)


if __name__ == "__main__":
    unittest.main()
