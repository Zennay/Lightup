from __future__ import annotations

import json
import unittest

import test_future_security_evidence_freshness as freshness_tests
from lightup.future_security_evidence_freshness_constraints_consumer import (
    load_and_validate_future_security_evidence_freshness_constraints,
)


class FutureSecurityEvidenceFreshnessConstraintsConsumerTest(unittest.TestCase):
    def setUp(self):
        self.base = freshness_tests.FutureSecurityEvidenceFreshnessConstraintsTest(
            "test_live_gap_binds_prior_evidence_and_run_as_forbidden"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.state = self.base.state

    def _producer(self, *, suffix: str):
        return self.base._constraints(suffix=suffix)

    def _consume(self, persisted: object, produced: tuple):
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            request,
            _,
        ) = produced
        return load_and_validate_future_security_evidence_freshness_constraints(
            persisted,
            request,
            plan,
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )

    def test_real_producer_json_is_strictly_parsed_and_live_validated(self):
        produced = self._producer(suffix="constraints-consumer-roundtrip")
        constraints = produced[-1]

        consumed = self._consume(constraints.to_json(), produced)

        self.assertEqual(consumed, constraints)
        self.assertFalse(consumed.collection_authorized)
        self.assertFalse(consumed.capability_selected)
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
        produced = self._producer(suffix="constraints-consumer-json")
        constraints = produced[-1]

        with self.assertRaisesRegex(ValueError, "persisted JSON is invalid"):
            self._consume("{", produced)

        with self.assertRaisesRegex(ValueError, "duplicate object keys"):
            self._consume(
                '{"schema_version":"a","schema_version":"b"}',
                produced,
            )

        duplicate_nested = constraints.to_json().replace(
            '"fresh_evidence_required":true',
            '"fresh_evidence_required":true,"fresh_evidence_required":false',
            1,
        )
        with self.assertRaisesRegex(ValueError, "duplicate object keys"):
            self._consume(duplicate_nested, produced)

        with self.assertRaisesRegex(ValueError, "persisted payload must be an object"):
            self._consume("[]", produced)

        with self.assertRaisesRegex(ValueError, "JSON text or object"):
            self._consume(123, produced)

    def test_strict_digest_tampering_fails_before_live_acceptance(self):
        produced = self._producer(suffix="constraints-consumer-tamper")
        constraints = produced[-1]
        payload = json.loads(constraints.to_json())
        payload["constraints_sha256"] = "0" * 64

        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            self._consume(payload, produced)

    def test_live_prior_evidence_drift_fails_after_strict_parse(self):
        produced = self._producer(suffix="constraints-consumer-live-drift")
        resolution = produced[3]
        constraints = produced[-1]

        with self.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                ("0" * 64, resolution.evidence_ids[0]),
            )

        with self.assertRaises(ValueError):
            self._consume(constraints.to_json(), produced)


if __name__ == "__main__":
    unittest.main()
