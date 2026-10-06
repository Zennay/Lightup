from __future__ import annotations

import json
import unittest

import test_future_security_evidence_collection_request as request_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_security_evidence_collection_request_consumer import (
    load_and_validate_future_security_evidence_collection_request,
)


class FutureSecurityEvidenceCollectionRequestConsumerTest(unittest.TestCase):
    def setUp(self):
        self.base = request_tests.FutureSecurityEvidenceCollectionRequestTest(
            "test_insufficient_evidence_produces_fresh_evidence_request_only"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.state = self.base.state

    def _producer(self, *, suffix: str):
        return self.base._request(
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
            suffix=suffix,
        )

    def _consume(self, persisted: object, produced: tuple):
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            _,
        ) = produced
        return load_and_validate_future_security_evidence_collection_request(
            persisted,
            plan,
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )

    def test_real_producer_json_is_strictly_parsed_and_live_validated(self):
        produced = self._producer(suffix="collection-consumer-roundtrip")
        request = produced[-1]

        consumed = self._consume(request.to_json(), produced)

        self.assertEqual(consumed, request)
        self.assertEqual(consumed.evidence_gap_count, 1)
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
        produced = self._producer(suffix="collection-consumer-json")
        request = produced[-1]

        with self.assertRaisesRegex(ValueError, "persisted JSON is invalid"):
            self._consume("{", produced)

        with self.assertRaisesRegex(ValueError, "duplicate object keys"):
            self._consume(
                '{"schema_version":"a","schema_version":"b"}',
                produced,
            )

        duplicate_nested = request.to_json().replace(
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
        produced = self._producer(suffix="collection-consumer-tamper")
        request = produced[-1]
        payload = json.loads(request.to_json())
        payload["request_sha256"] = "0" * 64

        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            self._consume(payload, produced)

    def test_deleted_live_evidence_fails_after_strict_parse(self):
        produced = self._producer(suffix="collection-consumer-live-drift")
        resolution = produced[3]
        request = produced[-1]

        with self.state.connect() as con:
            con.execute(
                "DELETE FROM evidence WHERE evidence_id=?",
                (resolution.evidence_ids[0],),
            )

        with self.assertRaises(KeyError):
            self._consume(request.to_json(), produced)


if __name__ == "__main__":
    unittest.main()
