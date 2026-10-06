from __future__ import annotations

import copy
import json
import unittest

import test_future_security_classification_review_request_handoff as classification_handoff_tests
import test_future_security_evidence_collection_handoff as collection_handoff_tests
import test_future_security_evidence_freshness_admission_handoff as admission_handoff_tests
import test_future_security_evidence_freshness_handoff as freshness_handoff_tests
import test_future_security_evidence_sufficiency_attestation_handoff as attestation_handoff_tests
from lightup.future_security_classification_review_request_handoff import (
    future_security_classification_review_request_from_dict,
)
from lightup.future_security_evidence_collection_request import (
    future_security_evidence_collection_request_from_dict,
)
from lightup.future_security_evidence_freshness import (
    future_security_evidence_freshness_constraints_from_dict,
)
from lightup.future_security_evidence_freshness_admission_handoff import (
    future_security_evidence_freshness_admission_from_dict,
)
from lightup.future_security_evidence_sufficiency_attestation import (
    EvidenceSufficiencyAttestationDisposition,
)
from lightup.future_security_evidence_sufficiency_attestation_handoff import (
    future_security_evidence_sufficiency_attestation_from_dict,
)


class EvidenceRemediationParserInputPurityTest(unittest.TestCase):
    def _fixture(self, helper):
        helper.setUp()
        self.addCleanup(helper.doCleanups)
        return helper

    def _assert_input_pure(self, parser, artifact, payload):
        original = copy.deepcopy(payload)

        first = parser(payload)
        self.assertEqual(payload, original)
        self.assertEqual(first, artifact)

        second = parser(payload)
        self.assertEqual(payload, original)
        self.assertEqual(second, artifact)
        self.assertEqual(second, first)
        self.assertEqual(second.to_json(), artifact.to_json())

    def test_collection_request_parser_does_not_mutate_payload(self):
        helper = self._fixture(
            collection_handoff_tests.FutureSecurityEvidenceCollectionHandoffTest(
                "test_round_trip_restores_exact_typed_request"
            )
        )
        artifact, payload = helper._payload()

        self._assert_input_pure(
            future_security_evidence_collection_request_from_dict,
            artifact,
            payload,
        )

    def test_freshness_constraints_parser_does_not_mutate_payload(self):
        helper = self._fixture(
            freshness_handoff_tests.FutureSecurityEvidenceFreshnessHandoffTest(
                "test_round_trip_restores_exact_typed_constraints"
            )
        )
        artifact, payload = helper._payload()

        self._assert_input_pure(
            future_security_evidence_freshness_constraints_from_dict,
            artifact,
            payload,
        )

    def test_freshness_admission_parser_does_not_mutate_payload(self):
        helper = self._fixture(
            admission_handoff_tests.FutureSecurityEvidenceFreshnessAdmissionHandoffTest(
                "test_round_trip_restores_exact_typed_admission"
            )
        )
        artifact, payload = helper._payload()

        self._assert_input_pure(
            future_security_evidence_freshness_admission_from_dict,
            artifact,
            payload,
        )

    def test_sufficiency_attestation_parser_does_not_mutate_payload(self):
        helper = self._fixture(
            attestation_handoff_tests.FutureSecurityEvidenceSufficiencyAttestationHandoffTest(
                "test_all_dispositions_round_trip_with_exact_derived_flags"
            )
        )
        values, payload = helper._payload(
            EvidenceSufficiencyAttestationDisposition.SUFFICIENT_CLAIM_JUSTIFIED,
            suffix="parser-input-purity",
        )
        artifact = values[-1]

        self._assert_input_pure(
            future_security_evidence_sufficiency_attestation_from_dict,
            artifact,
            payload,
        )

    def test_classification_review_request_parser_does_not_mutate_payload(self):
        helper = self._fixture(
            classification_handoff_tests.FutureSecurityClassificationReviewRequestHandoffTest(
                "test_exact_round_trip_preserves_fail_closed_semantics"
            )
        )
        *_, artifact = helper._producer(suffix="parser-input-purity")
        payload = json.loads(artifact.to_json())

        self._assert_input_pure(
            future_security_classification_review_request_from_dict,
            artifact,
            payload,
        )


if __name__ == "__main__":
    unittest.main()
