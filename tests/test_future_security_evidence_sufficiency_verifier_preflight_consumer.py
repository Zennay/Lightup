from __future__ import annotations

import unittest

import test_future_security_evidence_sufficiency_verifier_preflight as preflight_tests
from lightup.domain import AccessContext, Role
from lightup.future_security_evidence_sufficiency_verifier_preflight_consumer import (
    load_and_validate_future_security_evidence_sufficiency_verifier_preflight,
)


class FutureSecurityEvidenceSufficiencyVerifierPreflightConsumerTest(unittest.TestCase):
    def setUp(self):
        self.base = preflight_tests.FutureSecurityEvidenceSufficiencyVerifierPreflightTest(
            "test_operator_context_creates_bounded_eligibility_only"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.state = self.base.state

    def _producer(self, *, suffix: str):
        return self.base._preflight(suffix=suffix)

    def _consume(self, persisted: object, produced: tuple, *, verifier=None):
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
            admission,
            review,
            sufficiency_request,
            source_verifier,
            _,
        ) = produced
        return load_and_validate_future_security_evidence_sufficiency_verifier_preflight(
            persisted,
            sufficiency_request,
            review,
            admission,
            constraints,
            verifier=source_verifier if verifier is None else verifier,
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
        produced = self._producer(suffix="preflight-consumer-roundtrip")
        preflight = produced[-1]
        consumed = self._consume(preflight.to_json(), produced)

        self.assertEqual(consumed, preflight)
        self.assertTrue(consumed.eligible_for_sufficiency_review)
        self.assertFalse(consumed.sufficiency_decision_created)
        self.assertFalse(consumed.evidence_sufficiency_evaluated)
        self.assertFalse(consumed.classification_selected)
        self.assertFalse(consumed.transition_resolution_created)
        self.assertFalse(consumed.execution_allowed)
        self.assertFalse(consumed.target_interaction_allowed)
        self.assertFalse(consumed.remediation_authoring_allowed)
        self.assertFalse(consumed.future_state_retest_allowed)
        self.assertFalse(consumed.deployment_authorized)
        self.assertFalse(consumed.attack_path_mutation_allowed)

    def test_invalid_duplicate_and_non_object_json_fail_closed(self):
        produced = self._producer(suffix="preflight-consumer-json")
        with self.assertRaisesRegex(ValueError, "persisted JSON is invalid"):
            self._consume("{", produced)
        with self.assertRaisesRegex(ValueError, "duplicate object keys"):
            self._consume('{"schema_version":"a","schema_version":"b"}', produced)
        with self.assertRaisesRegex(ValueError, "persisted payload must be an object"):
            self._consume("[]", produced)
        with self.assertRaisesRegex(ValueError, "JSON text or object"):
            self._consume(123, produced)

    def test_strict_digest_tampering_fails_before_live_acceptance(self):
        produced = self._producer(suffix="preflight-consumer-tamper")
        preflight = produced[-1]
        payload = preflight.as_dict()
        payload["preflight_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            self._consume(payload, produced)

    def test_changed_live_verifier_identity_fails_after_strict_parse(self):
        produced = self._producer(suffix="preflight-consumer-verifier-drift")
        preflight = produced[-1]
        different = AccessContext(user_id="operator-different", role=Role.OPERATOR)

        with self.assertRaisesRegex(ValueError, "does not match live validated lineage"):
            self._consume(preflight.to_json(), produced, verifier=different)


if __name__ == "__main__":
    unittest.main()
