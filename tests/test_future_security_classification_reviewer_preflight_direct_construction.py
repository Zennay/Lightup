from __future__ import annotations

import dataclasses
from hashlib import sha256
import json
import unittest

import test_future_security_classification_reviewer_preflight as preflight_tests
from lightup.future_security_classification_reviewer_preflight import (
    FutureSecurityClassificationReviewerPreflight,
)


_FALSE_FIELDS = (
    "classification_decision_created",
    "classification_selected",
    "transition_resolution_created",
    "collection_authorized",
    "tool_call_created",
    "execution_allowed",
    "target_interaction_allowed",
    "remediation_authoring_allowed",
    "future_state_retest_allowed",
    "deployment_authorized",
    "attack_path_mutation_allowed",
)


class FutureSecurityClassificationReviewerPreflightDirectConstructionTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = preflight_tests.FutureSecurityClassificationReviewerPreflightTest()
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _canonical(self):
        _, _, reviewer_preflight = self.base._preflight(
            suffix="classification-preflight-direct-construction"
        )
        return reviewer_preflight

    def _payload_with_digest(self, reviewer_preflight, **changes):
        payload = dataclasses.asdict(reviewer_preflight)
        payload.update(changes)
        digest_payload = dict(payload)
        digest_payload.pop("preflight_sha256", None)
        claim = digest_payload["candidate_classification_claim"]
        digest_payload["candidate_classification_claim"] = claim.value
        payload["preflight_sha256"] = sha256(
            json.dumps(
                digest_payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        ).hexdigest()
        return payload

    def test_canonical_preflight_can_be_reconstructed_directly(self):
        reviewer_preflight = self._canonical()
        rebuilt = FutureSecurityClassificationReviewerPreflight(
            **dataclasses.asdict(reviewer_preflight)
        )
        self.assertEqual(rebuilt, reviewer_preflight)

    def test_schema_identity_lineage_and_collection_invariants_fail_closed(self):
        reviewer_preflight = self._canonical()

        invalid_cases = (
            ("schema_version", "st5.classification_reviewer_preflight.v0"),
            ("client_id", " client-1 "),
            ("classification_review_request_sha256", "A" * 64),
            ("attestation_sha256", "0" * 63),
            ("candidate_evidence_ids", list(reviewer_preflight.candidate_evidence_ids)),
            (
                "candidate_evidence_ids",
                reviewer_preflight.candidate_evidence_ids
                + (reviewer_preflight.candidate_evidence_ids[0],),
            ),
            (
                "candidate_evidence_ids",
                tuple(reversed(reviewer_preflight.candidate_evidence_ids)),
            ),
            (
                "candidate_capability_ids",
                list(reviewer_preflight.candidate_capability_ids),
            ),
            (
                "candidate_classification_claim",
                reviewer_preflight.candidate_classification_claim.value,
            ),
            (
                "classification_reviewer_user_id",
                reviewer_preflight.sufficiency_verifier_user_id,
            ),
            ("classification_reviewer_role", "client_admin"),
        )

        for field, value in invalid_cases:
            with self.subTest(field=field, value=value):
                with self.assertRaisesRegex(ValueError, field):
                    dataclasses.replace(reviewer_preflight, **{field: value})

    def test_matching_digest_cannot_authorize_or_resolve_future_state(self):
        reviewer_preflight = self._canonical()

        forged_cases = [
            ("independent_reviewer_verified", False),
            ("eligible_for_classification_review", False),
            *( (field, True) for field in _FALSE_FIELDS ),
            ("future_semantics", "resolved"),
            ("security_verdict", "secure"),
        ]

        for field, value in forged_cases:
            with self.subTest(field=field):
                payload = self._payload_with_digest(
                    reviewer_preflight,
                    **{field: value},
                )
                with self.assertRaisesRegex(ValueError, field):
                    FutureSecurityClassificationReviewerPreflight(**payload)

    def test_digest_is_bound_to_all_typed_preflight_state(self):
        reviewer_preflight = self._canonical()
        with self.assertRaisesRegex(ValueError, "preflight_sha256"):
            dataclasses.replace(
                reviewer_preflight,
                classification_reviewer_user_id=(
                    reviewer_preflight.classification_reviewer_user_id + "-other"
                ),
            )


if __name__ == "__main__":
    unittest.main()
