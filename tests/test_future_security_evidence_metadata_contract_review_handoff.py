from __future__ import annotations

import copy
import dataclasses
from hashlib import sha256
import json
import unittest

from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_security_evidence_metadata_contract_review import (
    REVIEW_SCHEMA_VERSION,
    FutureSecurityEvidenceMetadataContractReview,
)
from lightup.future_security_evidence_metadata_contract_review_handoff import (
    future_security_evidence_metadata_contract_review_from_dict,
)


class FutureSecurityEvidenceMetadataContractReviewHandoffTest(unittest.TestCase):
    def _review(self) -> FutureSecurityEvidenceMetadataContractReview:
        review = FutureSecurityEvidenceMetadataContractReview(
            schema_version=REVIEW_SCHEMA_VERSION,
            client_id="client-1",
            current_twin_id="current-twin",
            current_twin_version=7,
            twin_id="future-twin",
            twin_version=8,
            changeset_id="changeset-1",
            request_sha256="1" * 64,
            constraints_sha256="2" * 64,
            admission_sha256="3" * 64,
            source_resolution_id="resolution-1",
            change_node_id="change-1",
            subject_node_id="subject-1",
            candidate_run_id="run-2",
            candidate_evidence_ids=("evidence-1", "evidence-2"),
            candidate_capability_ids=("capability-a", "capability-b"),
            candidate_classification_claim=(
                AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE
            ),
            metadata_contract_verified=True,
            review_sha256="0" * 64,
        )
        payload = review.as_dict()
        payload.pop("review_sha256")
        digest = sha256(
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        ).hexdigest()
        return dataclasses.replace(review, review_sha256=digest)

    def _payload(self) -> tuple[FutureSecurityEvidenceMetadataContractReview, dict]:
        review = self._review()
        return review, json.loads(review.to_json())

    def test_round_trip_restores_exact_typed_review(self):
        review, payload = self._payload()
        restored = future_security_evidence_metadata_contract_review_from_dict(
            payload
        )
        self.assertEqual(restored, review)

    def test_extra_missing_and_bad_primitive_fields_fail_closed(self):
        _, payload = self._payload()

        extra = copy.deepcopy(payload)
        extra["unexpected"] = "field"
        with self.assertRaisesRegex(ValueError, "payload schema mismatch"):
            future_security_evidence_metadata_contract_review_from_dict(extra)

        missing = copy.deepcopy(payload)
        del missing["constraints_sha256"]
        with self.assertRaisesRegex(ValueError, "payload schema mismatch"):
            future_security_evidence_metadata_contract_review_from_dict(missing)

        bool_version = copy.deepcopy(payload)
        bool_version["current_twin_version"] = True
        with self.assertRaisesRegex(ValueError, "non-negative integer"):
            future_security_evidence_metadata_contract_review_from_dict(
                bool_version
            )

        bad_identifier = copy.deepcopy(payload)
        bad_identifier["candidate_run_id"] = " run-2 "
        with self.assertRaisesRegex(ValueError, "canonical non-empty string"):
            future_security_evidence_metadata_contract_review_from_dict(
                bad_identifier
            )

    def test_candidate_identity_lists_must_be_non_empty_sorted_and_unique(self):
        _, payload = self._payload()

        empty = copy.deepcopy(payload)
        empty["candidate_evidence_ids"] = []
        with self.assertRaisesRegex(ValueError, "non-empty string list"):
            future_security_evidence_metadata_contract_review_from_dict(empty)

        unsorted = copy.deepcopy(payload)
        unsorted["candidate_evidence_ids"] = ["evidence-2", "evidence-1"]
        with self.assertRaisesRegex(ValueError, "sorted and unique"):
            future_security_evidence_metadata_contract_review_from_dict(
                unsorted
            )

        duplicate = copy.deepcopy(payload)
        duplicate["candidate_capability_ids"] = ["capability-a", "capability-a"]
        with self.assertRaisesRegex(ValueError, "sorted and unique"):
            future_security_evidence_metadata_contract_review_from_dict(
                duplicate
            )

    def test_classification_claim_is_parsed_as_existing_enum_only(self):
        review, payload = self._payload()
        restored = future_security_evidence_metadata_contract_review_from_dict(
            payload
        )
        self.assertEqual(
            restored.candidate_classification_claim,
            review.candidate_classification_claim,
        )
        self.assertFalse(restored.classification_selected)

        unsupported = copy.deepcopy(payload)
        unsupported["candidate_classification_claim"] = "secure"
        with self.assertRaisesRegex(ValueError, "claim is unsupported"):
            future_security_evidence_metadata_contract_review_from_dict(
                unsupported
            )

        non_string = copy.deepcopy(payload)
        non_string["candidate_classification_claim"] = 1
        with self.assertRaisesRegex(ValueError, "claim must be a string"):
            future_security_evidence_metadata_contract_review_from_dict(
                non_string
            )

    def test_verified_freshness_and_safety_semantics_fail_closed(self):
        _, payload = self._payload()

        not_verified = copy.deepcopy(payload)
        not_verified["metadata_contract_verified"] = False
        with self.assertRaisesRegex(ValueError, "retain verified metadata contract"):
            future_security_evidence_metadata_contract_review_from_dict(
                not_verified
            )

        stale = copy.deepcopy(payload)
        stale["freshness_check_passed"] = False
        with self.assertRaisesRegex(ValueError, "retain passed freshness check"):
            future_security_evidence_metadata_contract_review_from_dict(stale)

        classified = copy.deepcopy(payload)
        classified["classification_selected"] = True
        with self.assertRaisesRegex(ValueError, "classification_selected must remain false"):
            future_security_evidence_metadata_contract_review_from_dict(
                classified
            )

        executable = copy.deepcopy(payload)
        executable["execution_allowed"] = True
        with self.assertRaisesRegex(ValueError, "execution_allowed must remain false"):
            future_security_evidence_metadata_contract_review_from_dict(
                executable
            )

        closed = copy.deepcopy(payload)
        closed["transition_resolution_created"] = True
        with self.assertRaisesRegex(
            ValueError,
            "transition_resolution_created must remain false",
        ):
            future_security_evidence_metadata_contract_review_from_dict(closed)

        verdict = copy.deepcopy(payload)
        verdict["security_verdict"] = "secure"
        with self.assertRaisesRegex(ValueError, "must not claim a security verdict"):
            future_security_evidence_metadata_contract_review_from_dict(verdict)

    def test_noncanonical_sha_and_digest_tampering_fail_closed(self):
        _, payload = self._payload()

        uppercase = copy.deepcopy(payload)
        uppercase["review_sha256"] = uppercase["review_sha256"].upper()
        with self.assertRaisesRegex(ValueError, "canonical lowercase SHA-256"):
            future_security_evidence_metadata_contract_review_from_dict(
                uppercase
            )

        changed = copy.deepcopy(payload)
        changed["subject_node_id"] = "subject-2"
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            future_security_evidence_metadata_contract_review_from_dict(
                changed
            )

        digest = copy.deepcopy(payload)
        digest["review_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            future_security_evidence_metadata_contract_review_from_dict(digest)


if __name__ == "__main__":
    unittest.main()
