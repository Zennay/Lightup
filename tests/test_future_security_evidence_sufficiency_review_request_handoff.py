from __future__ import annotations

import copy
import dataclasses
from hashlib import sha256
import json
import unittest

import test_future_security_evidence_sufficiency_review_request as request_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_security_evidence_sufficiency_review_request import (
    REQUIRED_SUFFICIENCY_REVIEW_CHECKS,
    SUFFICIENCY_REVIEW_REQUEST_SCHEMA_VERSION,
    FutureSecurityEvidenceSufficiencyReviewRequest,
    validate_future_security_evidence_sufficiency_review_request,
)
from lightup.future_security_evidence_sufficiency_review_request_handoff import (
    future_security_evidence_sufficiency_review_request_from_dict,
)


class FutureSecurityEvidenceSufficiencyReviewRequestHandoffTest(unittest.TestCase):
    def _request(self) -> FutureSecurityEvidenceSufficiencyReviewRequest:
        request = FutureSecurityEvidenceSufficiencyReviewRequest(
            schema_version=SUFFICIENCY_REVIEW_REQUEST_SCHEMA_VERSION,
            client_id="client-1",
            current_twin_id="current-twin",
            current_twin_version=11,
            twin_id="future-twin",
            twin_version=12,
            changeset_id="changeset-1",
            request_sha256="1" * 64,
            constraints_sha256="2" * 64,
            admission_sha256="3" * 64,
            metadata_review_sha256="4" * 64,
            source_resolution_id="resolution-1",
            change_node_id="change-1",
            subject_node_id="subject-1",
            candidate_run_id="run-2",
            candidate_evidence_ids=("evidence-1", "evidence-2"),
            candidate_capability_ids=("capability-a", "capability-b"),
            candidate_classification_claim=(
                AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE
            ),
            required_checks=REQUIRED_SUFFICIENCY_REVIEW_CHECKS,
            sufficiency_request_sha256="0" * 64,
        )
        payload = request.as_dict()
        payload.pop("sufficiency_request_sha256")
        digest = sha256(
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        ).hexdigest()
        return dataclasses.replace(
            request,
            sufficiency_request_sha256=digest,
        )

    def _payload(self) -> tuple[FutureSecurityEvidenceSufficiencyReviewRequest, dict]:
        request = self._request()
        return request, json.loads(request.to_json())

    def test_round_trip_restores_exact_typed_request(self):
        request, payload = self._payload()
        restored = future_security_evidence_sufficiency_review_request_from_dict(
            payload
        )
        self.assertEqual(restored, request)

    def test_real_producer_round_trip_still_requires_live_validation(self):
        base = request_tests.FutureSecurityEvidenceSufficiencyReviewRequestTest(
            "test_live_metadata_review_becomes_bounded_independent_review_request"
        )
        base.setUp()
        self.addCleanup(base.doCleanups)
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
            produced,
        ) = base._request(suffix="sufficiency-handoff-real")

        restored = future_security_evidence_sufficiency_review_request_from_dict(
            json.loads(produced.to_json())
        )
        self.assertEqual(restored, produced)
        self.assertEqual(
            validate_future_security_evidence_sufficiency_review_request(
                restored,
                review,
                admission,
                constraints,
                candidate_context=candidate_context,
                request=request,
                plan=plan,
                report=report,
                preview=preview,
                proposal=proposal,
                resolutions=(resolution,),
                source_contexts=(source_context,),
                state=base.state,
            ),
            restored,
        )

        evidence_id = admission.candidate_evidence_ids[0]
        with base.state.connect() as con:
            con.execute(
                "UPDATE evidence SET capability_id=? WHERE evidence_id=?",
                ("drifted-capability", evidence_id),
            )
        with self.assertRaisesRegex(ValueError, "live validated evidence"):
            validate_future_security_evidence_sufficiency_review_request(
                restored,
                review,
                admission,
                constraints,
                candidate_context=candidate_context,
                request=request,
                plan=plan,
                report=report,
                preview=preview,
                proposal=proposal,
                resolutions=(resolution,),
                source_contexts=(source_context,),
                state=base.state,
            )

    def test_extra_missing_and_bad_primitive_fields_fail_closed(self):
        _, payload = self._payload()
        extra = copy.deepcopy(payload)
        extra["unexpected"] = "field"
        with self.assertRaisesRegex(ValueError, "payload schema mismatch"):
            future_security_evidence_sufficiency_review_request_from_dict(extra)

        missing = copy.deepcopy(payload)
        del missing["metadata_review_sha256"]
        with self.assertRaisesRegex(ValueError, "payload schema mismatch"):
            future_security_evidence_sufficiency_review_request_from_dict(missing)

        bool_version = copy.deepcopy(payload)
        bool_version["twin_version"] = True
        with self.assertRaisesRegex(ValueError, "non-negative integer"):
            future_security_evidence_sufficiency_review_request_from_dict(
                bool_version
            )

        bad_identifier = copy.deepcopy(payload)
        bad_identifier["candidate_run_id"] = " run-2 "
        with self.assertRaisesRegex(ValueError, "canonical non-empty string"):
            future_security_evidence_sufficiency_review_request_from_dict(
                bad_identifier
            )

    def test_candidate_ids_and_required_checks_are_canonical(self):
        _, payload = self._payload()

        empty = copy.deepcopy(payload)
        empty["candidate_evidence_ids"] = []
        with self.assertRaisesRegex(ValueError, "non-empty string list"):
            future_security_evidence_sufficiency_review_request_from_dict(empty)

        unsorted = copy.deepcopy(payload)
        unsorted["candidate_evidence_ids"] = ["evidence-2", "evidence-1"]
        with self.assertRaisesRegex(ValueError, "sorted and unique"):
            future_security_evidence_sufficiency_review_request_from_dict(
                unsorted
            )

        duplicate = copy.deepcopy(payload)
        duplicate["candidate_capability_ids"] = ["capability-a", "capability-a"]
        with self.assertRaisesRegex(ValueError, "sorted and unique"):
            future_security_evidence_sufficiency_review_request_from_dict(
                duplicate
            )

        reordered_checks = copy.deepcopy(payload)
        reordered_checks["required_checks"] = list(
            reversed(REQUIRED_SUFFICIENCY_REVIEW_CHECKS)
        )
        with self.assertRaisesRegex(ValueError, "canonical independent review checks"):
            future_security_evidence_sufficiency_review_request_from_dict(
                reordered_checks
            )

        missing_check = copy.deepcopy(payload)
        missing_check["required_checks"] = ["evidence_sufficiency"]
        with self.assertRaisesRegex(ValueError, "canonical independent review checks"):
            future_security_evidence_sufficiency_review_request_from_dict(
                missing_check
            )

    def test_classification_claim_is_existing_enum_only(self):
        request, payload = self._payload()
        restored = future_security_evidence_sufficiency_review_request_from_dict(
            payload
        )
        self.assertEqual(
            restored.candidate_classification_claim,
            request.candidate_classification_claim,
        )
        self.assertFalse(restored.classification_selected)

        unsupported = copy.deepcopy(payload)
        unsupported["candidate_classification_claim"] = "secure"
        with self.assertRaisesRegex(ValueError, "claim is unsupported"):
            future_security_evidence_sufficiency_review_request_from_dict(
                unsupported
            )

    def test_review_obligations_and_safety_semantics_fail_closed(self):
        _, payload = self._payload()

        for field in (
            "metadata_contract_verified",
            "freshness_check_passed",
            "independent_verifier_required",
            "review_required",
        ):
            forged = copy.deepcopy(payload)
            forged[field] = False
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, f"{field} must remain true"):
                    future_security_evidence_sufficiency_review_request_from_dict(
                        forged
                    )

        for field in (
            "evidence_sufficiency_evaluated",
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
        ):
            forged = copy.deepcopy(payload)
            forged[field] = True
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, f"{field} must remain false"):
                    future_security_evidence_sufficiency_review_request_from_dict(
                        forged
                    )

        semantics = copy.deepcopy(payload)
        semantics["future_semantics"] = "verified"
        with self.assertRaisesRegex(ValueError, "must remain unresolved"):
            future_security_evidence_sufficiency_review_request_from_dict(semantics)

        verdict = copy.deepcopy(payload)
        verdict["security_verdict"] = "secure"
        with self.assertRaisesRegex(ValueError, "must not claim a security verdict"):
            future_security_evidence_sufficiency_review_request_from_dict(verdict)

    def test_noncanonical_sha_and_digest_tampering_fail_closed(self):
        _, payload = self._payload()

        uppercase = copy.deepcopy(payload)
        uppercase["metadata_review_sha256"] = uppercase[
            "metadata_review_sha256"
        ].upper()
        with self.assertRaisesRegex(ValueError, "canonical lowercase SHA-256"):
            future_security_evidence_sufficiency_review_request_from_dict(
                uppercase
            )

        changed = copy.deepcopy(payload)
        changed["subject_node_id"] = "subject-2"
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            future_security_evidence_sufficiency_review_request_from_dict(changed)

        digest = copy.deepcopy(payload)
        digest["sufficiency_request_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            future_security_evidence_sufficiency_review_request_from_dict(digest)


if __name__ == "__main__":
    unittest.main()
