from __future__ import annotations

from hashlib import sha256
import json
import unittest
from unittest.mock import patch

from lightup.future_remediation_implementation_plan_review_request import (
    REQUIRED_IMPLEMENTATION_PLAN_REVIEW_CHECKS,
)
from lightup.future_remediation_implementation_plan_revision_request import (
    REMEDIATION_IMPLEMENTATION_PLAN_REVISION_REQUEST_SCHEMA_VERSION,
    FutureRemediationImplementationPlanRevisionRequest,
)
from lightup.future_remediation_implementation_plan_revision_request_handoff import (
    future_remediation_implementation_plan_revision_request_from_dict,
    future_remediation_implementation_plan_revision_request_from_json,
    load_and_validate_future_remediation_implementation_plan_revision_request,
)


_AUTHORITY_FLAGS = (
    "code_change_authorized",
    "tool_call_created",
    "execution_allowed",
    "target_interaction_allowed",
    "future_state_retest_allowed",
    "deployment_authorized",
    "attack_path_mutation_allowed",
)


def _request_digest(
    *,
    review_sha256: str,
    review_request_sha256: str,
    plan_sha256: str,
    implementation_request_sha256: str,
    reviewer_provider_id: str,
    reviewer_model_id: str,
    required_revisions: tuple[str, ...],
) -> str:
    payload = {
        "schema_version": REMEDIATION_IMPLEMENTATION_PLAN_REVISION_REQUEST_SCHEMA_VERSION,
        "review_sha256": review_sha256,
        "review_request_sha256": review_request_sha256,
        "plan_sha256": plan_sha256,
        "implementation_request_sha256": implementation_request_sha256,
        "reviewer_provider_id": reviewer_provider_id,
        "reviewer_model_id": reviewer_model_id,
        "required_revisions": list(required_revisions),
        "source_review_decision": "revision_required",
        "implementation_plan_revision_requested": True,
        "revised_implementation_plan_created": False,
        "implementation_plan_accepted": False,
        "code_change_authorized": False,
        "tool_call_created": False,
        "execution_allowed": False,
        "target_interaction_allowed": False,
        "future_state_retest_allowed": False,
        "deployment_authorized": False,
        "attack_path_mutation_allowed": False,
        "future_semantics": "unresolved",
        "security_verdict": "not_evaluated",
    }
    return sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _request(
    *,
    required_revisions: tuple[str, ...] | None = None,
    reviewer_model_id: str = "verifier-model",
) -> FutureRemediationImplementationPlanRevisionRequest:
    revisions = (
        tuple(REQUIRED_IMPLEMENTATION_PLAN_REVIEW_CHECKS[:1])
        if required_revisions is None
        else required_revisions
    )
    review_sha256 = "1" * 64
    review_request_sha256 = "2" * 64
    plan_sha256 = "3" * 64
    implementation_request_sha256 = "4" * 64
    reviewer_provider_id = "test-provider"
    digest = _request_digest(
        review_sha256=review_sha256,
        review_request_sha256=review_request_sha256,
        plan_sha256=plan_sha256,
        implementation_request_sha256=implementation_request_sha256,
        reviewer_provider_id=reviewer_provider_id,
        reviewer_model_id=reviewer_model_id,
        required_revisions=revisions,
    )
    return FutureRemediationImplementationPlanRevisionRequest(
        schema_version=REMEDIATION_IMPLEMENTATION_PLAN_REVISION_REQUEST_SCHEMA_VERSION,
        review_sha256=review_sha256,
        review_request_sha256=review_request_sha256,
        plan_sha256=plan_sha256,
        implementation_request_sha256=implementation_request_sha256,
        reviewer_provider_id=reviewer_provider_id,
        reviewer_model_id=reviewer_model_id,
        required_revisions=revisions,
        revision_request_sha256=digest,
    )


class FutureRemediationImplementationPlanRevisionRequestHandoffTest(
    unittest.TestCase
):
    def setUp(self):
        self.request = _request()

    def test_programmatic_and_json_forms_round_trip_exactly(self):
        from_dict = (
            future_remediation_implementation_plan_revision_request_from_dict(
                self.request.as_dict()
            )
        )
        from_json = (
            future_remediation_implementation_plan_revision_request_from_json(
                self.request.to_json()
            )
        )

        self.assertEqual(from_dict, self.request)
        self.assertEqual(from_json, self.request)
        self.assertTrue(from_json.implementation_plan_revision_requested)
        self.assertFalse(from_json.revised_implementation_plan_created)
        self.assertFalse(from_json.implementation_plan_accepted)
        for field in _AUTHORITY_FLAGS:
            self.assertFalse(getattr(from_json, field))
        self.assertEqual(from_json.future_semantics, "unresolved")
        self.assertEqual(from_json.security_verdict, "not_evaluated")

    def test_schema_digest_provenance_and_authority_tampering_fail_closed(self):
        extra = self.request.as_dict()
        extra["unexpected"] = "field"
        with self.assertRaisesRegex(ValueError, "schema mismatch"):
            future_remediation_implementation_plan_revision_request_from_dict(
                extra
            )

        missing = self.request.as_dict()
        missing.pop("plan_sha256")
        with self.assertRaisesRegex(ValueError, "schema mismatch"):
            future_remediation_implementation_plan_revision_request_from_dict(
                missing
            )

        digest = self.request.as_dict()
        digest["revision_request_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            future_remediation_implementation_plan_revision_request_from_dict(
                digest
            )

        blank_model = self.request.as_dict()
        blank_model["reviewer_model_id"] = " "
        with self.assertRaisesRegex(ValueError, "non-empty string"):
            future_remediation_implementation_plan_revision_request_from_dict(
                blank_model
            )

        for field in _AUTHORITY_FLAGS:
            with self.subTest(field=field):
                widened = self.request.as_dict()
                widened[field] = True
                with self.assertRaisesRegex(ValueError, "authority flag"):
                    future_remediation_implementation_plan_revision_request_from_dict(
                        widened
                    )

    def test_required_revisions_are_unique_known_and_canonically_ordered(self):
        duplicate = self.request.as_dict()
        duplicate["required_revisions"] = [
            REQUIRED_IMPLEMENTATION_PLAN_REVIEW_CHECKS[0],
            REQUIRED_IMPLEMENTATION_PLAN_REVIEW_CHECKS[0],
        ]
        with self.assertRaisesRegex(ValueError, "must be unique"):
            future_remediation_implementation_plan_revision_request_from_dict(
                duplicate
            )

        unknown = self.request.as_dict()
        unknown["required_revisions"] = ["not_a_real_check"]
        with self.assertRaisesRegex(ValueError, "invalid or out of order"):
            future_remediation_implementation_plan_revision_request_from_dict(
                unknown
            )

        out_of_order = self.request.as_dict()
        out_of_order["required_revisions"] = [
            REQUIRED_IMPLEMENTATION_PLAN_REVIEW_CHECKS[1],
            REQUIRED_IMPLEMENTATION_PLAN_REVIEW_CHECKS[0],
        ]
        with self.assertRaisesRegex(ValueError, "invalid or out of order"):
            future_remediation_implementation_plan_revision_request_from_dict(
                out_of_order
            )

        empty = self.request.as_dict()
        empty["required_revisions"] = []
        with self.assertRaisesRegex(ValueError, "must be non-empty"):
            future_remediation_implementation_plan_revision_request_from_dict(
                empty
            )

    def test_duplicate_json_keys_are_rejected_before_decode(self):
        raw = self.request.to_json()
        duplicate = (
            raw[:-1]
            + ',"revision_request_sha256":"'
            + ("0" * 64)
            + '"}'
        )

        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            future_remediation_implementation_plan_revision_request_from_json(
                duplicate
            )

    def test_live_validation_rebuilds_exact_request_without_other_authority(self):
        args = [object() for _ in range(16)]
        with patch(
            "lightup.future_remediation_implementation_plan_revision_request_handoff."
            "build_future_remediation_implementation_plan_revision_request",
            return_value=self.request,
        ) as builder:
            validated = (
                load_and_validate_future_remediation_implementation_plan_revision_request(
                    self.request.to_json(),
                    *args,
                )
            )

        self.assertEqual(validated, self.request)
        builder.assert_called_once_with(*args)

    def test_live_lineage_substitution_fails_closed(self):
        alternate = _request(
            required_revisions=tuple(
                REQUIRED_IMPLEMENTATION_PLAN_REVIEW_CHECKS[:2]
            )
        )
        args = [object() for _ in range(16)]
        with patch(
            "lightup.future_remediation_implementation_plan_revision_request_handoff."
            "build_future_remediation_implementation_plan_revision_request",
            return_value=alternate,
        ):
            with self.assertRaisesRegex(ValueError, "does not match"):
                load_and_validate_future_remediation_implementation_plan_revision_request(
                    self.request.as_dict(),
                    *args,
                )

    def test_persisted_value_type_is_exactly_json_text_or_object(self):
        args = [object() for _ in range(16)]
        with self.assertRaisesRegex(ValueError, "JSON text or object"):
            load_and_validate_future_remediation_implementation_plan_revision_request(
                [],
                *args,
            )


if __name__ == "__main__":
    unittest.main()
