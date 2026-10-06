from __future__ import annotations

import json
import unittest

import test_future_remediation_text_review_handoff as original_handoff_tests
import test_future_remediation_text_revision_review_handoff as revision_handoff_tests
from lightup.future_remediation_authoring_request_handoff import (
    future_remediation_authoring_request_from_dict,
    future_remediation_authoring_request_from_json,
)
from lightup.future_remediation_text_review_handoff import (
    future_remediation_text_review_from_dict,
    future_remediation_text_review_from_json,
)
from lightup.future_remediation_text_revision_review_handoff import (
    future_remediation_text_revision_review_from_dict,
    future_remediation_text_revision_review_from_json,
)


class FutureRemediationNestedSchemaIntegrityTest(unittest.TestCase):
    def setUp(self):
        self.original = original_handoff_tests.FutureRemediationTextReviewHandoffTest(
            "test_approved_review_round_trips_without_action_authority"
        )
        self.original.setUp()
        self.addCleanup(self.original.tearDown)

        self.revised = (
            revision_handoff_tests.FutureRemediationTextRevisionReviewHandoffTest(
                "test_approved_review_round_trips_without_action_authority"
            )
        )
        self.revised.setUp()
        self.addCleanup(self.revised.tearDown)

    def _authoring_request(self):
        return self.original.base.base.request

    @staticmethod
    def _with_unknown_field(payload: dict) -> dict:
        mutated = dict(payload)
        mutated["unexpected_nested_field"] = "forged"
        return mutated

    @staticmethod
    def _without_field(payload: dict, field: str) -> dict:
        mutated = dict(payload)
        mutated.pop(field)
        return mutated

    def test_canonical_nested_artifacts_still_round_trip(self):
        request = self._authoring_request()

        self.assertEqual(
            future_remediation_authoring_request_from_json(request.to_json()),
            request,
        )
        self.assertEqual(
            future_remediation_text_review_from_json(self.original.review.to_json()),
            self.original.review,
        )
        self.assertEqual(
            future_remediation_text_revision_review_from_json(
                self.revised.review.to_json()
            ),
            self.revised.review,
        )

    def test_authoring_item_rejects_unknown_and_missing_fields(self):
        request = self._authoring_request()

        for mutation in ("unknown", "missing"):
            payload = json.loads(request.to_json())
            item = payload["items"][0]
            payload["items"][0] = (
                self._with_unknown_field(item)
                if mutation == "unknown"
                else self._without_field(item, "requested_output")
            )
            with self.subTest(mutation=mutation):
                with self.assertRaisesRegex(ValueError, "item schema mismatch"):
                    future_remediation_authoring_request_from_json(
                        json.dumps(payload)
                    )

    def test_authoring_evidence_ref_rejects_unknown_and_missing_fields(self):
        request = self._authoring_request()

        for mutation in ("unknown", "missing"):
            payload = json.loads(request.to_json())
            evidence = payload["items"][0]["evidence"][0]
            payload["items"][0]["evidence"][0] = (
                self._with_unknown_field(evidence)
                if mutation == "unknown"
                else self._without_field(evidence, "kind")
            )
            with self.subTest(mutation=mutation):
                with self.assertRaisesRegex(ValueError, "evidence schema mismatch"):
                    future_remediation_authoring_request_from_json(
                        json.dumps(payload)
                    )

    def test_direct_dict_path_rejects_nested_schema_widening(self):
        authoring_item = json.loads(self._authoring_request().to_json())
        authoring_item["items"][0]["unexpected_nested_field"] = "forged"

        authoring_evidence = json.loads(self._authoring_request().to_json())
        authoring_evidence["items"][0]["evidence"][0][
            "unexpected_nested_field"
        ] = "forged"

        original_review = json.loads(self.original.review.to_json())
        original_review["checks"][0]["unexpected_nested_field"] = "forged"

        revised_review = json.loads(self.revised.review.to_json())
        revised_review["checks"][0]["unexpected_nested_field"] = "forged"

        cases = (
            (
                "authoring item",
                future_remediation_authoring_request_from_dict,
                authoring_item,
            ),
            (
                "authoring evidence",
                future_remediation_authoring_request_from_dict,
                authoring_evidence,
            ),
            (
                "original review check",
                future_remediation_text_review_from_dict,
                original_review,
            ),
            (
                "revised review check",
                future_remediation_text_revision_review_from_dict,
                revised_review,
            ),
        )
        for name, parser, payload in cases:
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, "schema mismatch"):
                    parser(payload)

    def test_direct_dict_path_rejects_nested_schema_erosion(self):
        authoring_item = json.loads(self._authoring_request().to_json())
        authoring_item["items"][0].pop("requested_output")

        authoring_evidence = json.loads(self._authoring_request().to_json())
        authoring_evidence["items"][0]["evidence"][0].pop("kind")

        original_review = json.loads(self.original.review.to_json())
        original_review["checks"][0].pop("result")

        revised_review = json.loads(self.revised.review.to_json())
        revised_review["checks"][0].pop("result")

        cases = (
            (
                "authoring item",
                future_remediation_authoring_request_from_dict,
                authoring_item,
            ),
            (
                "authoring evidence",
                future_remediation_authoring_request_from_dict,
                authoring_evidence,
            ),
            (
                "original review check",
                future_remediation_text_review_from_dict,
                original_review,
            ),
            (
                "revised review check",
                future_remediation_text_revision_review_from_dict,
                revised_review,
            ),
        )
        for name, parser, payload in cases:
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, "schema mismatch"):
                    parser(payload)

    def test_nested_schema_slots_reject_non_object_values(self):
        item_payload = json.loads(self._authoring_request().to_json())
        item_payload["items"][0] = []
        with self.assertRaisesRegex(ValueError, "item schema mismatch"):
            future_remediation_authoring_request_from_json(
                json.dumps(item_payload)
            )

        evidence_payload = json.loads(self._authoring_request().to_json())
        evidence_payload["items"][0]["evidence"][0] = "forged"
        with self.assertRaisesRegex(ValueError, "evidence schema mismatch"):
            future_remediation_authoring_request_from_json(
                json.dumps(evidence_payload)
            )

        original_review_payload = json.loads(self.original.review.to_json())
        original_review_payload["checks"][0] = ["evidence_alignment", "pass"]
        with self.assertRaisesRegex(ValueError, "check schema mismatch"):
            future_remediation_text_review_from_json(
                json.dumps(original_review_payload)
            )

        revised_review_payload = json.loads(self.revised.review.to_json())
        revised_review_payload["checks"][0] = ["evidence_alignment", "pass"]
        with self.assertRaisesRegex(ValueError, "check schema mismatch"):
            future_remediation_text_revision_review_from_json(
                json.dumps(revised_review_payload)
            )

    def test_original_review_check_rejects_unknown_and_missing_fields(self):
        for mutation in ("unknown", "missing"):
            payload = json.loads(self.original.review.to_json())
            check = payload["checks"][0]
            payload["checks"][0] = (
                self._with_unknown_field(check)
                if mutation == "unknown"
                else self._without_field(check, "result")
            )
            with self.subTest(mutation=mutation):
                with self.assertRaisesRegex(ValueError, "check schema mismatch"):
                    future_remediation_text_review_from_json(json.dumps(payload))

    def test_revised_review_check_rejects_unknown_and_missing_fields(self):
        for mutation in ("unknown", "missing"):
            payload = json.loads(self.revised.review.to_json())
            check = payload["checks"][0]
            payload["checks"][0] = (
                self._with_unknown_field(check)
                if mutation == "unknown"
                else self._without_field(check, "result")
            )
            with self.subTest(mutation=mutation):
                with self.assertRaisesRegex(ValueError, "check schema mismatch"):
                    future_remediation_text_revision_review_from_json(
                        json.dumps(payload)
                    )


if __name__ == "__main__":
    unittest.main()
