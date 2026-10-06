from __future__ import annotations

import json
import unittest

import test_future_remediation_text_review_handoff as original_handoff_tests
import test_future_remediation_text_revision_review_handoff as revision_handoff_tests
from lightup.future_remediation_authoring_request_handoff import (
    future_remediation_authoring_request_from_json,
)
from lightup.future_remediation_text_review_handoff import (
    future_remediation_text_review_from_json,
)
from lightup.future_remediation_text_revision_review_handoff import (
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
