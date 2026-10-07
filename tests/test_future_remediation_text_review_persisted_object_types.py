from __future__ import annotations

import copy
import json
import unittest

import test_future_remediation_text_review_handoff as handoff_tests
from lightup.future_remediation_text_review_handoff import (
    future_remediation_text_review_from_dict,
)


class _StringSubclass(str):
    pass


class _ListSubclass(list):
    pass


class _DictSubclass(dict):
    pass


class FutureRemediationTextReviewPersistedObjectTypesTest(unittest.TestCase):
    def setUp(self):
        self.base = handoff_tests.FutureRemediationTextReviewHandoffTest(
            "test_approved_review_round_trips_without_action_authority"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.review = self.base.review
        self.payload = json.loads(self.review.to_json())

    def _assert_rejected_unchanged(self, payload):
        before = copy.deepcopy(payload)
        with self.assertRaises(ValueError):
            future_remediation_text_review_from_dict(payload)
        self.assertEqual(payload, before)

    def test_canonical_json_decoded_object_remains_green(self):
        parsed = future_remediation_text_review_from_dict(
            copy.deepcopy(self.payload)
        )
        self.assertEqual(parsed, self.review)

    def test_top_level_mapping_subclass_fails_closed(self):
        self._assert_rejected_unchanged(_DictSubclass(copy.deepcopy(self.payload)))

    def test_top_level_schema_key_subclass_fails_closed(self):
        payload = copy.deepcopy(self.payload)
        value = payload.pop("reviewer_provider_id")
        payload[_StringSubclass("reviewer_provider_id")] = value
        self._assert_rejected_unchanged(payload)

    def test_checks_container_and_mapping_subclasses_fail_closed(self):
        payload = copy.deepcopy(self.payload)
        payload["checks"] = _ListSubclass(payload["checks"])
        self._assert_rejected_unchanged(payload)

        payload = copy.deepcopy(self.payload)
        payload["checks"][0] = _DictSubclass(payload["checks"][0])
        self._assert_rejected_unchanged(payload)

    def test_nested_check_schema_key_subclass_fails_closed(self):
        payload = copy.deepcopy(self.payload)
        check = payload["checks"][0]
        value = check.pop("check")
        check[_StringSubclass("check")] = value
        self._assert_rejected_unchanged(payload)

    def test_lineage_provenance_and_fixed_string_subclasses_fail_closed(self):
        for field in (
            "schema_version",
            "review_request_sha256",
            "proposal_sha256",
            "content_sha256",
            "reviewer_provider_id",
            "reviewer_model_id",
            "review_sha256",
            "future_semantics",
            "security_verdict",
        ):
            with self.subTest(field=field):
                payload = copy.deepcopy(self.payload)
                payload[field] = _StringSubclass(payload[field])
                self._assert_rejected_unchanged(payload)

    def test_decision_check_result_and_summary_subclasses_fail_closed(self):
        payload = copy.deepcopy(self.payload)
        payload["decision"] = _StringSubclass(payload["decision"])
        self._assert_rejected_unchanged(payload)

        payload = copy.deepcopy(self.payload)
        payload["checks"][0]["check"] = _StringSubclass(
            payload["checks"][0]["check"]
        )
        self._assert_rejected_unchanged(payload)

        payload = copy.deepcopy(self.payload)
        payload["checks"][0]["result"] = _StringSubclass(
            payload["checks"][0]["result"]
        )
        self._assert_rejected_unchanged(payload)

        payload = copy.deepcopy(self.payload)
        payload["summary"] = _StringSubclass(payload["summary"])
        self._assert_rejected_unchanged(payload)


if __name__ == "__main__":
    unittest.main()
