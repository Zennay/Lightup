from __future__ import annotations

import copy
import json
import unittest

import test_future_remediation_text_review_request_handoff as handoff_tests
from lightup.future_remediation_text_review_request_handoff import (
    future_remediation_text_review_request_from_dict,
)


class _StringSubclass(str):
    pass


class _IntSubclass(int):
    pass


class _ListSubclass(list):
    pass


class _TupleSubclass(tuple):
    pass


class _DictSubclass(dict):
    pass


class FutureRemediationTextReviewRequestPersistedObjectTypesTest(unittest.TestCase):
    def setUp(self):
        self.base = handoff_tests.FutureRemediationTextReviewRequestHandoffTest(
            "test_round_trip_rebuilds_exact_live_review_request"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.review_request = self.base.review_request
        self.json_payload = json.loads(self.review_request.to_json())
        self.programmatic_payload = self.review_request.as_dict()

    def _assert_rejected_unchanged(self, payload):
        before = copy.deepcopy(payload)
        with self.assertRaises(ValueError):
            future_remediation_text_review_request_from_dict(payload)
        self.assertEqual(payload, before)

    def test_supported_builtin_json_and_programmatic_forms_remain_green(self):
        self.assertEqual(
            future_remediation_text_review_request_from_dict(
                copy.deepcopy(self.json_payload)
            ),
            self.review_request,
        )
        self.assertEqual(
            future_remediation_text_review_request_from_dict(
                copy.deepcopy(self.programmatic_payload)
            ),
            self.review_request,
        )
        self.assertIs(type(self.json_payload["required_checks"]), list)
        self.assertIs(type(self.programmatic_payload["required_checks"]), tuple)

    def test_top_level_mapping_subclass_fails_closed(self):
        self._assert_rejected_unchanged(
            _DictSubclass(copy.deepcopy(self.json_payload))
        )

    def test_top_level_schema_key_subclass_fails_closed(self):
        payload = copy.deepcopy(self.json_payload)
        value = payload.pop("provider_id")
        payload[_StringSubclass("provider_id")] = value
        self._assert_rejected_unchanged(payload)

    def test_lineage_provenance_and_fixed_string_subclasses_fail_closed(self):
        for field in (
            "schema_version",
            "request_sha256",
            "bundle_sha256",
            "proposal_sha256",
            "content_sha256",
            "provider_id",
            "model_id",
            "review_request_sha256",
            "future_semantics",
            "security_verdict",
        ):
            with self.subTest(field=field):
                payload = copy.deepcopy(self.json_payload)
                payload[field] = _StringSubclass(payload[field])
                self._assert_rejected_unchanged(payload)

    def test_item_count_integer_subclass_fails_closed(self):
        payload = copy.deepcopy(self.json_payload)
        payload["item_count"] = _IntSubclass(payload["item_count"])
        self._assert_rejected_unchanged(payload)

    def test_required_checks_list_and_tuple_subclasses_fail_closed(self):
        payload = copy.deepcopy(self.json_payload)
        payload["required_checks"] = _ListSubclass(payload["required_checks"])
        self._assert_rejected_unchanged(payload)

        payload = copy.deepcopy(self.programmatic_payload)
        payload["required_checks"] = _TupleSubclass(payload["required_checks"])
        self._assert_rejected_unchanged(payload)

    def test_required_check_string_subclass_fails_closed(self):
        payload = copy.deepcopy(self.json_payload)
        payload["required_checks"][0] = _StringSubclass(
            payload["required_checks"][0]
        )
        self._assert_rejected_unchanged(payload)


if __name__ == "__main__":
    unittest.main()
