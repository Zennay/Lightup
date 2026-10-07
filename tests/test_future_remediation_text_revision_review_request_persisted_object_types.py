from __future__ import annotations

import copy
import json
import unittest

import test_future_remediation_text_revision_review_request_handoff as handoff_tests
from lightup.future_remediation_text_revision_review_request_handoff import (
    future_remediation_text_revision_review_request_from_dict,
)


class _StringSubclass(str):
    pass


class _ListSubclass(list):
    pass


class _TupleSubclass(tuple):
    pass


class _DictSubclass(dict):
    pass


class FutureRemediationTextRevisionReviewRequestPersistedObjectTypesTest(unittest.TestCase):
    def setUp(self):
        self.base = handoff_tests.FutureRemediationTextRevisionReviewRequestHandoffTest(
            "test_round_trip_rebuilds_exact_live_review_request"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.request = self.base.request
        self.json_payload = json.loads(self.request.to_json())
        self.programmatic_payload = self.request.as_dict()

    def _assert_rejected_unchanged(self, payload):
        before = copy.deepcopy(payload)
        with self.assertRaises(ValueError):
            future_remediation_text_revision_review_request_from_dict(payload)
        self.assertEqual(payload, before)

    def test_supported_builtin_json_and_programmatic_forms_remain_green(self):
        self.assertEqual(
            future_remediation_text_revision_review_request_from_dict(
                copy.deepcopy(self.json_payload)
            ),
            self.request,
        )
        self.assertEqual(
            future_remediation_text_revision_review_request_from_dict(
                copy.deepcopy(self.programmatic_payload)
            ),
            self.request,
        )
        self.assertIs(type(self.json_payload["required_checks"]), list)
        self.assertIs(type(self.programmatic_payload["required_checks"]), tuple)

    def test_top_level_mapping_and_schema_key_subclasses_fail_closed(self):
        self._assert_rejected_unchanged(
            _DictSubclass(copy.deepcopy(self.json_payload))
        )

        payload = copy.deepcopy(self.json_payload)
        value = payload.pop("provider_id")
        payload[_StringSubclass("provider_id")] = value
        self._assert_rejected_unchanged(payload)

    def test_lineage_provenance_and_fixed_string_subclasses_fail_closed(self):
        for field in (
            "schema_version",
            "revision_proposal_sha256",
            "revision_request_sha256",
            "prior_review_sha256",
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
