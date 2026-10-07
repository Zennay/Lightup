from __future__ import annotations

import copy
import json
import unittest

import test_future_remediation_authoring_request_handoff as handoff_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_remediation_authoring_request_handoff import (
    future_remediation_authoring_request_from_dict,
)


class FutureRemediationAuthoringRequestParserPurityTest(unittest.TestCase):
    def setUp(self):
        self.base = handoff_tests.FutureRemediationAuthoringRequestHandoffTest(
            "test_real_request_round_trips_and_is_live_validated"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.produced = self.base._request(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="authoring-parser-purity",
        )
        self.request = self.produced[-1]

    def _payload(self) -> dict:
        return json.loads(self.request.to_json())

    @staticmethod
    def _shape(payload: dict) -> tuple:
        item = payload["items"][0]
        evidence = item["evidence"][0]
        return (
            id(payload),
            id(payload["items"]),
            id(item),
            id(item["current_attack_path_ids"]),
            id(item["effect_ids"]),
            id(item["capability_ids"]),
            id(item["evidence"]),
            id(evidence),
            tuple(payload.keys()),
            tuple(item.keys()),
            tuple(evidence.keys()),
        )

    def _assert_success_is_pure(self, payload: dict):
        before = copy.deepcopy(payload)
        shape = self._shape(payload)

        parsed = future_remediation_authoring_request_from_dict(payload)

        self.assertEqual(parsed, self.request)
        self.assertEqual(payload, before)
        self.assertEqual(self._shape(payload), shape)
        return parsed

    def test_success_preserves_caller_content_identities_and_order(self):
        payload = self._payload()

        first = self._assert_success_is_pure(payload)
        second = self._assert_success_is_pure(payload)

        self.assertEqual(first, second)
        self.assertEqual(first.to_json(), second.to_json())

    def test_late_request_digest_rejection_is_repeatably_pure(self):
        payload = self._payload()
        payload["request_sha256"] = "0" * 64
        before = copy.deepcopy(payload)
        shape = self._shape(payload)

        errors = []
        for _ in range(2):
            with self.assertRaisesRegex(ValueError, "request digest mismatch") as caught:
                future_remediation_authoring_request_from_dict(payload)
            errors.append(str(caught.exception))
            self.assertEqual(payload, before)
            self.assertEqual(self._shape(payload), shape)

        self.assertEqual(errors[0], errors[1])

    def test_nested_manifest_rejection_is_repeatably_pure(self):
        payload = self._payload()
        payload["items"][0]["evidence"][0]["sha256"] = "0" * 64
        before = copy.deepcopy(payload)
        shape = self._shape(payload)

        errors = []
        for _ in range(2):
            with self.assertRaisesRegex(ValueError, "manifest digest mismatch") as caught:
                future_remediation_authoring_request_from_dict(payload)
            errors.append(str(caught.exception))
            self.assertEqual(payload, before)
            self.assertEqual(self._shape(payload), shape)

        self.assertEqual(errors[0], errors[1])

    def test_authority_rejection_is_repeatably_pure(self):
        payload = self._payload()
        payload["execution_allowed"] = True
        before = copy.deepcopy(payload)
        shape = self._shape(payload)

        errors = []
        for _ in range(2):
            with self.assertRaisesRegex(ValueError, "must remain false") as caught:
                future_remediation_authoring_request_from_dict(payload)
            errors.append(str(caught.exception))
            self.assertEqual(payload, before)
            self.assertEqual(self._shape(payload), shape)

        self.assertEqual(errors[0], errors[1])


if __name__ == "__main__":
    unittest.main()
