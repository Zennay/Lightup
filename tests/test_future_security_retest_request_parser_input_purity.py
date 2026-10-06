from __future__ import annotations

import copy
import json
import unittest

import test_future_security_retest_request_handoff as handoff_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_security_retest_request_handoff import (
    future_security_retest_request_from_dict,
)


class FutureSecurityRetestRequestParserInputPurityTest(unittest.TestCase):
    def setUp(self):
        self.h = handoff_tests.FutureSecurityRetestRequestHandoffTest(
            "test_round_trip_accepts_exact_builder_output_for_all_supported_classifications"
        )
        self.h.setUp()
        self.addCleanup(self.h.tearDown)

    @staticmethod
    def _container_identities(value, path="root"):
        identities = {}
        if isinstance(value, dict):
            identities[path] = id(value)
            for key, item in value.items():
                identities.update(
                    FutureSecurityRetestRequestParserInputPurityTest
                    ._container_identities(item, f"{path}[{key!r}]")
                )
        elif isinstance(value, list):
            identities[path] = id(value)
            for index, item in enumerate(value):
                identities.update(
                    FutureSecurityRetestRequestParserInputPurityTest
                    ._container_identities(item, f"{path}[{index}]")
                )
        return identities

    @staticmethod
    def _ordered_json(value):
        return json.dumps(
            value,
            separators=(",", ":"),
            ensure_ascii=True,
        )

    def _payload(self, classification, *, suffix):
        *_, request = self.h._request(classification, suffix=suffix)
        return request, json.loads(request.to_json())

    def _assert_caller_input_unchanged(
        self,
        payload,
        *,
        before_value,
        before_json,
        before_ids,
    ):
        self.assertEqual(payload, before_value)
        self.assertEqual(self._ordered_json(payload), before_json)
        self.assertEqual(self._container_identities(payload), before_ids)

    def test_successful_parser_is_input_pure_for_all_supported_classifications(self):
        for classification in (
            AttackPathTransitionClassification.INTRODUCED,
            AttackPathTransitionClassification.WORSENED,
            AttackPathTransitionClassification.IMPROVED,
            AttackPathTransitionClassification.REMOVED,
        ):
            with self.subTest(classification=classification.value):
                request, payload = self._payload(
                    classification,
                    suffix=f"retest-parser-purity-{classification.value}",
                )
                before_value = copy.deepcopy(payload)
                before_json = self._ordered_json(payload)
                before_ids = self._container_identities(payload)

                first = future_security_retest_request_from_dict(payload)
                second = future_security_retest_request_from_dict(payload)

                self.assertEqual(first, request)
                self.assertEqual(second, request)
                self.assertEqual(first, second)
                self._assert_caller_input_unchanged(
                    payload,
                    before_value=before_value,
                    before_json=before_json,
                    before_ids=before_ids,
                )

                self.assertFalse(first.execution_allowed)
                self.assertFalse(first.target_interaction_allowed)
                self.assertFalse(first.deployment_authorized)
                self.assertFalse(first.attack_path_mutation_allowed)
                self.assertEqual(first.future_semantics, "unresolved")
                self.assertEqual(first.security_verdict, "not_evaluated")

    def test_schema_rejection_is_repeatable_and_input_pure(self):
        _, payload = self._payload(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="retest-parser-purity-schema",
        )
        payload["unexpected"] = {"nested": ["caller", "owned"]}
        before_value = copy.deepcopy(payload)
        before_json = self._ordered_json(payload)
        before_ids = self._container_identities(payload)

        errors = []
        for _ in range(2):
            with self.assertRaisesRegex(ValueError, "schema mismatch") as raised:
                future_security_retest_request_from_dict(payload)
            errors.append(str(raised.exception))

        self.assertEqual(errors[0], errors[1])
        self._assert_caller_input_unchanged(
            payload,
            before_value=before_value,
            before_json=before_json,
            before_ids=before_ids,
        )

    def test_deep_digest_rejection_is_repeatable_and_input_pure(self):
        _, payload = self._payload(
            AttackPathTransitionClassification.WORSENED,
            suffix="retest-parser-purity-digest",
        )
        payload["request_sha256"] = "0" * 64
        before_value = copy.deepcopy(payload)
        before_json = self._ordered_json(payload)
        before_ids = self._container_identities(payload)

        errors = []
        for _ in range(2):
            with self.assertRaisesRegex(ValueError, "digest mismatch") as raised:
                future_security_retest_request_from_dict(payload)
            errors.append(str(raised.exception))

        self.assertEqual(errors[0], errors[1])
        self._assert_caller_input_unchanged(
            payload,
            before_value=before_value,
            before_json=before_json,
            before_ids=before_ids,
        )


if __name__ == "__main__":
    unittest.main()
