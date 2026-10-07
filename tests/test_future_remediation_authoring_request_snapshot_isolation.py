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


class FutureRemediationAuthoringRequestSnapshotIsolationTest(unittest.TestCase):
    def setUp(self):
        self.base = handoff_tests.FutureRemediationAuthoringRequestHandoffTest(
            "test_real_request_round_trips_and_is_live_validated"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.produced = self.base._request(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="authoring-snapshot-isolation",
        )
        self.request = self.produced[-1]

    def test_repeated_json_and_producer_snapshots_are_deeply_detached(self):
        first_json = self.request.to_json()
        second_json = self.request.to_json()
        first = self.request.as_dict()
        second = self.request.as_dict()

        self.assertEqual(first_json, second_json)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["items"], second["items"])
        self.assertIsNot(first["items"][0], second["items"][0])
        self.assertIsNot(
            first["items"][0]["capability_ids"],
            second["items"][0]["capability_ids"],
        )
        self.assertIsNot(
            first["items"][0]["evidence"],
            second["items"][0]["evidence"],
        )
        self.assertIsNot(
            first["items"][0]["evidence"][0],
            second["items"][0]["evidence"][0],
        )

    def test_producer_snapshot_mutation_cannot_rewrite_request_or_later_json(self):
        before_json = self.request.to_json()
        before = self.request

        snapshot = self.request.as_dict()
        snapshot["bundle_sha256"] = "0" * 64
        snapshot["items"][0]["effect_ids"] = ("caller-mutated-effect",)
        snapshot["items"][0]["evidence"][0]["sha256"] = "0" * 64
        snapshot["execution_allowed"] = True
        snapshot["security_verdict"] = "forged"

        self.assertEqual(self.request, before)
        self.assertEqual(self.request.to_json(), before_json)
        self.assertNotEqual(
            self.request.items[0].effect_ids,
            ("caller-mutated-effect",),
        )
        self.assertFalse(self.request.execution_allowed)
        self.assertEqual(self.request.security_verdict, "not_evaluated")

    def test_canonical_json_decoded_snapshot_round_trips_exactly(self):
        persisted = json.loads(self.request.to_json())
        parsed = future_remediation_authoring_request_from_dict(
            copy.deepcopy(persisted)
        )

        self.assertEqual(parsed, self.request)

    def test_forged_persisted_snapshot_fails_closed_without_mutation(self):
        cases = (
            (
                lambda payload: payload["items"][0]["evidence"][0].__setitem__(
                    "sha256", "0" * 64
                ),
                "manifest digest mismatch",
            ),
            (
                lambda payload: payload.__setitem__("request_sha256", "0" * 64),
                "request digest mismatch",
            ),
            (
                lambda payload: payload.__setitem__("execution_allowed", True),
                "must remain false",
            ),
        )

        for mutate, message in cases:
            with self.subTest(message=message):
                persisted = json.loads(self.request.to_json())
                mutate(persisted)
                before = copy.deepcopy(persisted)
                with self.assertRaisesRegex(ValueError, message):
                    future_remediation_authoring_request_from_dict(persisted)
                self.assertEqual(persisted, before)

    def test_post_parse_caller_mutation_cannot_rewrite_parsed_request(self):
        caller_owned = json.loads(self.request.to_json())
        parsed = future_remediation_authoring_request_from_dict(caller_owned)
        parsed_json = parsed.to_json()

        caller_owned["bundle_sha256"] = "0" * 64
        caller_owned["items"][0]["effect_ids"].append("caller-mutated-effect")
        caller_owned["items"][0]["capability_ids"].append(
            "caller-mutated-capability"
        )
        caller_owned["items"][0]["evidence"][0]["sha256"] = "0" * 64
        caller_owned["request_sha256"] = "0" * 64
        caller_owned["execution_allowed"] = True
        caller_owned["security_verdict"] = "forged"

        self.assertEqual(parsed, self.request)
        self.assertEqual(parsed.to_json(), parsed_json)
        self.assertNotIn(
            "caller-mutated-effect",
            parsed.items[0].effect_ids,
        )
        self.assertNotIn(
            "caller-mutated-capability",
            parsed.items[0].capability_ids,
        )
        self.assertFalse(parsed.execution_allowed)
        self.assertEqual(parsed.security_verdict, "not_evaluated")


if __name__ == "__main__":
    unittest.main()
