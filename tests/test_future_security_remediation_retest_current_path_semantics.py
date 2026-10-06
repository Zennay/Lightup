from __future__ import annotations

import copy
from hashlib import sha256
import json
import unittest

import test_future_security_remediation_retest_plan_handoff as handoff_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_security_remediation_retest_plan_handoff import (
    future_security_remediation_retest_plan_from_dict,
)


def _rehash(payload: dict) -> None:
    digest_payload = copy.deepcopy(payload)
    digest_payload.pop("plan_sha256")
    payload["plan_sha256"] = sha256(
        json.dumps(
            digest_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


class FutureSecurityRemediationRetestCurrentPathSemanticsAcceptanceTest(
    unittest.TestCase
):
    def setUp(self):
        self.h = handoff_tests.FutureSecurityRemediationRetestPlanHandoffTest(
            "test_round_trip_accepts_exact_builder_output"
        )
        self.h.setUp()
        self.addCleanup(self.h.tearDown)

    def _payload(self, classification, *, suffix):
        plan = self.h._plan(classification, suffix=suffix)
        return plan, json.loads(plan.to_json())

    def test_all_canonical_classification_path_shapes_round_trip(self):
        for classification in AttackPathTransitionClassification:
            with self.subTest(classification=classification.value):
                plan, payload = self._payload(
                    classification,
                    suffix=f"current-path-canonical-{classification.value}",
                )
                self.assertEqual(
                    future_security_remediation_retest_plan_from_dict(payload),
                    plan,
                )

    def test_introduced_cannot_gain_current_path_with_matching_digest(self):
        _, payload = self._payload(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="current-path-introduced-forged",
        )
        self.assertEqual(payload["items"][0]["current_attack_path_ids"], [])
        payload["items"][0]["current_attack_path_ids"] = ["path:forged-existing"]
        _rehash(payload)

        with self.assertRaisesRegex(ValueError, "classification|current|path|lineage"):
            future_security_remediation_retest_plan_from_dict(payload)

    def test_existing_path_classifications_cannot_lose_current_paths(self):
        for classification in (
            AttackPathTransitionClassification.WORSENED,
            AttackPathTransitionClassification.IMPROVED,
            AttackPathTransitionClassification.REMOVED,
        ):
            with self.subTest(classification=classification.value):
                _, payload = self._payload(
                    classification,
                    suffix=f"current-path-empty-{classification.value}",
                )
                self.assertTrue(payload["items"][0]["current_attack_path_ids"])
                payload["items"][0]["current_attack_path_ids"] = []
                _rehash(payload)

                with self.assertRaisesRegex(
                    ValueError,
                    "classification|current|path|lineage",
                ):
                    future_security_remediation_retest_plan_from_dict(payload)


if __name__ == "__main__":
    unittest.main()
