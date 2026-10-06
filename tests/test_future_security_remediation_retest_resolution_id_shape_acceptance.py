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


def _resign(payload: dict) -> None:
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


class FutureSecurityRemediationRetestResolutionIdShapeAcceptanceTest(unittest.TestCase):
    def setUp(self):
        self.h = handoff_tests.FutureSecurityRemediationRetestPlanHandoffTest(
            "test_round_trip_accepts_exact_builder_output"
        )
        self.h.setUp()
        self.addCleanup(self.h.tearDown)

    def _payload(self) -> dict:
        plan = self.h._plan(
            AttackPathTransitionClassification.WORSENED,
            suffix="plan-handoff-resolution-id-shape",
        )
        return json.loads(plan.to_json())

    def test_canonical_producer_resolution_id_round_trips(self):
        payload = self._payload()
        resolution_id = payload["items"][0]["resolution_id"]
        prefix = "transition-resolution:"
        self.assertTrue(resolution_id.startswith(prefix))
        suffix = resolution_id[len(prefix) :]
        self.assertEqual(len(suffix), 24)
        self.assertTrue(all(character in "0123456789abcdef" for character in suffix))

        parsed = future_security_remediation_retest_plan_from_dict(
            copy.deepcopy(payload)
        )
        self.assertEqual(json.loads(parsed.to_json()), payload)

    def test_non_producer_resolution_id_shapes_fail_closed_with_matching_digest(self):
        payload = self._payload()
        forged_resolution_ids = (
            "resolution:" + "0" * 24,
            "transition-resolution:" + "0" * 23,
            "transition-resolution:" + "A" * 24,
        )

        for forged_resolution_id in forged_resolution_ids:
            with self.subTest(resolution_id=forged_resolution_id):
                tampered = copy.deepcopy(payload)
                tampered["items"][0]["resolution_id"] = forged_resolution_id
                _resign(tampered)

                with self.assertRaises(ValueError):
                    future_security_remediation_retest_plan_from_dict(tampered)


if __name__ == "__main__":
    unittest.main()
