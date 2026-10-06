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


def _rehash(payload: dict) -> str:
    digest_payload = copy.deepcopy(payload)
    digest_payload.pop("plan_sha256")
    return sha256(
        json.dumps(
            digest_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


class FutureSecurityRemediationRetestPositiveVersionAcceptanceTest(unittest.TestCase):
    def setUp(self):
        self.h = handoff_tests.FutureSecurityRemediationRetestPlanHandoffTest(
            "test_round_trip_accepts_exact_builder_output"
        )
        self.h.setUp()
        self.addCleanup(self.h.tearDown)

    def _payload(self, *, suffix):
        plan = self.h._plan(
            AttackPathTransitionClassification.WORSENED,
            suffix=suffix,
        )
        return plan, json.loads(plan.to_json())

    def test_canonical_producer_versions_still_round_trip(self):
        plan, payload = self._payload(suffix="positive-version-canonical")
        self.assertGreaterEqual(payload["current_twin_version"], 1)
        self.assertGreaterEqual(payload["twin_version"], 1)
        self.assertEqual(
            future_security_remediation_retest_plan_from_dict(payload),
            plan,
        )

    def test_zero_versions_fail_closed_with_matching_digest(self):
        for field in ("current_twin_version", "twin_version"):
            with self.subTest(field=field):
                _, payload = self._payload(suffix=f"positive-version-zero-{field}")
                payload[field] = 0
                payload["plan_sha256"] = _rehash(payload)

                with self.assertRaisesRegex(ValueError, "positive|version|integer"):
                    future_security_remediation_retest_plan_from_dict(payload)


if __name__ == "__main__":
    unittest.main()
