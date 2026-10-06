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


class FutureSecurityRemediationRetestCanonicalItemOrderAcceptanceTest(
    unittest.TestCase
):
    def setUp(self):
        self.h = handoff_tests.FutureSecurityRemediationRetestPlanHandoffTest(
            "test_round_trip_accepts_exact_builder_output"
        )
        self.h.setUp()
        self.addCleanup(self.h.tearDown)

    def _two_item_payload(self) -> dict:
        plan = self.h._plan(
            AttackPathTransitionClassification.WORSENED,
            suffix="canonical-item-order",
        )
        payload = json.loads(plan.to_json())
        second = copy.deepcopy(payload["items"][0])
        second["change_node_id"] = second["change_node_id"] + "-zz"
        second["subject_node_id"] = second["subject_node_id"] + "-zz"
        second["resolution_id"] = second["resolution_id"] + "-zz"
        second["resolution_sha256"] = sha256(
            second["resolution_id"].encode("utf-8")
        ).hexdigest()
        payload["items"].append(second)
        payload["remediation_item_count"] = 2
        payload["retest_item_count"] = 2
        payload["evidence_gap_count"] = 0
        payload["contains_insufficient_evidence"] = False
        _rehash(payload)
        return payload

    def test_canonical_ordered_distinct_items_parse(self):
        payload = self._two_item_payload()
        identities = [
            (item["change_node_id"], item["subject_node_id"])
            for item in payload["items"]
        ]
        self.assertEqual(identities, sorted(identities))

        parsed = future_security_remediation_retest_plan_from_dict(payload)

        self.assertEqual(
            [(item.change_node_id, item.subject_node_id) for item in parsed.items],
            identities,
        )

    def test_reordered_distinct_items_fail_with_matching_digest(self):
        payload = self._two_item_payload()
        payload["items"].reverse()
        _rehash(payload)

        with self.assertRaisesRegex(ValueError, "canonical|ordered|order"):
            future_security_remediation_retest_plan_from_dict(payload)


if __name__ == "__main__":
    unittest.main()
