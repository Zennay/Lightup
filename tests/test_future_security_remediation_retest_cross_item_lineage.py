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


class FutureSecurityRemediationRetestCrossItemLineageTest(unittest.TestCase):
    def setUp(self):
        self.base = handoff_tests.FutureSecurityRemediationRetestPlanHandoffTest(
            "test_round_trip_accepts_exact_builder_output"
        )
        self.base.setUp()
        self.addCleanup(self.base.doCleanups)

    def _payload(self):
        plan = self.base._plan(
            AttackPathTransitionClassification.WORSENED,
            suffix="handoff-cross-item-lineage",
        )
        return json.loads(plan.to_json())

    @staticmethod
    def _resign(payload):
        resigned = copy.deepcopy(payload)
        digest_payload = copy.deepcopy(resigned)
        digest_payload.pop("plan_sha256")
        resigned["plan_sha256"] = sha256(
            json.dumps(
                digest_payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        ).hexdigest()
        return resigned

    @staticmethod
    def _refresh_counts(payload):
        payload["remediation_item_count"] = sum(
            item["remediation_required"] for item in payload["items"]
        )
        payload["retest_item_count"] = sum(
            item["future_state_retest_required"] for item in payload["items"]
        )
        payload["evidence_gap_count"] = sum(
            item["evidence_required"] for item in payload["items"]
        )
        payload["contains_insufficient_evidence"] = any(
            item["classification"] == "insufficient_evidence"
            for item in payload["items"]
        )

    def _two_items(self):
        payload = self._payload()
        second = copy.deepcopy(payload["items"][0])
        second["change_node_id"] = second["change_node_id"] + "-second"
        second["subject_node_id"] = second["subject_node_id"] + "-second"
        second["resolution_id"] = second["resolution_id"] + "-second"
        second["resolution_sha256"] = sha256(
            second["resolution_id"].encode("utf-8")
        ).hexdigest()
        payload["items"].append(second)
        self._refresh_counts(payload)
        return payload

    def test_canonical_single_item_payload_still_round_trips(self):
        payload = self._payload()

        parsed = future_security_remediation_retest_plan_from_dict(payload)

        self.assertEqual(json.loads(parsed.to_json()), payload)

    def test_duplicate_change_identity_across_distinct_items_fails_closed(self):
        payload = self._two_items()
        payload["items"][1]["change_node_id"] = payload["items"][0]["change_node_id"]
        payload = self._resign(payload)

        with self.assertRaisesRegex(ValueError, "duplicate change"):
            future_security_remediation_retest_plan_from_dict(payload)

    def test_duplicate_resolution_identity_across_distinct_items_fails_closed(self):
        payload = self._two_items()
        payload["items"][1]["resolution_id"] = payload["items"][0]["resolution_id"]
        payload = self._resign(payload)

        with self.assertRaisesRegex(ValueError, "duplicate resolution"):
            future_security_remediation_retest_plan_from_dict(payload)

    def test_current_attack_path_cannot_be_claimed_by_different_changes(self):
        payload = self._two_items()
        shared_path_id = "path-cross-item-shared"
        payload["items"][0]["current_attack_path_ids"] = [shared_path_id]
        payload["items"][1]["current_attack_path_ids"] = [shared_path_id]
        payload = self._resign(payload)

        with self.assertRaisesRegex(ValueError, "colliding current attack path"):
            future_security_remediation_retest_plan_from_dict(payload)


if __name__ == "__main__":
    unittest.main()
