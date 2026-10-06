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


class FutureSecurityRemediationRetestBlankLineageIdentityTest(unittest.TestCase):
    def setUp(self):
        self.base = handoff_tests.FutureSecurityRemediationRetestPlanHandoffTest(
            "test_round_trip_accepts_exact_builder_output"
        )
        self.base.setUp()
        self.addCleanup(self.base.doCleanups)

    def _payload(self):
        plan = self.base._plan(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="handoff-blank-lineage",
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

    def test_canonical_producer_payload_still_round_trips(self):
        payload = self._payload()

        parsed = future_security_remediation_retest_plan_from_dict(payload)

        self.assertEqual(json.loads(parsed.to_json()), payload)

    def test_whitespace_only_top_level_lineage_ids_fail_closed_after_resigning(self):
        baseline = self._payload()

        for field in (
            "client_id",
            "current_twin_id",
            "twin_id",
            "changeset_id",
        ):
            with self.subTest(field=field):
                payload = copy.deepcopy(baseline)
                payload[field] = " \t "
                payload = self._resign(payload)

                with self.assertRaisesRegex(ValueError, "non-empty string"):
                    future_security_remediation_retest_plan_from_dict(payload)

    def test_whitespace_only_item_ids_fail_closed_after_resigning(self):
        baseline = self._payload()

        for field in (
            "change_node_id",
            "subject_node_id",
            "resolution_id",
        ):
            with self.subTest(field=field):
                payload = copy.deepcopy(baseline)
                payload["items"][0][field] = "   "
                payload = self._resign(payload)

                with self.assertRaisesRegex(ValueError, "non-empty string"):
                    future_security_remediation_retest_plan_from_dict(payload)

    def test_whitespace_only_lineage_collection_entries_fail_closed_after_resigning(self):
        baseline = self._payload()

        for field in (
            "current_attack_path_ids",
            "effect_ids",
            "evidence_ids",
            "capability_ids",
        ):
            with self.subTest(field=field):
                payload = copy.deepcopy(baseline)
                payload["items"][0][field] = [" \n "]
                payload = self._resign(payload)

                with self.assertRaisesRegex(ValueError, "non-empty strings"):
                    future_security_remediation_retest_plan_from_dict(payload)


if __name__ == "__main__":
    unittest.main()
