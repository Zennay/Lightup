from __future__ import annotations

import json
import unittest

import test_future_security_retest_request as request_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)


class FutureSecurityRetestRequestSnapshotIsolationTest(unittest.TestCase):
    def setUp(self):
        self.r = request_tests.FutureSecurityRetestRequestTest(
            "test_request_is_deterministic_lineage_bound_and_read_only"
        )
        self.r.setUp()
        self.addCleanup(self.r.tearDown)

    def test_real_requests_export_deterministic_detached_snapshots(self):
        classifications = (
            AttackPathTransitionClassification.INTRODUCED,
            AttackPathTransitionClassification.WORSENED,
            AttackPathTransitionClassification.IMPROVED,
            AttackPathTransitionClassification.REMOVED,
        )

        for classification in classifications:
            with self.subTest(classification=classification.value):
                *_, request = self.r._request(
                    classification,
                    suffix=f"retest-snapshot-{classification.value}",
                )

                baseline_json = request.to_json()
                self.assertEqual(request.to_json(), baseline_json)
                self.assertEqual(
                    json.loads(request.to_json()),
                    json.loads(baseline_json),
                )

                first = request.as_dict()
                second = request.as_dict()

                self.assertEqual(first, second)
                self.assertIsNot(first, second)
                self.assertIsNot(first["items"], second["items"])
                self.assertIsNot(first["items"][0], second["items"][0])

                original_change_node_id = request.items[0].change_node_id
                original_requested_capability_ids = request.requested_capability_ids
                original_evidence_ids = request.evidence_ids

                first["client_id"] = "forged-client"
                first["request_sha256"] = "0" * 64
                first["items"][0]["change_node_id"] = "forged-change-node"
                first["items"][0]["evidence_ids"] = ("forged-evidence",)
                first["items"][0]["capability_ids"] = ("forged-capability",)
                first["requested_capability_ids"] = ("forged-capability",)
                first["evidence_ids"] = ("forged-evidence",)
                first["request_complete"] = False
                first["isolated_future_state_required"] = False
                first["execution_allowed"] = True
                first["target_interaction_allowed"] = True
                first["deployment_authorized"] = True
                first["attack_path_mutation_allowed"] = True
                first["future_semantics"] = "resolved"
                first["security_verdict"] = "secure"

                self.assertEqual(
                    second["items"][0]["change_node_id"],
                    original_change_node_id,
                )
                self.assertEqual(request.items[0].change_node_id, original_change_node_id)
                self.assertEqual(
                    request.requested_capability_ids,
                    original_requested_capability_ids,
                )
                self.assertEqual(request.evidence_ids, original_evidence_ids)

                self.assertTrue(request.request_complete)
                self.assertTrue(request.isolated_future_state_required)
                self.assertFalse(request.execution_allowed)
                self.assertFalse(request.target_interaction_allowed)
                self.assertFalse(request.deployment_authorized)
                self.assertFalse(request.attack_path_mutation_allowed)
                self.assertEqual(request.future_semantics, "unresolved")
                self.assertEqual(request.security_verdict, "not_evaluated")
                self.assertEqual(request.to_json(), baseline_json)


if __name__ == "__main__":
    unittest.main()
