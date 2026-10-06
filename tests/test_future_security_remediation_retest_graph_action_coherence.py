from __future__ import annotations

import copy
from hashlib import sha256
import json
import unittest

import test_future_security_remediation_retest_plan_handoff as handoff_tests
from lightup.future_attack_path_graph_diff_preview import AttackPathGraphDiffAction
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_security_remediation_retest_plan_handoff import (
    future_security_remediation_retest_plan_from_dict,
)


class FutureSecurityRemediationRetestGraphActionCoherenceTest(unittest.TestCase):
    def setUp(self):
        self.h = handoff_tests.FutureSecurityRemediationRetestPlanHandoffTest(
            "test_round_trip_accepts_exact_builder_output"
        )
        self.h.setUp()
        self.addCleanup(self.h.tearDown)

    @staticmethod
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

    def test_canonical_graph_action_mapping_round_trips_for_all_classifications(self):
        expected = {
            AttackPathTransitionClassification.INTRODUCED:
                AttackPathGraphDiffAction.ADD_PATH_HYPOTHESIS,
            AttackPathTransitionClassification.WORSENED:
                AttackPathGraphDiffAction.MODIFY_EXISTING_PATH_RISK_UP,
            AttackPathTransitionClassification.IMPROVED:
                AttackPathGraphDiffAction.MODIFY_EXISTING_PATH_RISK_DOWN,
            AttackPathTransitionClassification.REMOVED:
                AttackPathGraphDiffAction.REMOVE_EXISTING_PATH_CANDIDATE,
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE:
                AttackPathGraphDiffAction.NO_GRAPH_CHANGE_CLAIM,
        }

        for classification, action in expected.items():
            with self.subTest(classification=classification.value):
                plan = self.h._plan(
                    classification,
                    suffix=f"graph-action-canonical-{classification.value}",
                )
                payload = json.loads(plan.to_json())
                self.assertEqual(payload["items"][0]["graph_diff_action"], action.value)
                self.assertEqual(
                    future_security_remediation_retest_plan_from_dict(payload),
                    plan,
                )

    def test_wrong_valid_graph_action_fails_with_matching_recomputed_digest(self):
        wrong_action = {
            AttackPathTransitionClassification.INTRODUCED:
                AttackPathGraphDiffAction.REMOVE_EXISTING_PATH_CANDIDATE,
            AttackPathTransitionClassification.WORSENED:
                AttackPathGraphDiffAction.MODIFY_EXISTING_PATH_RISK_DOWN,
            AttackPathTransitionClassification.IMPROVED:
                AttackPathGraphDiffAction.MODIFY_EXISTING_PATH_RISK_UP,
            AttackPathTransitionClassification.REMOVED:
                AttackPathGraphDiffAction.ADD_PATH_HYPOTHESIS,
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE:
                AttackPathGraphDiffAction.ADD_PATH_HYPOTHESIS,
        }

        for classification, forged_action in wrong_action.items():
            with self.subTest(classification=classification.value):
                plan = self.h._plan(
                    classification,
                    suffix=f"graph-action-forged-{classification.value}",
                )
                payload = json.loads(plan.to_json())
                payload["items"][0]["graph_diff_action"] = forged_action.value
                payload["plan_sha256"] = self._rehash(payload)

                with self.assertRaisesRegex(ValueError, "semantics mismatch"):
                    future_security_remediation_retest_plan_from_dict(payload)


if __name__ == "__main__":
    unittest.main()
