from __future__ import annotations

import dataclasses
import unittest

import test_future_security_retest_request as request_tests
from lightup.future_attack_path_graph_diff_preview import AttackPathGraphDiffAction
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_security_remediation_retest_plan import FutureRemediationNextAction
from lightup.future_security_retest_request import FutureStateRetestPurpose


class FutureSecurityRetestRequestDirectConstructionAcceptanceTest(unittest.TestCase):
    def setUp(self):
        self.r = request_tests.FutureSecurityRetestRequestTest(
            "test_request_is_deterministic_lineage_bound_and_read_only"
        )
        self.r.setUp()
        self.addCleanup(self.r.tearDown)

    def _request(self):
        *_, request = self.r._request(
            AttackPathTransitionClassification.WORSENED,
            suffix="retest-request-direct-construction",
        )
        return request

    def test_canonical_producer_objects_remain_usable(self):
        request = self._request()
        self.assertEqual(dataclasses.replace(request), request)
        self.assertEqual(dataclasses.replace(request.items[0]), request.items[0])

    def test_direct_request_authority_lifecycle_and_version_forgery_fail_closed(self):
        request = self._request()
        forged_states = (
            {"request_complete": False},
            {"isolated_future_state_required": False},
            {"execution_allowed": True},
            {"target_interaction_allowed": True},
            {"deployment_authorized": True},
            {"attack_path_mutation_allowed": True},
            {"future_semantics": "resolved"},
            {"security_verdict": "approved"},
            {"current_twin_version": 0},
            {"twin_version": 0},
        )

        for changes in forged_states:
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    dataclasses.replace(request, **changes)

    def test_direct_item_semantic_and_lineage_forgery_fail_closed(self):
        item = self._request().items[0]
        forged_states = (
            {"classification": AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE},
            {"graph_diff_action": AttackPathGraphDiffAction.MODIFY_EXISTING_PATH_RISK_DOWN},
            {"source_next_action": FutureRemediationNextAction.VERIFY_IMPROVEMENT_WITH_RETEST},
            {"purpose": FutureStateRetestPurpose.IMPROVEMENT_VERIFICATION},
            {"remediation_required": False},
            {"current_attack_path_ids": ()},
            {"effect_ids": ()},
            {"evidence_ids": ()},
            {"capability_ids": ()},
            {"resolution_sha256": "A" * 64},
        )

        for changes in forged_states:
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    dataclasses.replace(item, **changes)


if __name__ == "__main__":
    unittest.main()
