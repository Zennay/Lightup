from __future__ import annotations

from dataclasses import replace
import unittest

import test_future_remediation_authoring_request as authoring_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)


class FutureRemediationAuthoringItemDirectConstructionTest(unittest.TestCase):
    def setUp(self):
        self.base = authoring_tests.FutureRemediationAuthoringRequestTest(
            "test_introduced_and_worsened_create_bounded_text_authoring_requests"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        *_, self.request = self.base._request(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="authoring-item-direct-construction",
        )
        self.item = self.request.items[0]

    def test_valid_item_preserves_required_lifecycle_markers(self):
        self.assertTrue(self.item.remediation_required)
        self.assertTrue(self.item.future_state_retest_required)

    def test_direct_construction_rejects_remediation_required_forgery(self):
        with self.assertRaisesRegex(ValueError, "remediation_required must remain true"):
            replace(self.item, remediation_required=False)

    def test_direct_construction_rejects_retest_required_forgery(self):
        with self.assertRaisesRegex(
            ValueError,
            "future_state_retest_required must remain true",
        ):
            replace(self.item, future_state_retest_required=False)

    def test_direct_construction_rejects_bool_int_confusion(self):
        with self.assertRaisesRegex(ValueError, "remediation_required must remain true"):
            replace(self.item, remediation_required=1)
        with self.assertRaisesRegex(
            ValueError,
            "future_state_retest_required must remain true",
        ):
            replace(self.item, future_state_retest_required=1)


if __name__ == "__main__":
    unittest.main()
