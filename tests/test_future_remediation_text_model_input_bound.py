from __future__ import annotations

import dataclasses
import unittest

import test_future_remediation_text_proposal as proposal_tests
from lightup.future_remediation_text_proposal import _authoring_messages


MODEL_INPUT_CHAR_LIMIT = 65_536


class RemediationTextModelInputBoundAcceptanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.base = proposal_tests.FutureRemediationTextProposalTest(
            "test_live_valid_request_generates_bounded_non_executable_proposal"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.request = self.base.request

    def test_canonical_authoring_request_stays_within_v1_input_bound(self) -> None:
        before = dataclasses.asdict(self.request)

        messages = _authoring_messages(self.request)

        self.assertEqual(len(messages), 2)
        self.assertLessEqual(
            len(messages[1].content),
            MODEL_INPUT_CHAR_LIMIT,
        )
        self.assertEqual(dataclasses.asdict(self.request), before)

    def test_oversized_aggregate_authoring_payload_fails_closed(self) -> None:
        base_item = self.request.items[0]
        items = tuple(
            dataclasses.replace(
                base_item,
                change_node_id=f"change-{index:04d}-" + ("c" * 180),
                subject_node_id=f"subject-{index:04d}-" + ("s" * 180),
                resolution_id=f"resolution-{index:04d}-" + ("r" * 180),
                current_attack_path_ids=(
                    f"path-{index:04d}-" + ("p" * 180),
                ),
                effect_ids=(
                    f"effect-{index:04d}-" + ("e" * 180),
                ),
            )
            for index in range(120)
        )
        oversized = dataclasses.replace(
            self.request,
            items=items,
            item_count=len(items),
        )
        before = dataclasses.asdict(oversized)

        with self.assertRaisesRegex(ValueError, "model input|input payload|input size"):
            _authoring_messages(oversized)

        self.assertEqual(dataclasses.asdict(oversized), before)


if __name__ == "__main__":
    unittest.main()
