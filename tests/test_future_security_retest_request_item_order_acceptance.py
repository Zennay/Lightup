from __future__ import annotations

import copy
from hashlib import sha256
import json
import unittest

import test_future_security_retest_request as request_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_security_retest_request_handoff import (
    future_security_retest_request_from_dict,
)


def _resign(payload: dict) -> None:
    digest_payload = copy.deepcopy(payload)
    digest_payload.pop("request_sha256")
    payload["request_sha256"] = sha256(
        json.dumps(
            digest_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


class FutureSecurityRetestRequestItemOrderAcceptanceTest(unittest.TestCase):
    def setUp(self):
        self.r = request_tests.FutureSecurityRetestRequestTest(
            "test_request_is_deterministic_lineage_bound_and_read_only"
        )
        self.r.setUp()
        self.addCleanup(self.r.tearDown)

    def _two_item_payload(self) -> dict:
        *_, request = self.r._request(
            AttackPathTransitionClassification.WORSENED,
            suffix="retest-handoff-item-order",
        )
        payload = json.loads(request.to_json())
        template = payload["items"][0]

        first = copy.deepcopy(template)
        first["change_node_id"] = "change-a"
        first["subject_node_id"] = "subject-a"
        first["resolution_id"] = "transition-resolution:item-order-a"
        first["resolution_sha256"] = "1" * 64
        first["current_attack_path_ids"] = ["path-a"]

        second = copy.deepcopy(template)
        second["change_node_id"] = "change-z"
        second["subject_node_id"] = "subject-z"
        second["resolution_id"] = "transition-resolution:item-order-z"
        second["resolution_sha256"] = "2" * 64
        second["current_attack_path_ids"] = ["path-z"]

        payload["items"] = [first, second]
        _resign(payload)
        return payload

    def test_canonical_structural_multi_item_order_parses(self):
        payload = self._two_item_payload()
        parsed = future_security_retest_request_from_dict(copy.deepcopy(payload))
        self.assertEqual(
            [item.change_node_id for item in parsed.items],
            ["change-a", "change-z"],
        )

    def test_reversed_item_order_fails_closed_with_matching_digest(self):
        payload = self._two_item_payload()
        payload["items"] = list(reversed(payload["items"]))
        _resign(payload)

        with self.assertRaises(ValueError):
            future_security_retest_request_from_dict(payload)


if __name__ == "__main__":
    unittest.main()
