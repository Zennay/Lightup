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


class FutureSecurityRetestRequestCrossItemPathAcceptanceTest(unittest.TestCase):
    def setUp(self):
        self.r = request_tests.FutureSecurityRetestRequestTest(
            "test_request_is_deterministic_lineage_bound_and_read_only"
        )
        self.r.setUp()
        self.addCleanup(self.r.tearDown)

    def _payload(self) -> dict:
        *_, request = self.r._request(
            AttackPathTransitionClassification.WORSENED,
            suffix="retest-handoff-cross-item-path",
        )
        return json.loads(request.to_json())

    def test_canonical_producer_payload_round_trips(self):
        payload = self._payload()
        parsed = future_security_retest_request_from_dict(copy.deepcopy(payload))
        self.assertEqual(json.loads(parsed.to_json()), payload)

    def test_distinct_changes_cannot_claim_the_same_current_attack_path(self):
        payload = self._payload()
        first = payload["items"][0]
        self.assertTrue(first["current_attack_path_ids"])

        sibling = copy.deepcopy(first)
        sibling["change_node_id"] = "change-cross-item-path-sibling"
        sibling["subject_node_id"] = "subject-cross-item-path-sibling"
        sibling["resolution_id"] = "transition-resolution:cross-item-path-sibling"
        sibling["resolution_sha256"] = "1" * 64
        payload["items"].append(sibling)
        _resign(payload)

        with self.assertRaises(ValueError):
            future_security_retest_request_from_dict(payload)


if __name__ == "__main__":
    unittest.main()
