from __future__ import annotations

import copy
from hashlib import sha256
import json
import unittest

import test_future_remediation_authoring_request_handoff as handoff_tests
from lightup.future_attack_path_transition_resolution import AttackPathTransitionClassification
from lightup.future_remediation_authoring_request_handoff import future_remediation_authoring_request_from_dict


def _rehash_request(payload: dict) -> None:
    body = copy.deepcopy(payload)
    body.pop("request_sha256")
    payload["request_sha256"] = sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


class FutureRemediationAuthoringRequestCapabilityCoverageAcceptanceTest(unittest.TestCase):
    def setUp(self):
        self.h = handoff_tests.FutureRemediationAuthoringRequestHandoffTest(
            "test_real_request_round_trips_and_is_live_validated"
        )
        self.h.setUp()
        self.addCleanup(self.h.tearDown)

    def _payload(self, *, suffix: str) -> tuple[object, dict]:
        produced = self.h._request(AttackPathTransitionClassification.WORSENED, suffix=suffix)
        request = produced[-1]
        payload = json.loads(request.to_json())
        item = payload["items"][0]
        self.assertTrue(item["capability_ids"])
        self.assertTrue(item["evidence"])
        return request, payload

    def test_canonical_producer_capability_coverage_round_trips(self):
        request, payload = self._payload(suffix="authoring-capability-coverage-control")
        item = payload["items"][0]
        self.assertEqual(
            set(item["capability_ids"]),
            {record["capability_id"] for record in item["evidence"]},
        )
        self.assertEqual(future_remediation_authoring_request_from_dict(payload), request)

    def test_unevidenced_item_capability_fails_with_matching_request_digest(self):
        _, payload = self._payload(suffix="authoring-capability-coverage-forged")
        item = payload["items"][0]
        forged = "capability:forged-without-authoring-evidence"
        self.assertNotIn(forged, item["capability_ids"])
        self.assertNotIn(forged, {record["capability_id"] for record in item["evidence"]})

        item["capability_ids"] = sorted([*item["capability_ids"], forged])
        _rehash_request(payload)

        with self.assertRaisesRegex(ValueError, "capability|evidence|lineage|match|exact"):
            future_remediation_authoring_request_from_dict(payload)


if __name__ == "__main__":
    unittest.main()
