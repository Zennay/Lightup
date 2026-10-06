from __future__ import annotations

import copy
from hashlib import sha256
import json
import unittest

import test_future_remediation_authoring_request_handoff as handoff_tests
from lightup.future_attack_path_transition_resolution import AttackPathTransitionClassification
from lightup.future_remediation_authoring_request_handoff import future_remediation_authoring_request_from_dict


def _rehash_manifest(item: dict) -> None:
    item["evidence_manifest_sha256"] = sha256(
        json.dumps(item["evidence"], sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


def _rehash_request(payload: dict) -> None:
    body = copy.deepcopy(payload)
    body.pop("request_sha256")
    payload["request_sha256"] = sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


class FutureRemediationAuthoringRequestEvidenceKindAcceptanceTest(unittest.TestCase):
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
        self.assertTrue(payload["items"][0]["evidence"])
        return request, payload

    def test_canonical_producer_kind_round_trips(self):
        request, payload = self._payload(suffix="authoring-kind-control")
        self.assertEqual(payload["items"][0]["evidence"][0]["kind"], "future-transition-verification")
        self.assertEqual(future_remediation_authoring_request_from_dict(payload), request)

    def test_alternative_nonempty_kind_fails_with_matching_digests(self):
        _, payload = self._payload(suffix="authoring-kind-forged")
        item = payload["items"][0]
        item["evidence"][0]["kind"] = "forged-transition-verification"
        _rehash_manifest(item)
        _rehash_request(payload)

        with self.assertRaisesRegex(ValueError, "kind|canonical|future-transition-verification"):
            future_remediation_authoring_request_from_dict(payload)


if __name__ == "__main__":
    unittest.main()
