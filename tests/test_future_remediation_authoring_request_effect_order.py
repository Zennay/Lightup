from __future__ import annotations

import copy
from hashlib import sha256
import json
import unittest

import test_future_remediation_authoring_request_handoff as handoff_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_remediation_authoring_request_handoff import (
    future_remediation_authoring_request_from_dict,
)


def _rehash_request(payload: dict) -> None:
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


class FutureRemediationAuthoringRequestEffectOrderAcceptanceTest(unittest.TestCase):
    def setUp(self):
        self.h = handoff_tests.FutureRemediationAuthoringRequestHandoffTest(
            "test_real_request_round_trips_and_is_live_validated"
        )
        self.h.setUp()
        self.addCleanup(self.h.tearDown)

    def _payload(self, *, suffix: str) -> tuple[object, dict]:
        produced = self.h._request(
            AttackPathTransitionClassification.WORSENED,
            suffix=suffix,
        )
        request = produced[-1]
        payload = json.loads(request.to_json())
        self.assertTrue(payload["items"])
        self.assertTrue(payload["items"][0]["effect_ids"])
        return request, payload

    def test_canonical_producer_request_round_trips(self):
        request, payload = self._payload(
            suffix="authoring-effect-order-control"
        )

        self.assertEqual(
            future_remediation_authoring_request_from_dict(payload),
            request,
        )

    def test_effect_ids_reject_noncanonical_order_with_matching_digest(self):
        _, payload = self._payload(
            suffix="authoring-effect-order-reversed"
        )
        item = payload["items"][0]
        original_effects = list(item["effect_ids"])

        probe_effect = "effect:000-order-probe"
        while probe_effect in original_effects:
            probe_effect += "x"

        canonical_effects = sorted([*original_effects, probe_effect])
        self.assertGreaterEqual(len(canonical_effects), 2)

        item["effect_ids"] = list(reversed(canonical_effects))
        self.assertNotEqual(item["effect_ids"], canonical_effects)
        _rehash_request(payload)
        before = copy.deepcopy(payload)

        with self.assertRaisesRegex(
            ValueError,
            "canonical|order|sorted|effect",
        ):
            future_remediation_authoring_request_from_dict(payload)

        self.assertEqual(payload, before)


if __name__ == "__main__":
    unittest.main()
