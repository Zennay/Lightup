from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
import unittest

import test_future_remediation_authoring_request as request_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_remediation_authoring_request_handoff import (
    future_remediation_authoring_request_from_dict,
)


def _recompute_request_sha256(payload: dict) -> str:
    digest_payload = deepcopy(payload)
    digest_payload.pop("request_sha256")
    return sha256(
        json.dumps(
            digest_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


class FutureRemediationAuthoringRequestPathSemanticsAcceptanceTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = request_tests.FutureRemediationAuthoringRequestTest(
            "test_request_is_deterministic_and_export_is_bounded"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _payload(self, classification, *, suffix: str) -> dict:
        produced = self.base._request(classification, suffix=suffix)
        payload = json.loads(produced[-1].to_json())
        self.assertEqual(
            future_remediation_authoring_request_from_dict(payload),
            produced[-1],
        )
        return payload

    def test_classification_controls_current_path_presence(self):
        introduced = self._payload(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="authoring-path-semantics-introduced",
        )
        worsened = self._payload(
            AttackPathTransitionClassification.WORSENED,
            suffix="authoring-path-semantics-worsened",
        )

        self.assertEqual(introduced["items"][0]["current_attack_path_ids"], [])
        self.assertTrue(worsened["items"][0]["current_attack_path_ids"])

        forged_introduced = deepcopy(introduced)
        forged_introduced["items"][0]["current_attack_path_ids"] = deepcopy(
            worsened["items"][0]["current_attack_path_ids"]
        )
        forged_introduced["request_sha256"] = _recompute_request_sha256(
            forged_introduced
        )
        with self.assertRaisesRegex(
            ValueError,
            "introduced remediation authoring item must not carry current attack-path lineage",
        ):
            future_remediation_authoring_request_from_dict(forged_introduced)

        forged_worsened = deepcopy(worsened)
        forged_worsened["items"][0]["current_attack_path_ids"] = []
        forged_worsened["request_sha256"] = _recompute_request_sha256(
            forged_worsened
        )
        with self.assertRaisesRegex(
            ValueError,
            "worsened remediation authoring item must retain current attack-path lineage",
        ):
            future_remediation_authoring_request_from_dict(forged_worsened)


if __name__ == "__main__":
    unittest.main()
