from __future__ import annotations

import copy
from hashlib import sha256
import json
import unittest

import test_future_remediation_evidence_bundle_handoff as handoff_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_remediation_evidence_bundle_handoff import (
    future_remediation_evidence_bundle_from_dict,
)


def _rehash_bundle(payload: dict) -> None:
    digest_payload = copy.deepcopy(payload)
    digest_payload.pop("bundle_sha256")
    payload["bundle_sha256"] = sha256(
        json.dumps(
            digest_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


class FutureRemediationEvidenceBundlePathSemanticsAcceptanceTest(
    unittest.TestCase
):
    def setUp(self):
        self.h = handoff_tests.FutureRemediationEvidenceBundleHandoffTest(
            "test_real_producer_round_trips_and_is_immediately_live_validated"
        )
        self.h.setUp()
        self.addCleanup(self.h.tearDown)

    def _payload(self, classification, *, suffix: str) -> tuple[object, dict]:
        produced = self.h._bundle(classification, suffix=suffix)
        bundle = produced[-1]
        return bundle, json.loads(bundle.to_json())

    def test_canonical_classification_path_shapes_round_trip(self):
        for classification in (
            AttackPathTransitionClassification.INTRODUCED,
            AttackPathTransitionClassification.WORSENED,
        ):
            with self.subTest(classification=classification.value):
                bundle, payload = self._payload(
                    classification,
                    suffix=f"bundle-path-canonical-{classification.value}",
                )
                paths = payload["items"][0]["current_attack_path_ids"]
                if classification is AttackPathTransitionClassification.INTRODUCED:
                    self.assertEqual(paths, [])
                else:
                    self.assertTrue(paths)
                self.assertEqual(
                    future_remediation_evidence_bundle_from_dict(payload),
                    bundle,
                )

    def test_introduced_cannot_claim_current_path_with_matching_digest(self):
        _, payload = self._payload(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="bundle-path-introduced-forged",
        )
        self.assertEqual(payload["items"][0]["current_attack_path_ids"], [])
        payload["items"][0]["current_attack_path_ids"] = [
            "path:forged-existing"
        ]
        _rehash_bundle(payload)

        with self.assertRaisesRegex(ValueError, "classification|current|path|lineage"):
            future_remediation_evidence_bundle_from_dict(payload)

    def test_worsened_cannot_lose_current_path_with_matching_digest(self):
        _, payload = self._payload(
            AttackPathTransitionClassification.WORSENED,
            suffix="bundle-path-worsened-erased",
        )
        self.assertTrue(payload["items"][0]["current_attack_path_ids"])
        payload["items"][0]["current_attack_path_ids"] = []
        _rehash_bundle(payload)

        with self.assertRaisesRegex(ValueError, "classification|current|path|lineage"):
            future_remediation_evidence_bundle_from_dict(payload)


if __name__ == "__main__":
    unittest.main()
