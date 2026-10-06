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


def _manifest_digest(records: list[dict]) -> str:
    return sha256(
        json.dumps(
            records,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _bundle_digest(payload: dict) -> str:
    digest_payload = copy.deepcopy(payload)
    digest_payload.pop("bundle_sha256")
    return sha256(
        json.dumps(
            digest_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


class FutureRemediationEvidenceBundleCapabilityLineageAcceptanceTest(
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

    def test_canonical_remediation_bundle_capabilities_round_trip(self):
        for classification in (
            AttackPathTransitionClassification.INTRODUCED,
            AttackPathTransitionClassification.WORSENED,
        ):
            with self.subTest(classification=classification.value):
                bundle, payload = self._payload(
                    classification,
                    suffix=f"bundle-capability-lineage-{classification.value}",
                )
                item = payload["items"][0]
                self.assertTrue(item["capability_ids"])
                self.assertTrue(item["evidence"])
                self.assertTrue(
                    all(
                        record["capability_id"] in item["capability_ids"]
                        for record in item["evidence"]
                    )
                )
                self.assertEqual(
                    future_remediation_evidence_bundle_from_dict(payload),
                    bundle,
                )

    def test_evidence_capability_outside_item_lineage_fails_with_matching_digests(self):
        _, payload = self._payload(
            AttackPathTransitionClassification.WORSENED,
            suffix="bundle-capability-lineage-forged",
        )
        item = payload["items"][0]
        forged_capability = "capability:forged-outside-remediation-lineage"
        self.assertNotIn(forged_capability, item["capability_ids"])

        item["evidence"][0]["capability_id"] = forged_capability
        item["evidence_manifest_sha256"] = _manifest_digest(item["evidence"])
        payload["bundle_sha256"] = _bundle_digest(payload)

        with self.assertRaisesRegex(ValueError, "capability|lineage|outside"):
            future_remediation_evidence_bundle_from_dict(payload)


if __name__ == "__main__":
    unittest.main()
