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


CANONICAL_EVIDENCE_KIND = "future-transition-verification"


def _manifest_digest(records: list[dict]) -> str:
    return sha256(
        json.dumps(
            records,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


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


class FutureRemediationEvidenceBundleEvidenceKindAcceptanceTest(
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

    def test_canonical_producer_evidence_kind_round_trips(self):
        for classification in (
            AttackPathTransitionClassification.INTRODUCED,
            AttackPathTransitionClassification.WORSENED,
        ):
            with self.subTest(classification=classification.value):
                bundle, payload = self._payload(
                    classification,
                    suffix=f"bundle-kind-canonical-{classification.value}",
                )
                self.assertTrue(payload["items"][0]["evidence"])
                self.assertTrue(
                    all(
                        record["kind"] == CANONICAL_EVIDENCE_KIND
                        for record in payload["items"][0]["evidence"]
                    )
                )
                self.assertEqual(
                    future_remediation_evidence_bundle_from_dict(payload),
                    bundle,
                )

    def test_noncanonical_evidence_kind_fails_with_matching_digests(self):
        _, payload = self._payload(
            AttackPathTransitionClassification.WORSENED,
            suffix="bundle-kind-forged",
        )
        item = payload["items"][0]
        item["evidence"][0]["kind"] = "future-transition-observation"
        item["evidence_manifest_sha256"] = _manifest_digest(item["evidence"])
        _rehash_bundle(payload)

        with self.assertRaisesRegex(
            ValueError,
            "evidence|kind|canonical|transition",
        ):
            future_remediation_evidence_bundle_from_dict(payload)


if __name__ == "__main__":
    unittest.main()
