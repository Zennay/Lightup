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


def _rehash(payload: dict) -> None:
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


class FutureRemediationEvidenceBundlePositiveVersionAcceptanceTest(
    unittest.TestCase
):
    def setUp(self):
        self.h = handoff_tests.FutureRemediationEvidenceBundleHandoffTest(
            "test_real_producer_round_trips_and_is_immediately_live_validated"
        )
        self.h.setUp()
        self.addCleanup(self.h.tearDown)

    def _payload(self, *, suffix: str) -> tuple[object, dict]:
        produced = self.h._bundle(
            AttackPathTransitionClassification.WORSENED,
            suffix=suffix,
        )
        bundle = produced[-1]
        return bundle, json.loads(bundle.to_json())

    def test_canonical_producer_versions_round_trip(self):
        bundle, payload = self._payload(
            suffix="bundle-positive-version-canonical"
        )
        self.assertGreaterEqual(payload["current_twin_version"], 1)
        self.assertGreaterEqual(payload["twin_version"], 1)

        self.assertEqual(
            future_remediation_evidence_bundle_from_dict(payload),
            bundle,
        )

    def test_zero_versions_fail_closed_with_matching_bundle_digest(self):
        for field in ("current_twin_version", "twin_version"):
            with self.subTest(field=field):
                _, payload = self._payload(
                    suffix=f"bundle-positive-version-zero-{field}"
                )
                payload[field] = 0
                _rehash(payload)

                with self.assertRaisesRegex(
                    ValueError,
                    "positive|version|integer",
                ):
                    future_remediation_evidence_bundle_from_dict(payload)


if __name__ == "__main__":
    unittest.main()
