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


class FutureRemediationEvidenceBundleTopLevelLineageAcceptanceTest(
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
        payload = json.loads(bundle.to_json())
        return bundle, payload

    def test_canonical_producer_bundle_round_trips(self):
        bundle, payload = self._payload(
            suffix="bundle-top-level-lineage-control"
        )
        self.assertEqual(
            future_remediation_evidence_bundle_from_dict(payload),
            bundle,
        )

    def test_top_level_lineage_rejects_noncanonical_text_with_matching_digest(self):
        bad_values = (
            " padded-identity ",
            "bad\x7fidentity",
            "x" * 257,
        )
        for field in (
            "client_id",
            "current_twin_id",
            "twin_id",
            "changeset_id",
        ):
            for index, bad_value in enumerate(bad_values):
                with self.subTest(field=field, bad_value=index):
                    _, payload = self._payload(
                        suffix=f"bundle-top-level-lineage-{field}-{index}"
                    )
                    payload[field] = bad_value
                    _rehash_bundle(payload)

                    with self.assertRaisesRegex(
                        ValueError,
                        "canonical|identifier|string|control|256|whitespace",
                    ):
                        future_remediation_evidence_bundle_from_dict(payload)


if __name__ == "__main__":
    unittest.main()
