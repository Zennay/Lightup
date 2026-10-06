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


def _rehash_manifest(item: dict) -> None:
    item["evidence_manifest_sha256"] = sha256(
        json.dumps(
            item["evidence"],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


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


class FutureRemediationAuthoringRequestCapabilityPathIdentityAcceptanceTest(
    unittest.TestCase
):
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
        item = payload["items"][0]
        self.assertTrue(item["capability_ids"])
        self.assertTrue(item["evidence"])
        self.assertTrue(item["current_attack_path_ids"])
        return request, payload

    def test_canonical_worsened_producer_request_round_trips(self):
        request, payload = self._payload(
            suffix="authoring-capability-path-identity-control"
        )
        self.assertEqual(
            future_remediation_authoring_request_from_dict(payload),
            request,
        )

    def test_capability_identifiers_reject_noncanonical_text_with_matching_digests(self):
        bad_values = (
            " padded-capability ",
            "bad\x7fcapability",
            "x" * 257,
        )
        for index, bad_value in enumerate(bad_values):
            with self.subTest(bad_value=index):
                _, payload = self._payload(
                    suffix=f"authoring-capability-identity-{index}"
                )
                item = payload["items"][0]
                original = item["capability_ids"][0]

                item["capability_ids"] = sorted(
                    bad_value if value == original else value
                    for value in item["capability_ids"]
                )
                for record in item["evidence"]:
                    if record["capability_id"] == original:
                        record["capability_id"] = bad_value

                _rehash_manifest(item)
                _rehash_request(payload)

                with self.assertRaisesRegex(
                    ValueError,
                    "canonical|identifier|capability|string|character",
                ):
                    future_remediation_authoring_request_from_dict(payload)

    def test_current_path_identifiers_reject_noncanonical_text_with_matching_digest(self):
        bad_values = (
            " padded-path ",
            "bad\npath",
            "x" * 257,
        )
        for index, bad_value in enumerate(bad_values):
            with self.subTest(bad_value=index):
                _, payload = self._payload(
                    suffix=f"authoring-current-path-identity-{index}"
                )
                paths = payload["items"][0]["current_attack_path_ids"]
                original = paths[0]
                payload["items"][0]["current_attack_path_ids"] = sorted(
                    bad_value if value == original else value
                    for value in paths
                )
                _rehash_request(payload)

                with self.assertRaisesRegex(
                    ValueError,
                    "canonical|identifier|current|path|string|character",
                ):
                    future_remediation_authoring_request_from_dict(payload)

    def test_capability_collection_rejects_noncanonical_order_with_matching_sets_and_digests(self):
        _, payload = self._payload(
            suffix="authoring-capability-order"
        )
        item = payload["items"][0]
        probe_capability = "capability:000-authoring-order-probe"
        while probe_capability in item["capability_ids"]:
            probe_capability += "x"

        probe_record = copy.deepcopy(item["evidence"][0])
        existing_evidence_ids = {
            record["evidence_id"] for record in item["evidence"]
        }
        probe_evidence_id = "evidence:zzzz-authoring-capability-order-probe"
        while probe_evidence_id in existing_evidence_ids:
            probe_evidence_id += "x"
        probe_record["evidence_id"] = probe_evidence_id
        probe_record["capability_id"] = probe_capability
        item["evidence"].append(probe_record)
        item["evidence"].sort(key=lambda record: record["evidence_id"])

        canonical_capabilities = sorted(
            [*item["capability_ids"], probe_capability]
        )
        self.assertGreaterEqual(len(canonical_capabilities), 2)
        item["capability_ids"] = list(reversed(canonical_capabilities))
        self.assertNotEqual(item["capability_ids"], canonical_capabilities)

        _rehash_manifest(item)
        _rehash_request(payload)

        with self.assertRaisesRegex(
            ValueError,
            "canonical|order|sorted|capability",
        ):
            future_remediation_authoring_request_from_dict(payload)

    def test_current_path_collection_rejects_noncanonical_order_with_matching_digest(self):
        _, payload = self._payload(
            suffix="authoring-current-path-order"
        )
        item = payload["items"][0]
        probe_path = "path:000-authoring-order-probe"
        while probe_path in item["current_attack_path_ids"]:
            probe_path += "x"

        canonical_paths = sorted(
            [*item["current_attack_path_ids"], probe_path]
        )
        self.assertGreaterEqual(len(canonical_paths), 2)
        item["current_attack_path_ids"] = list(reversed(canonical_paths))
        self.assertNotEqual(item["current_attack_path_ids"], canonical_paths)
        _rehash_request(payload)

        with self.assertRaisesRegex(
            ValueError,
            "canonical|order|sorted|current|path",
        ):
            future_remediation_authoring_request_from_dict(payload)


if __name__ == "__main__":
    unittest.main()
