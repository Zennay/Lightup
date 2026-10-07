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


def _rehash_request(payload: dict) -> None:
    digest_payload = deepcopy(payload)
    digest_payload.pop("request_sha256")
    payload["request_sha256"] = sha256(
        json.dumps(
            digest_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


class FutureRemediationAuthoringRequestResolutionEffectLineageAcceptanceTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = request_tests.FutureRemediationAuthoringRequestTest(
            "test_request_is_deterministic_and_export_is_bounded"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _payload(self, *, suffix: str) -> tuple[object, dict]:
        produced = self.base._request(
            AttackPathTransitionClassification.WORSENED,
            suffix=suffix,
        )
        request = produced[-1]
        return request, json.loads(request.to_json())

    def test_canonical_resolution_and_effect_lineage_round_trip(self):
        request, payload = self._payload(
            suffix="authoring-resolution-effect-canonical"
        )
        item = payload["items"][0]
        self.assertRegex(
            item["resolution_id"],
            r"^transition-resolution:[0-9a-f]{24}$",
        )
        self.assertTrue(item["effect_ids"])
        self.assertEqual(
            future_remediation_authoring_request_from_dict(payload),
            request,
        )

    def _assert_bad_resolution_id(self, value: str, *, suffix: str) -> None:
        _, payload = self._payload(suffix=suffix)
        payload["items"][0]["resolution_id"] = value
        _rehash_request(payload)

        with self.assertRaisesRegex(
            ValueError,
            "resolution|canonical|identifier|transition",
        ):
            future_remediation_authoring_request_from_dict(payload)

    def test_resolution_id_wrong_prefix_fails_with_matching_digest(self):
        self._assert_bad_resolution_id(
            "resolution:" + ("a" * 24),
            suffix="authoring-resolution-wrong-prefix",
        )

    def test_resolution_id_wrong_length_fails_with_matching_digest(self):
        self._assert_bad_resolution_id(
            "transition-resolution:" + ("a" * 23),
            suffix="authoring-resolution-wrong-length",
        )

    def test_resolution_id_uppercase_hex_fails_with_matching_digest(self):
        self._assert_bad_resolution_id(
            "transition-resolution:" + ("A" * 24),
            suffix="authoring-resolution-uppercase",
        )

    def test_empty_effect_lineage_fails_with_matching_digest(self):
        _, payload = self._payload(suffix="authoring-effect-empty")
        payload["items"][0]["effect_ids"] = []
        _rehash_request(payload)

        with self.assertRaisesRegex(
            ValueError,
            "effect|lineage|required|empty",
        ):
            future_remediation_authoring_request_from_dict(payload)

    def test_noncanonical_effect_identifiers_fail_with_matching_digest(self):
        bad_values = (
            " effect:forged ",
            "effect:bad\ncontrol",
            "e" * 257,
        )
        for index, value in enumerate(bad_values):
            with self.subTest(value=repr(value)):
                _, payload = self._payload(
                    suffix=f"authoring-effect-noncanonical-{index}"
                )
                payload["items"][0]["effect_ids"] = [value]
                _rehash_request(payload)

                with self.assertRaisesRegex(
                    ValueError,
                    "effect|canonical|identifier|control|256",
                ):
                    future_remediation_authoring_request_from_dict(payload)


if __name__ == "__main__":
    unittest.main()
