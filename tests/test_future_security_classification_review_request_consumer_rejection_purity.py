from __future__ import annotations

import copy
import dataclasses
import json
import unittest

import test_future_security_classification_review_request_consumer as consumer_tests


class FutureSecurityClassificationReviewConsumerRejectionPurityTest(unittest.TestCase):
    def setUp(self):
        self.base = consumer_tests.FutureSecurityClassificationReviewRequestConsumerTest(
            "test_real_producer_json_is_parsed_and_live_validated_as_one_boundary"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    @classmethod
    def _container_identities(cls, value, path="$"):
        identities = {}
        if isinstance(value, dict):
            identities[path] = id(value)
            for key, nested in value.items():
                identities.update(
                    cls._container_identities(nested, f"{path}.{key}")
                )
        elif isinstance(value, list):
            identities[path] = id(value)
            for index, nested in enumerate(value):
                identities.update(
                    cls._container_identities(nested, f"{path}[{index}]")
                )
        return identities

    def _assert_rejection_is_input_atomic(
        self,
        payload,
        produced,
        *,
        message_pattern,
    ):
        before = copy.deepcopy(payload)
        identities_before = self._container_identities(payload)
        json_before = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=False,
        )

        for attempt in range(2):
            with self.subTest(attempt=attempt + 1):
                with self.assertRaisesRegex(ValueError, message_pattern):
                    self.base._consume(payload, produced)
                self.assertEqual(payload, before)
                self.assertEqual(
                    self._container_identities(payload),
                    identities_before,
                )
                self.assertEqual(
                    json.dumps(
                        payload,
                        ensure_ascii=False,
                        separators=(",", ":"),
                        sort_keys=False,
                    ),
                    json_before,
                )

    def test_strict_digest_rejection_leaves_persisted_dict_untouched(self):
        produced = self.base._producer(
            suffix="classification-consumer-rejection-purity-digest"
        )
        request = produced[-1]
        payload = json.loads(request.to_json())
        digest = payload["classification_review_request_sha256"]
        payload["classification_review_request_sha256"] = (
            ("0" if digest[0] != "0" else "1") + digest[1:]
        )

        self._assert_rejection_is_input_atomic(
            payload,
            produced,
            message_pattern="digest mismatch",
        )

    def test_live_lineage_rejection_leaves_persisted_dict_untouched(self):
        produced = list(
            self.base._producer(
                suffix="classification-consumer-rejection-purity-live"
            )
        )
        request = produced[-1]
        payload = json.loads(request.to_json())
        attestation = produced[-2]
        produced[-2] = dataclasses.replace(
            attestation,
            attestation_sha256="0" * 64,
        )

        self._assert_rejection_is_input_atomic(
            payload,
            tuple(produced),
            message_pattern="live validated lineage",
        )


if __name__ == "__main__":
    unittest.main()
